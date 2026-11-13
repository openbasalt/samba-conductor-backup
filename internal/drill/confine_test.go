package drill

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The confinement is tested in child processes of the test binary: the
// seccomp filter is irreversible, and the mounts, pivot_root and the
// capability drop need privileges, which an unprivileged user namespace
// provides where the host allows them (the test is skipped where it does
// not, for example on CI runners that restrict user namespaces).

const childEnv = "CONDUCTOR_BACKUP_CONFINE_CHILD"

func init() {
	if os.Getenv(childEnv) != "" {
		// As cmd/conductor-backup does for drill-sandbox.
		runtime.LockOSThread()
	}
}

func TestMain(m *testing.M) {
	switch os.Getenv(childEnv) {
	case "seccomp":
		os.Exit(report(seccompChild()))
	case "confine":
		os.Exit(report(confineChild(os.Getenv("CONDUCTOR_BACKUP_CONFINE_DIR"))))
	}
	os.Exit(m.Run())
}

// childResult is what a child prints.
type childResult struct {
	Skip   string   `json:"skip,omitempty"`
	Errors []string `json:"errors,omitempty"`
}

func report(r childResult) int {
	_ = json.NewEncoder(os.Stdout).Encode(r)
	return 0
}

func runChild(t *testing.T, mode string, attr *syscall.SysProcAttr, env ...string) childResult {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append([]string{childEnv + "=" + mode, "PATH=/usr/bin:/bin"}, env...)
	cmd.SysProcAttr = attr
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) && attr != nil && attr.Cloneflags&syscall.CLONE_NEWUSER != 0 {
			t.Skipf("user namespaces are not available here: %v", err)
		}
		t.Fatalf("child: %v\n%s", err, errb.String())
	}
	var r childResult
	if err := json.Unmarshal([]byte(out.String()), &r); err != nil {
		t.Fatalf("child output %q: %v\n%s", out.String(), err, errb.String())
	}
	return r
}

// seccompChild installs the filter and checks what it refuses.
func seccompChild() childResult {
	var r childResult
	fail := func(f string, a ...any) { r.Errors = append(r.Errors, fmt.Sprintf(f, a...)) }
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fail("no_new_privs: %v", err)
		return r
	}
	if err := installSeccomp(); err != nil {
		fail("install: %v", err)
		return r
	}
	checkDenied(&r)
	// Allowed calls still work, on every thread (TSYNC): a new goroutine on
	// another thread is filtered too.
	if unix.Getpid() <= 0 {
		fail("getpid")
	}
	done := make(chan error)
	go func() {
		runtime.LockOSThread()
		done <- unix.Unshare(unix.CLONE_NEWUTS)
	}()
	if err := <-done; !errors.Is(err, unix.EPERM) {
		fail("unshare on another thread: %v", err)
	}
	// A child process inherits the filter.
	if out, err := exec.Command("/bin/sh", "-c", "grep -E '^(Seccomp|NoNewPrivs):' /proc/self/status").Output(); err != nil ||
		!strings.Contains(string(out), "Seccomp:\t2") || !strings.Contains(string(out), "NoNewPrivs:\t1") {
		fail("child process status %q %v", out, err)
	}
	return r
}

// checkDenied tries calls the filter must refuse.
func checkDenied(r *childResult) {
	fail := func(f string, a ...any) { r.Errors = append(r.Errors, fmt.Sprintf(f, a...)) }
	if err := unix.Unshare(unix.CLONE_NEWNS); !errors.Is(err, unix.EPERM) {
		fail("unshare: %v", err)
	}
	if err := unix.Mount("tmpfs", "/tmp", "tmpfs", 0, ""); !errors.Is(err, unix.EPERM) {
		fail("mount: %v", err)
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_CLONE3, 0, 0, 0); errno != unix.ENOSYS {
		fail("clone3: %v", errno)
	}
	// clone with a namespace flag (refused before the kernel sees it).
	if _, _, errno := unix.RawSyscall(unix.SYS_CLONE, unix.CLONE_NEWUSER|uintptr(unix.SIGCHLD), 0, 0); errno != unix.EPERM {
		fail("clone(CLONE_NEWUSER): %v", errno)
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_KEYCTL, 0, 0, 0); errno != unix.EPERM {
		fail("keyctl: %v", errno)
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_PTRACE, unix.PTRACE_TRACEME, 0, 0); errno != unix.EPERM {
		fail("ptrace: %v", errno)
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_IO_URING_SETUP, 1, 0, 0); errno != unix.EPERM {
		fail("io_uring_setup: %v", errno)
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_OPEN_BY_HANDLE_AT, 0, 0, 0); errno != unix.EPERM {
		fail("open_by_handle_at: %v", errno)
	}
	if err := unix.Sethostname([]byte("x")); !errors.Is(err, unix.EPERM) {
		fail("sethostname: %v", err)
	}
	if runtime.GOARCH == "amd64" {
		// The x32 ABI (bit 30 of the number).
		if _, _, errno := unix.RawSyscall(0x40000000|unix.SYS_GETPID, 0, 0, 0); errno != unix.EPERM {
			fail("x32 getpid: %v", errno)
		}
	}
}

func TestSeccompFilter(t *testing.T) {
	if r := runChild(t, "seccomp", nil); len(r.Errors) > 0 {
		t.Fatal(strings.Join(r.Errors, "\n"))
	}
}

// confineChild runs as root of a new user namespace (with new mount, PID,
// network, UTS and IPC namespaces): it confines itself exactly as the
// sandbox does and checks the result.
func confineChild(dir string) childResult {
	var r childResult
	fail := func(f string, a ...any) { r.Errors = append(r.Errors, fmt.Sprintf(f, a...)) }
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		r.Skip = "private mounts: " + err.Error()
		return r
	}
	work := filepath.Join(dir, "work")
	resolv := filepath.Join(work, "resolv.conf")
	if err := writeNew(resolv, []byte("nameserver 127.0.0.1\n"), 0o644); err != nil {
		fail("%v", err)
		return r
	}
	if err := confine(rootLayout{Root: filepath.Join(work, ".root"), WorkDir: work, EtcFiles: map[string]string{"resolv.conf": resolv},
		EtcLinks: map[string]string{"samba": filepath.Join(work, "restore", "etc")}}); err != nil {
		fail("confine: %v", err)
		return r
	}
	// The filesystem.
	for _, gone := range []string{filepath.Join(dir, "secret"), "/home", "/root", "/etc/shadow", "/etc/ssl", "/.old-root", filepath.Join(work, ".root")} {
		if _, err := os.Lstat(gone); err == nil || !errors.Is(err, os.ErrNotExist) {
			if gone == filepath.Join(work, ".root") && err == nil {
				// The mount point itself is in the work directory (empty).
				continue
			}
			fail("%s is visible (%v)", gone, err)
		}
	}
	for _, there := range []string{"/usr/bin", "/bin/sh", "/etc/passwd", "/dev/null", "/proc/self/status", "/run/samba", "/var/lib/samba", "/tmp"} {
		if _, err := os.Stat(there); err != nil {
			fail("%s missing: %v", there, err)
		}
	}
	if b, err := os.ReadFile("/etc/resolv.conf"); err != nil || string(b) != "nameserver 127.0.0.1\n" {
		fail("resolv.conf %q %v", b, err)
	}
	if target, err := os.Readlink("/etc/samba"); err != nil || target != filepath.Join(work, "restore", "etc") {
		fail("/etc/samba -> %q %v", target, err)
	}
	if err := os.WriteFile(filepath.Join(work, "written"), []byte("x"), 0o600); err != nil {
		fail("work directory not writable: %v", err)
	}
	for _, ro := range []string{"/usr/conductor-backup-test", "/conductor-backup-test", "/etc/conductor-backup-test", "/proc/sys/kernel/hostname"} {
		if err := os.WriteFile(ro, []byte("x"), 0o600); err == nil {
			fail("%s writable", ro)
		}
	}
	if f, err := os.OpenFile("/dev/null", os.O_WRONLY, 0); err != nil {
		fail("/dev/null: %v", err)
	} else {
		_ = f.Close()
	}
	// Privileges, from the kernel's view, here and in a child.
	if err := verifyRestricted(); err != nil {
		fail("verify: %v", err)
	}
	checkDenied(&r)
	out, err := exec.Command("/bin/cat", "/proc/self/status").Output()
	if err != nil {
		fail("cat: %v", err)
		return r
	}
	p := filepath.Join(work, "child-status")
	_ = os.WriteFile(p, out, 0o600)
	st, err := readStatus(p)
	want := capMask(keepCaps)
	if err != nil || st.CapBnd&^want != 0 || st.CapEff&^want != 0 || st.CapInh != 0 || st.CapAmb != 0 || !st.NoNewPrivs || st.Seccomp != 2 {
		fail("child status %+v %v", st, err)
	}
	return r
}

func TestConfinementInUserNamespace(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte("drill identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "work"), 0o700); err != nil {
		t.Fatal(err)
	}
	attr := &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET |
			syscall.CLONE_NEWUTS | syscall.CLONE_NEWIPC,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	r := runChild(t, "confine", attr, "CONDUCTOR_BACKUP_CONFINE_DIR="+dir)
	if r.Skip != "" {
		t.Skip(r.Skip)
	}
	if len(r.Errors) > 0 {
		t.Fatal(strings.Join(r.Errors, "\n"))
	}
	if _, err := os.Stat(filepath.Join(dir, "work", "written")); err != nil {
		t.Fatalf("the work directory bound inside is not the real one: %v", err)
	}
}

func TestSeccompProgramShape(t *testing.T) {
	p, err := seccompProgram()
	if err != nil {
		t.Fatal(err)
	}
	if len(p) > 4096 || len(p) < 2*len(deniedSyscalls) {
		t.Fatalf("program length %d", len(p))
	}
	// Every jump lands inside the program.
	for i, ins := range p {
		if ins.Code&0x07 == unix.BPF_JMP && (i+1+int(ins.Jt) >= len(p) || i+1+int(ins.Jf) >= len(p)) {
			t.Fatalf("instruction %d jumps outside", i)
		}
	}
	if last := p[len(p)-1]; last.Code != unix.BPF_RET|unix.BPF_K || last.K != unix.SECCOMP_RET_ALLOW {
		t.Fatal("default is not allow")
	}
}

// TestSandboxEtcFiles: the generated /etc of the sandbox names the
// restored realm as Kerberos' default realm. Samba built with MIT Kerberos
// (Fedora, Basalt OS) runs krb5kdc, which refuses to start without one
// ("Configuration file does not specify default realm"); the host's
// krb5.conf is never shown in the sandbox.
func TestSandboxEtcFiles(t *testing.T) {
	files := sandboxEtcFiles(SandboxSpec{ServerName: "DRILL", Realm: "LAB.TEST"})
	krb := files["krb5.conf"]
	for _, want := range []string{"[libdefaults]\n", "\tdefault_realm = LAB.TEST\n", "\tdns_lookup_realm = false\n",
		"\tdns_lookup_kdc = true\n", "[realms]\nLAB.TEST = {\n\tdefault_domain = lab.test\n}\n", "\tdrill.lab.test = LAB.TEST\n"} {
		if !strings.Contains(krb, want) {
			t.Errorf("krb5.conf lacks %q:\n%s", want, krb)
		}
	}
	if files["resolv.conf"] != "nameserver 127.0.0.1\nsearch lab.test\n" {
		t.Errorf("resolv.conf %q", files["resolv.conf"])
	}
	if files["hosts"] != "127.0.0.1 localhost\n"+sandboxIP+" drill.lab.test drill\n" {
		t.Errorf("hosts %q", files["hosts"])
	}
	if len(files) != 3 {
		t.Errorf("files %v", files)
	}
}
