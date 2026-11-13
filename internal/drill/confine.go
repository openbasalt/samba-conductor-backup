package drill

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The restored domain controller is attacker-controlled content as far as
// the drill host is concerned: whoever can produce a backup that verifies
// chooses its database and sysvol. Beyond the namespaces (sandbox.go) and
// the allowlisted smb.conf (internal/sambaconf), the sandbox confines what
// samba-tool and samba can reach, in this order, and fails the drill if any
// layer cannot be set up (it never runs with less):
//
//  1. Filesystem: a new root (tmpfs) holding read-only binds of /usr (and
//     the /bin, /sbin, /lib* links or binds), a short list of /etc files,
//     the generated /etc/hosts and /etc/resolv.conf, a minimal /dev, a
//     fresh /proc with its kernel knobs read-only, empty tmpfs /run, /tmp
//     and /var, and the drill's work directory. pivot_root into it and
//     detach the old root: the drill identity, the credentials, the rest
//     of the drill state and the host's /etc are not there.
//  2. Capabilities: the bounding, permitted, effective, inheritable and
//     ambient sets are cut to keepCaps (what Samba as an AD DC needs on its
//     own files and ports).
//  3. no_new_privs, not dumpable (a root child cannot read the sandbox's
//     memory, which holds the probe password), and a seccomp filter that
//     refuses mounting, namespaces, module and kexec loading, ptrace,
//     BPF, perf, keyrings, io_uring, clock and host name changes and file
//     handle lookups (seccomp.go).
//
// Everything is applied to the sandbox's main thread, which
// `conductor-backup drill-sandbox` locks at start (cmd/conductor-backup),
// and every child (samba-tool, samba) is started from it, so the children
// inherit all of it. The seccomp filter and no_new_privs are synchronized
// to every thread of the sandbox.
//
// Not done here (see docs/design.md, "Restore drill sandbox"): a user
// namespace. Samba writes sysvol ACLs into the security.NTACL extended
// attribute, which needs CAP_SYS_ADMIN in the initial user namespace on a
// disk file system, so "root" in the sandbox is still root on the host,
// with the capabilities in keepCaps.

// keepCaps are the capabilities samba-tool and samba keep: file access as
// root on the restored tree (chown, DAC override and search, fowner,
// fsetid), signalling their own processes, switching user and group
// (smbd), binding the DC's ports (53, 88, 389, ...), and CAP_SYS_ADMIN for
// the security.NTACL attribute of sysvol. Everything else (CAP_NET_ADMIN,
// CAP_SYS_MODULE, CAP_SYS_PTRACE, CAP_SYS_RAWIO, CAP_MKNOD, CAP_SETPCAP,
// ...) goes.
var keepCaps = []int{
	unix.CAP_CHOWN, unix.CAP_DAC_OVERRIDE, unix.CAP_DAC_READ_SEARCH, unix.CAP_FOWNER, unix.CAP_FSETID,
	unix.CAP_KILL, unix.CAP_SETGID, unix.CAP_SETUID, unix.CAP_NET_BIND_SERVICE, unix.CAP_SYS_ADMIN,
}

// rootEntries are the top-level host paths the new root shows read-only
// (a directory is bound, a symbolic link such as /bin -> usr/bin is
// copied as a link). /usr is required.
var rootEntries = []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32"}

// etcEntries are the /etc files and directories the new root shows
// read-only when the host has them: user and group names, name service and
// dynamic linker configuration, the time zone, crypto policies and the
// Debian alternatives links. Nothing with secrets (no ssl, pki, shadow,
// krb5.conf, samba or conductor-backup).
var etcEntries = []string{
	"passwd", "group", "nsswitch.conf", "host.conf", "gai.conf", "protocols", "services", "ld.so.cache", "ld.so.conf",
	"ld.so.conf.d", "localtime", "crypto-policies", "alternatives", "gnutls",
}

// devNodes are bound into the new /dev.
var devNodes = []string{"null", "zero", "full", "random", "urandom"}

// procReadOnly are kernel knobs under the new /proc made read-only; procMask
// are hidden behind /dev/null.
var (
	procReadOnly = []string{"sys", "sysrq-trigger", "irq", "bus", "fs"}
	procMask     = []string{"kcore", "keys", "timer_list", "kallsyms"}
)

// rootLayout describes the new root.
type rootLayout struct {
	// Root is the directory the tmpfs root is mounted on (created).
	Root string
	// WorkDir is bound read-write at the same path inside.
	WorkDir string
	// EtcFiles are generated files bound read-only at /etc/<name>.
	EtcFiles map[string]string
	// EtcLinks are symbolic links /etc/<name> -> target (the default
	// Samba configuration directory points at the restored, allowlisted
	// one, so samba-tool's checks load nothing else).
	EtcLinks map[string]string
}

// lockedFlags are the mount flags a bind keeps from its source (the kernel
// refuses to clear them on a remount inside a user namespace, and they
// only ever restrict).
const lockedFlags = unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_NOATIME | unix.MS_NODIRATIME | unix.MS_RELATIME

// bind mounts src on dst (non-recursive) and remounts it with flags plus
// the source's locked flags.
func bind(src, dst string, flags uintptr) error {
	if err := unix.Mount(src, dst, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind %s: %w", src, err)
	}
	var st unix.Statfs_t
	if err := unix.Statfs(dst, &st); err != nil {
		return fmt.Errorf("statfs %s: %w", dst, err)
	}
	f := flags | uintptr(st.Flags)&lockedFlags
	if err := unix.Mount("", dst, "", unix.MS_REMOUNT|unix.MS_BIND|f, ""); err != nil {
		return fmt.Errorf("remount %s: %w", dst, err)
	}
	return nil
}

// mountPoint creates an empty directory or file at p to bind src on.
func mountPoint(src, p string) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if st.IsDir() {
		return os.Mkdir(p, 0o755)
	}
	return writeNew(p, nil, 0o644)
}

// bindEntry shows a host path in the new root: a link is copied as a
// link, anything else is bound read-only. Absent paths are skipped unless
// required.
func bindEntry(src, dst string, required bool) error {
	st, err := os.Lstat(src)
	if errors.Is(err, os.ErrNotExist) && !required {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.Symlink(target, dst)
	}
	if err := mountPoint(src, dst); err != nil {
		return err
	}
	return bind(src, dst, unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV)
}

// buildRoot assembles the new root under l.Root (see the package comment
// above). It must run in the sandbox's private mount namespace and PID
// namespace (for /proc).
func buildRoot(l rootLayout) error {
	if err := os.Mkdir(l.Root, 0o700); err != nil {
		return err
	}
	r := l.Root
	if err := unix.Mount("tmpfs", r, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755,size=16m"); err != nil {
		return fmt.Errorf("root tmpfs: %w", err)
	}
	for _, e := range rootEntries {
		if err := bindEntry(e, filepath.Join(r, e), e == "/usr"); err != nil {
			return fmt.Errorf("%s: %w", e, err)
		}
	}
	for _, e := range etcEntries {
		if err := bindEntry(filepath.Join("/etc", e), filepath.Join(r, "etc", e), false); err != nil {
			return fmt.Errorf("/etc/%s: %w", e, err)
		}
	}
	for name, src := range l.EtcFiles {
		dst := filepath.Join(r, "etc", name)
		if err := mountPoint(src, dst); err != nil {
			return err
		}
		if err := bind(src, dst, unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC); err != nil {
			return err
		}
	}
	for name, target := range l.EtcLinks {
		if err := os.Symlink(target, filepath.Join(r, "etc", name)); err != nil {
			return err
		}
	}
	// Writable scratch space, empty: Samba's defaults outside the restored
	// tree (/run/samba, /var/lib/samba/ntp_signd, /var/log/samba, ...).
	for _, d := range []string{"run", "tmp", "var"} {
		p := filepath.Join(r, d)
		if err := os.Mkdir(p, 0o755); err != nil {
			return err
		}
		mode := "0755"
		if d == "tmp" {
			mode = "1777"
		}
		if err := unix.Mount("tmpfs", p, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode="+mode+",size=256m"); err != nil {
			return fmt.Errorf("/%s: %w", d, err)
		}
	}
	for _, d := range []string{"run/samba", "run/lock", "var/lib/samba", "var/log/samba", "var/cache/samba", "var/tmp"} {
		if err := os.MkdirAll(filepath.Join(r, d), 0o755); err != nil {
			return err
		}
	}
	for link, target := range map[string]string{"var/run": "../run", "var/lock": "../run/lock"} {
		if err := os.Symlink(target, filepath.Join(r, link)); err != nil {
			return err
		}
	}
	// A minimal /dev.
	dev := filepath.Join(r, "dev")
	if err := os.Mkdir(dev, 0o755); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", dev, "tmpfs", unix.MS_NOSUID|unix.MS_NOEXEC, "mode=0755,size=1m"); err != nil {
		return fmt.Errorf("/dev: %w", err)
	}
	for _, n := range devNodes {
		dst := filepath.Join(dev, n)
		if err := writeNew(dst, nil, 0o666); err != nil {
			return err
		}
		if err := bind(filepath.Join("/dev", n), dst, unix.MS_NOSUID|unix.MS_NOEXEC); err != nil {
			return err
		}
	}
	if err := os.Mkdir(filepath.Join(dev, "shm"), 0o1777); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", filepath.Join(dev, "shm"), "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=1777,size=64m"); err != nil {
		return fmt.Errorf("/dev/shm: %w", err)
	}
	for link, target := range map[string]string{"fd": "/proc/self/fd", "stdin": "/proc/self/fd/0", "stdout": "/proc/self/fd/1", "stderr": "/proc/self/fd/2"} {
		if err := os.Symlink(target, filepath.Join(dev, link)); err != nil {
			return err
		}
	}
	// A /proc of the sandbox's PID namespace, kernel knobs read-only.
	proc := filepath.Join(r, "proc")
	if err := os.Mkdir(proc, 0o555); err != nil {
		return err
	}
	if err := unix.Mount("proc", proc, "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("/proc: %w", err)
	}
	for _, p := range procReadOnly {
		pp := filepath.Join(proc, p)
		if _, err := os.Lstat(pp); err != nil {
			continue
		}
		if err := bind(pp, pp, unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC); err != nil {
			return err
		}
	}
	for _, p := range procMask {
		pp := filepath.Join(proc, p)
		if _, err := os.Lstat(pp); err != nil {
			continue
		}
		if err := unix.Mount(filepath.Join(dev, "null"), pp, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("mask /proc/%s: %w", p, err)
		}
	}
	// The drill's work directory, read-write, at the same path.
	wd := filepath.Join(r, l.WorkDir)
	if err := os.MkdirAll(wd, 0o700); err != nil {
		return err
	}
	if err := bind(l.WorkDir, wd, unix.MS_NOSUID|unix.MS_NODEV); err != nil {
		return err
	}
	return nil
}

// pivot makes l.Root the root of the mount namespace and detaches the old
// one, then makes the root tmpfs read-only.
func pivot(root string) error {
	old := filepath.Join(root, ".old-root")
	if err := os.Mkdir(old, 0o700); err != nil {
		return err
	}
	if err := unix.PivotRoot(root, old); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	if err := unix.Unmount("/.old-root", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detaching the old root: %w", err)
	}
	if err := os.Remove("/.old-root"); err != nil {
		return err
	}
	if err := unix.Mount("", "/", "", unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return fmt.Errorf("read-only root: %w", err)
	}
	return nil
}

// capMask turns a list of capabilities into a bit mask.
func capMask(caps []int) uint64 {
	var m uint64
	for _, c := range caps {
		m |= 1 << uint(c)
	}
	return m
}

// lastCap is the highest capability the kernel knows.
func lastCap() (int, error) {
	b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

// dropCaps cuts the calling thread's capability sets to keep: bounding
// set first (needs CAP_SETPCAP), ambient cleared, then permitted,
// effective and inheritable.
func dropCaps(keep []int) error {
	last, err := lastCap()
	if err != nil {
		return fmt.Errorf("cap_last_cap: %w", err)
	}
	want := capMask(keep)
	for c := 0; c <= last; c++ {
		if want&(1<<uint(c)) != 0 {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil {
			return fmt.Errorf("dropping capability %d from the bounding set: %w", c, err)
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clearing ambient capabilities: %w", err)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return err
	}
	for i := range data {
		w := uint32(want >> (32 * uint(i)))
		data[i].Permitted &= w
		data[i].Effective &= w
		data[i].Inheritable = 0
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	return nil
}

// restrict applies capabilities, no_new_privs, non-dumpable and the
// seccomp filter to the calling (locked) thread; the filter and
// no_new_privs are synchronized to every thread.
func restrict() error {
	if err := dropCaps(keepCaps); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("not dumpable: %w", err)
	}
	return installSeccomp()
}

// threadStatus is what /proc/thread-self/status says about the confinement.
type threadStatus struct {
	CapBnd, CapEff, CapPrm, CapInh, CapAmb uint64
	NoNewPrivs                             bool
	Seccomp                                int
}

func readStatus(path string) (threadStatus, error) {
	var s threadStatus
	f, err := os.Open(path)
	if err != nil {
		return s, err
	}
	defer func() { _ = f.Close() }()
	seen := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		hex := func(dst *uint64) {
			if n, err := strconv.ParseUint(v, 16, 64); err == nil {
				*dst = n
				seen++
			}
		}
		switch k {
		case "CapBnd":
			hex(&s.CapBnd)
		case "CapEff":
			hex(&s.CapEff)
		case "CapPrm":
			hex(&s.CapPrm)
		case "CapInh":
			hex(&s.CapInh)
		case "CapAmb":
			hex(&s.CapAmb)
		case "NoNewPrivs":
			s.NoNewPrivs = v == "1"
			seen++
		case "Seccomp":
			s.Seccomp, _ = strconv.Atoi(v)
			seen++
		}
	}
	if seen != 7 {
		return s, fmt.Errorf("%s: incomplete status", path)
	}
	return s, sc.Err()
}

// verifyRestricted checks, from the kernel's point of view, that the
// calling thread is confined as restrict intended.
func verifyRestricted() error {
	s, err := readStatus("/proc/thread-self/status")
	if err != nil {
		return err
	}
	want := capMask(keepCaps)
	switch {
	case s.CapBnd&^want != 0, s.CapEff&^want != 0, s.CapPrm&^want != 0:
		return fmt.Errorf("capabilities not dropped (bounding %x, effective %x, permitted %x)", s.CapBnd, s.CapEff, s.CapPrm)
	case s.CapInh != 0, s.CapAmb != 0:
		return errors.New("inheritable or ambient capabilities left")
	case !s.NoNewPrivs:
		return errors.New("no_new_privs not set")
	case s.Seccomp != 2:
		return errors.New("seccomp filter not active")
	}
	if dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil || dumpable != 0 {
		return errors.New("still dumpable")
	}
	return nil
}

// installSeccomp loads the filter (seccomp.go) on every thread.
func installSeccomp() error {
	prog, err := seccompProgram()
	if err != nil {
		return err
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	r1, _, errno := syscall.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog)))
	runtime.KeepAlive(prog)
	if errno != 0 {
		return fmt.Errorf("seccomp: %w", errno)
	}
	if r1 != 0 {
		// TSYNC names the thread it could not synchronize.
		return fmt.Errorf("seccomp: thread %d could not be synchronized", r1)
	}
	return nil
}
