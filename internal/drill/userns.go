package drill

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/openbasalt/samba-conductor-backup/internal/config"
	"golang.org/x/sys/unix"
)

// The sandbox runs in two stages so that nothing from the backup ever
// runs with a capability in the host's initial user namespace:
//
//  1. `drill-sandbox` (host root, in new network, mount, PID, UTS and IPC
//     namespaces) sets up what needs host privileges: the network, the
//     new root with a fresh /proc, the host name, and lets unprivileged
//     processes bind the DC's ports in the sandbox's network namespace.
//     It hands the work directory to the mapped range, pivots, starts
//     stage 2 and then drops every capability of its own but CAP_KILL and
//     installs the seccomp filter while it waits.
//  2. `drill-sandbox-inner` runs as root of a new user namespace whose IDs
//     0 to config.UserNSSize-1 map to an unprivileged host range
//     (drill.userns_base), with a mount namespace that namespace owns. It
//     mounts a tmpfs on the restore target (Samba writes the sysvol ACLs
//     into the security.NTACL attribute, which needs CAP_SYS_ADMIN in the
//     user namespace that owns the file system: on that tmpfs it is this
//     one), confines itself as stage 1 would, and runs samba-tool, Samba
//     and the checks.
//
// When the host cannot create the user namespace, the drill fails unless
// the operator accepted running without one (drill.accept_no_userns or
// `drill --accept-no-userns`); stage 1 then runs everything itself with
// the reduced capabilities of confine.go, as host root.

// stage1Caps is what stage 1 keeps once stage 2 runs.
var stage1Caps = []int{unix.CAP_KILL}

// errNoUserNS: the host refused to create the sandbox's user namespace.
var errNoUserNS = errors.New("user namespaces are not available on this host")

// Isolation of the restored DC, as reported in the drill's checks.
const (
	isolationUserNS   = "user namespace"
	isolationHostRoot = "no user namespace (accepted by drill.accept_no_userns or --accept-no-userns)"
)

// userNSUnavailable tells whether starting a process in a new user
// namespace failed because the host does not allow one (as opposed to any
// other failure): disabled by sysctl or the unit (EPERM, ENOSPC, EUSERS),
// or a kernel without user namespaces (EINVAL, ENOSYS).
func userNSUnavailable(err error) bool {
	for _, e := range []syscall.Errno{unix.EPERM, unix.EACCES, unix.ENOSPC, unix.EUSERS, unix.EINVAL, unix.ENOSYS} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// noUserNSError is the message of a drill that could not get its user
// namespace and was not allowed to run without one. err is the cause,
// already wrapping errNoUserNS (runInner) or not.
func noUserNSError(err error) error {
	const remedy = "; the drill refuses to run the restored DC as host root. Allow user namespaces for " +
		"conductor-backup-drill.service (RestrictNamespaces= must include user; user.max_user_namespaces > 0), or accept " +
		"the weaker sandbox with drill.accept_no_userns = true or `drill --accept-no-userns`"
	if errors.Is(err, errNoUserNS) {
		return fmt.Errorf("%w"+remedy, err)
	}
	return fmt.Errorf("%w (%v)"+remedy, errNoUserNS, err)
}

// chownTree gives every entry under root (root included) to uid:gid,
// never following a symbolic link.
func chownTree(root string, uid, gid int) error {
	return filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
}

// idRange is one line of /proc/<pid>/uid_map or gid_map.
type idRange struct{ Inside, Outside, Count uint64 }

// parseIDMap reads a uid_map or gid_map.
func parseIDMap(b []byte) ([]idRange, error) {
	var out []idRange
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 {
			return nil, fmt.Errorf("unreadable ID map line %q", sc.Text())
		}
		var r idRange
		for i, dst := range []*uint64{&r.Inside, &r.Outside, &r.Count} {
			n, err := strconv.ParseUint(f[i], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("unreadable ID map line %q", sc.Text())
			}
			*dst = n
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// checkIDMap accepts exactly the drill's mapping: IDs 0 to size-1 onto the
// host range starting at base, which must not hold host ID 0. The initial
// user namespace ("0 0 4294967295") and any other mapping are refused.
func checkIDMap(m []idRange, base uint32, size uint64) error {
	if base == 0 {
		return errors.New("no host ID range configured")
	}
	if len(m) != 1 || m[0] != (idRange{Inside: 0, Outside: uint64(base), Count: size}) {
		return fmt.Errorf("ID map %v, want 0 %d %d", m, base, size)
	}
	return nil
}

// verifyUserNS checks, from the kernel's view, that this process runs in
// the drill's user namespace (its root is not host root) as that
// namespace's root.
func verifyUserNS(base uint32) error {
	for _, f := range []string{"/proc/self/uid_map", "/proc/self/gid_map"} {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		m, err := parseIDMap(b)
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		if err := checkIDMap(m, base, config.UserNSSize); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
	}
	return checkNSRoot(os.Getuid(), os.Getgid())
}

// checkNSRoot accepts only the user namespace's root (ID 0 inside, the
// range's base on the host). A process that entered the namespace without
// switching to it keeps an unmapped host ID (the overflow ID inside) and
// loses its capabilities at execve.
func checkNSRoot(uid, gid int) error {
	if uid != 0 || gid != 0 {
		return fmt.Errorf("running as %d:%d in the user namespace, not as its root", uid, gid)
	}
	return nil
}

// innerSysProcAttr starts stage 2: a new user namespace mapped onto the
// drill's range and a mount namespace it owns. The child switches to the
// namespace's root (Credential: setgroups, setgid and setuid to 0 once the
// maps are written) before it executes: cloned into the namespace it still
// holds host UID 0, which is not mapped there, so execve would drop its
// capabilities and it would be "other" on the work directory it was given.
func innerSysProcAttr(base uint32) *syscall.SysProcAttr {
	m := []syscall.SysProcIDMap{{ContainerID: 0, HostID: int(base), Size: config.UserNSSize}}
	return &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS, UidMappings: m, GidMappings: m,
		GidMappingsEnableSetgroups: true, Credential: &syscall.Credential{Uid: 0, Gid: 0}, Pdeathsig: syscall.SIGKILL}
}

// runInner is stage 1's part once the new root is in place: start stage 2
// with the probe password on its descriptor 3, drop every privilege of
// its own, and return stage 2's result. started is when the sandbox
// started (for the result's ReadyMS).
func runInner(ctx context.Context, specPath string, base uint32, pw []byte, started time.Time) (SandboxResult, error) {
	var res SandboxResult
	r, w, err := os.Pipe()
	if err != nil {
		return res, err
	}
	if _, err := w.Write(pw); err != nil {
		_ = r.Close()
		_ = w.Close()
		return res, err
	}
	_ = w.Close()
	defer func() { _ = r.Close() }()
	var out bytes.Buffer
	// /proc/self/exe: this program, wherever it lives (the old root is
	// detached by now).
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "drill-sandbox-inner", specPath)
	cmd.Env = sandboxEnv
	cmd.ExtraFiles = []*os.File{r}
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = innerSysProcAttr(base)
	innerStart := time.Now()
	if err := cmd.Start(); err != nil {
		if userNSUnavailable(err) {
			return res, fmt.Errorf("%w: %v", errNoUserNS, err)
		}
		return res, fmt.Errorf("starting the sandbox's user namespace: %w", err)
	}
	_ = r.Close()
	// Stage 1 keeps nothing but CAP_KILL (stopping stage 2 on timeout:
	// it runs as another host user) while the restored DC runs.
	if err := restrict(stage1Caps); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return res, fmt.Errorf("confining the sandbox's first stage: %w", err)
	}
	if err := verifyRestricted(stage1Caps); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return res, fmt.Errorf("confining the sandbox's first stage: %w", err)
	}
	waitErr := cmd.Wait()
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		if waitErr != nil {
			return res, fmt.Errorf("drill sandbox (user namespace): %w", waitErr)
		}
		return res, fmt.Errorf("drill sandbox (user namespace): unreadable result: %w", err)
	}
	res.ReadyMS += innerStart.Sub(started).Milliseconds()
	return res, nil
}

// RunSandboxInner is the body of `conductor-backup drill-sandbox-inner
// SPEC` (stage 2, started by RunSandbox). It prints a SandboxResult on
// stdout and returns the exit code.
func RunSandboxInner(specPath string) int {
	start := time.Now()
	res := SandboxResult{}
	emit := func() int {
		_ = json.NewEncoder(os.Stdout).Encode(res)
		if res.Error != "" {
			return 1
		}
		return 0
	}
	spec, pw, err := readSpec(specPath)
	if err != nil {
		res.Error = err.Error()
		return emit()
	}
	if err := verifyUserNS(spec.UserNSBase); err != nil {
		res.Error = "user namespace: " + err.Error()
		return emit()
	}
	res.Isolation = fmt.Sprintf("%s (host IDs %d-%d)", isolationUserNS, spec.UserNSBase, uint64(spec.UserNSBase)+config.UserNSSize-1)
	if err := mountRestoreTarget(spec.TargetDir); err != nil {
		res.Error = "isolation: " + err.Error()
		return emit()
	}
	if err := restrict(keepCaps); err != nil {
		res.Error = "isolation: " + err.Error()
		return emit()
	}
	if err := verifyRestricted(keepCaps); err != nil {
		res.Error = "isolation: " + err.Error()
		return emit()
	}
	ctx, cancel := context.WithTimeout(context.Background(), spec.timeout())
	defer cancel()
	runDrill(ctx, spec, string(pw), start, &res)
	return emit()
}

// mountRestoreTarget makes the restore target a tmpfs owned by this user
// namespace (samba-tool wants it empty; the restored domain then lives in
// memory and is gone when the sandbox exits).
func mountRestoreTarget(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", dir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755,size=50%"); err != nil {
		return fmt.Errorf("restore tmpfs: %w", err)
	}
	return nil
}

// readSpec reads the sandbox spec and the probe password (descriptor 3).
func readSpec(specPath string) (SandboxSpec, []byte, error) {
	var spec SandboxSpec
	b, err := os.ReadFile(specPath)
	if err != nil {
		return spec, nil, err
	}
	if err := json.Unmarshal(b, &spec); err != nil {
		return spec, nil, fmt.Errorf("spec: %w", err)
	}
	pw, err := io.ReadAll(io.LimitReader(os.NewFile(3, "probe-password"), 4096))
	if err != nil || len(pw) == 0 {
		return spec, nil, errors.New("probe password not received")
	}
	return spec, pw, nil
}
