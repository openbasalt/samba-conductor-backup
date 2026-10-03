package drill

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-ldap/ldap/v3"
	ad "github.com/openbasalt/samba-conductor-ad"
	"github.com/openbasalt/samba-conductor-ad/helper"
	"github.com/openbasalt/samba-conductor-ad/sambatool"
)

// The sandbox is a child process of `conductor-backup drill` started in new
// network, mount, PID, UTS and IPC namespaces. Its network namespace has
// only a loopback and a dummy interface (192.0.2.10, TEST-NET-1), so the
// restored domain controller has no path to anything: not the real DCs,
// not the bucket. Its mount namespace gets a private /run/samba, /proc,
// /etc/resolv.conf (127.0.0.1) and /etc/hosts. When it exits, the kernel
// kills whatever is left in its PID namespace.

// sandboxIP is the restored DC's address inside the sandbox.
const sandboxIP = "192.0.2.10"

// SandboxSpec is what the parent hands the sandbox (a 0600 file; the probe
// password travels on file descriptor 3, never in the spec).
type SandboxSpec struct {
	BackupFile     string                 `json:"backup_file"`
	TargetDir      string                 `json:"target_dir"`
	WorkDir        string                 `json:"work_dir"`
	ServerName     string                 `json:"server_name"`
	Realm          string                 `json:"realm"`
	ProbeUser      string                 `json:"probe_user"`
	Samples        []helper.ArchiveSample `json:"samples"`
	Users          helper.CountRange      `json:"users"`
	SambaBinary    string                 `json:"samba_binary"`
	SambaTool      string                 `json:"samba_tool"`
	TimeoutSeconds int                    `json:"timeout_seconds"`
}

// SandboxResult is what the sandbox prints on stdout.
type SandboxResult struct {
	Checks    []helper.DrillCheck `json:"checks"`
	RestoreMS int64               `json:"restore_ms"`
	StartMS   int64               `json:"start_ms"`
	ChecksMS  int64               `json:"checks_ms"`
	// ReadyMS: from the sandbox's start until every check passed.
	ReadyMS int64  `json:"ready_ms"`
	Error   string `json:"error,omitempty"`
}

// sandboxFlags are the namespaces of the sandbox.
const sandboxFlags = syscall.CLONE_NEWNET | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWUTS | syscall.CLONE_NEWIPC

// startSandbox runs `<exe> drill-sandbox <spec>` in the namespaces and
// returns its result.
func startSandbox(ctx context.Context, exe, specPath, probePassword string, logw io.Writer) (SandboxResult, error) {
	var res SandboxResult
	r, w, err := os.Pipe()
	if err != nil {
		return res, err
	}
	if _, err := w.WriteString(probePassword); err != nil {
		_ = r.Close()
		_ = w.Close()
		return res, err
	}
	_ = w.Close()
	defer func() { _ = r.Close() }()
	var out strings.Builder
	cmd := exec.CommandContext(ctx, exe, "drill-sandbox", specPath)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	cmd.ExtraFiles = []*os.File{r}
	cmd.Stdout = &out
	cmd.Stderr = logw
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: sandboxFlags, Pdeathsig: syscall.SIGKILL}
	runErr := cmd.Run()
	if err := json.Unmarshal([]byte(out.String()), &res); err != nil {
		if runErr != nil {
			return res, fmt.Errorf("drill sandbox: %w", runErr)
		}
		return res, fmt.Errorf("drill sandbox: unreadable result: %w", err)
	}
	return res, nil
}

// RunSandbox is the body of `conductor-backup drill-sandbox SPEC`. It
// prints a SandboxResult on stdout and returns the exit code.
func RunSandbox(specPath string) int {
	start := time.Now()
	res := SandboxResult{}
	emit := func() int {
		_ = json.NewEncoder(os.Stdout).Encode(res)
		if res.Error != "" {
			return 1
		}
		return 0
	}
	if os.Getpid() != 1 {
		res.Error = "drill-sandbox must be started by `conductor-backup drill` (new PID namespace)"
		return emit()
	}
	b, err := os.ReadFile(specPath)
	if err != nil {
		res.Error = err.Error()
		return emit()
	}
	var spec SandboxSpec
	if err := json.Unmarshal(b, &spec); err != nil {
		res.Error = "spec: " + err.Error()
		return emit()
	}
	pw, err := io.ReadAll(io.LimitReader(os.NewFile(3, "probe-password"), 4096))
	if err != nil || len(pw) == 0 {
		res.Error = "probe password not received"
		return emit()
	}
	timeout := time.Duration(spec.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 20 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := isolate(spec); err != nil {
		res.Error = "isolation: " + err.Error()
		return emit()
	}
	t := time.Now()
	runner := &sambatool.Runner{Binary: spec.SambaTool, Credentials: sambatool.LocalSystem{}, Timeout: 20 * time.Minute}
	if _, err := sambatool.Run(ctx, runner, sambatool.DomainBackupRestore{BackupFile: spec.BackupFile, TargetDir: spec.TargetDir,
		NewServerName: spec.ServerName, HostIP: sandboxIP}); err != nil {
		res.Error = "samba-tool domain backup restore failed"
		logf("restore: %v", err)
		return emit()
	}
	res.RestoreMS = time.Since(t).Milliseconds()
	t = time.Now()
	stop, err := startSamba(spec)
	if err != nil {
		res.Error = "starting samba: " + err.Error()
		return emit()
	}
	defer stop()
	res.StartMS = time.Since(t).Milliseconds()
	t = time.Now()
	res.Checks = runChecks(ctx, spec, string(pw))
	res.ChecksMS = time.Since(t).Milliseconds()
	res.ReadyMS = time.Since(start).Milliseconds()
	return emit()
}

func logf(format string, a ...any) { fmt.Fprintf(os.Stderr, "drill-sandbox: "+format+"\n", a...) }

// isolate prepares the namespaces: private mounts, loopback + dummy
// network, host name.
func isolate(spec SandboxSpec) error {
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("private mounts: %w", err)
	}
	if err := syscall.Mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("/proc: %w", err)
	}
	if err := os.MkdirAll("/run/samba", 0o755); err != nil {
		return err
	}
	if err := syscall.Mount("tmpfs", "/run/samba", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=0755,size=64m"); err != nil {
		return fmt.Errorf("/run/samba: %w", err)
	}
	host := strings.ToLower(spec.ServerName)
	domain := strings.ToLower(spec.Realm)
	files := map[string]string{
		"/etc/resolv.conf": "nameserver 127.0.0.1\nsearch " + domain + "\n",
		"/etc/hosts":       "127.0.0.1 localhost\n" + sandboxIP + " " + host + "." + domain + " " + host + "\n",
	}
	for target, content := range files {
		src := filepath.Join(spec.WorkDir, filepath.Base(target))
		if err := os.WriteFile(src, []byte(content), 0o644); err != nil {
			return err
		}
		if err := syscall.Mount(src, target, "", syscall.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind %s: %w", target, err)
		}
	}
	if err := syscall.Sethostname([]byte(host)); err != nil {
		return fmt.Errorf("host name: %w", err)
	}
	ip, err := findIP()
	if err != nil {
		return err
	}
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"link", "add", "drill0", "type", "dummy"},
		{"addr", "add", sandboxIP + "/24", "dev", "drill0"},
		{"link", "set", "drill0", "up"},
	} {
		if out, err := exec.Command(ip, args...).CombinedOutput(); err != nil {
			return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func findIP() (string, error) {
	for _, p := range []string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("the ip command (iproute2) is required")
}

// startSamba starts the restored DC in the foreground (its own process
// group) and returns a function that stops it.
func startSamba(spec SandboxSpec) (func(), error) {
	lf, err := os.OpenFile(filepath.Join(spec.WorkDir, "samba.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(spec.SambaBinary, "-s", filepath.Join(spec.TargetDir, "etc", "smb.conf"), "-i", "--debug-stdout", "-d1")
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	cmd.Stdout, cmd.Stderr = lf, lf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = lf.Close()
		return nil, err
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	return func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		_ = lf.Close()
	}, nil
}

// realmDN turns "LAB.EXAMPLE.COM" into "DC=lab,DC=example,DC=com".
func realmDN(realm string) string {
	parts := strings.Split(strings.ToLower(realm), ".")
	for i, p := range parts {
		parts[i] = "DC=" + p
	}
	return strings.Join(parts, ",")
}

// poll retries f every second until it succeeds or the time is up.
func poll(ctx context.Context, d time.Duration, f func() (string, error)) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	var last error
	for {
		detail, err := f()
		if err == nil {
			return detail, nil
		}
		var final backoffErr
		if errors.As(err, &final) {
			return "", err
		}
		last = err
		select {
		case <-ctx.Done():
			return "", last
		case <-time.After(time.Second):
		}
	}
}

func check(name string, detail string, err error) helper.DrillCheck {
	if err != nil {
		msg := err.Error()
		if len(msg) > 160 {
			msg = msg[:157] + "..."
		}
		return helper.DrillCheck{Name: name, OK: false, Detail: msg}
	}
	if len(detail) > 160 {
		detail = detail[:157] + "..."
	}
	return helper.DrillCheck{Name: name, OK: true, Detail: detail}
}

// runChecks verifies the restored DC: LDAP, DNS SRV records, a Kerberos
// sign-in, the user count and sample SIDs.
func runChecks(ctx context.Context, spec SandboxSpec, password string) []helper.DrillCheck {
	var out []helper.DrillCheck
	dn := realmDN(spec.Realm)
	detail, err := poll(ctx, 2*time.Minute, func() (string, error) {
		c, err := ldap.DialURL("ldap://127.0.0.1:389", ldap.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}))
		if err != nil {
			return "", err
		}
		defer func() { _ = c.Close() }()
		c.SetTimeout(5 * time.Second)
		r, err := c.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 5, false, "(objectClass=*)",
			[]string{"defaultNamingContext", "dnsHostName"}, nil))
		if err != nil || len(r.Entries) != 1 {
			return "", fmt.Errorf("rootDSE: %v", err)
		}
		if got := r.Entries[0].GetAttributeValue("defaultNamingContext"); !strings.EqualFold(got, dn) {
			return "", fmt.Errorf("defaultNamingContext %q, want %q", got, dn)
		}
		return "rootDSE " + r.Entries[0].GetAttributeValue("dnsHostName"), nil
	})
	out = append(out, check("ldap", detail, err))
	if err != nil {
		return out
	}

	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, "127.0.0.1:53")
	}}
	domain := strings.ToLower(spec.Realm)
	for _, name := range []string{"_ldap._tcp." + domain, "_kerberos._tcp." + domain, "_ldap._tcp.dc._msdcs." + domain} {
		detail, err := poll(ctx, 90*time.Second, func() (string, error) {
			_, srvs, err := res.LookupSRV(ctx, "", "", name)
			if err != nil {
				return "", err
			}
			if len(srvs) == 0 {
				return "", errors.New("no records")
			}
			return fmt.Sprintf("%s:%d", strings.TrimSuffix(srvs[0].Target, "."), srvs[0].Port), nil
		})
		out = append(out, check("dns:"+name, detail, err))
	}

	detail, err = poll(ctx, 60*time.Second, func() (string, error) {
		s, err := ad.SignIn(ctx, ad.Config{Realm: spec.Realm, DCs: []string{"127.0.0.1"}, RootCAs: x509.NewCertPool(),
			DialTimeout: 5 * time.Second}, spec.ProbeUser, password)
		if err != nil {
			var ae *ad.AuthError
			if errors.As(err, &ae) {
				// A refusal is an answer: do not retry (and do not lock the
				// probe account in the restored copy).
				return "", backoffErr{fmt.Errorf("refused: %s", ae.Reason)}
			}
			return "", err
		}
		s.Close()
		return "TGT for " + spec.ProbeUser, nil
	})
	out = append(out, check("kerberos", detail, unwrapBackoff(err)))

	tool := &sambatool.Runner{Binary: spec.SambaTool, Credentials: sambatool.Password{Username: spec.ProbeUser, Password: password}, Timeout: 2 * time.Minute}
	users, err := sambatool.Run(ctx, tool, sambatool.UserList{URL: "ldap://127.0.0.1"})
	if err == nil && !spec.Users.Contains(len(users)) {
		err = fmt.Errorf("%d users, the source had %d-%d", len(users), spec.Users.Min, spec.Users.Max)
	}
	out = append(out, check("users", strconv.Itoa(len(users))+" users", err))

	for _, s := range spec.Samples {
		got, err := sambatool.Run(ctx, tool, sambatool.ObjectSID{Kind: sambatool.ObjectKind(s.Kind), Name: s.Name, URL: "ldap://127.0.0.1"})
		if err == nil && got != s.SID {
			err = fmt.Errorf("SID %s, the source had %s", got, s.SID)
		}
		out = append(out, check("sid:"+s.Name, got, err))
	}
	return out
}

// backoffErr stops poll early (a definitive answer).
type backoffErr struct{ error }

func unwrapBackoff(err error) error {
	var b backoffErr
	if errors.As(err, &b) {
		return b.error
	}
	return err
}
