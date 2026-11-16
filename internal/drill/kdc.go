package drill

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-backup/internal/sambaconf"
)

// Samba builds with one of two KDCs: Heimdal (embedded; Debian, Ubuntu)
// or MIT Kerberos (krb5kdc with Samba's KDB plugin; Fedora, RHEL). A
// restored domain keeps the KDC files of the build that made the backup
// (an MIT build reads private/kdc.conf, which a Heimdal DC never wrote), so
// drilling a backup on a drill host of the other flavour is not supported:
// the drill refuses it before the sandbox starts.

// kdcProbe asks Samba's Python bindings which KDC the build uses.
const kdcProbe = "import samba; print('heimdal' if samba.is_heimdal_built() else 'mit')"

// hostKDC reports the KDC flavour of the drill host's Samba: it runs the
// probe with the interpreter samba-tool runs under (its #! line).
func hostKDC(ctx context.Context, sambaTool string) (string, error) {
	py, err := scriptInterpreter(sambaTool)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// -I: no environment variables, user site or current directory on the
	// module path; only the system's.
	cmd := exec.CommandContext(ctx, py, "-I", "-c", kdcProbe)
	cmd.Env = sandboxEnv
	cmd.Dir = "/"
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s: %w", py, err)
	}
	switch v := strings.TrimSpace(string(out)); v {
	case sambaconf.KDCHeimdal, sambaconf.KDCMIT:
		return v, nil
	default:
		return "", fmt.Errorf("%s: unexpected answer %q", py, v)
	}
}

// scriptInterpreter reads a script's #! line: "/usr/bin/python3" or
// "/usr/bin/env python3" (looked up in the sandbox's PATH).
func scriptInterpreter(script string) (string, error) {
	f, err := os.Open(script)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("%s: %w", script, err)
	}
	if !strings.HasPrefix(line, "#!") {
		return "", fmt.Errorf("%s has no #! line", script)
	}
	f2 := strings.Fields(strings.TrimPrefix(line, "#!"))
	if len(f2) == 0 {
		return "", fmt.Errorf("%s: empty #! line", script)
	}
	interp := f2[0]
	if filepath.Base(interp) == "env" {
		var name string
		for _, a := range f2[1:] {
			if !strings.HasPrefix(a, "-") {
				name = a
				break
			}
		}
		if name == "" || strings.Contains(name, "/") {
			return "", fmt.Errorf("%s: unreadable #! line %q", script, strings.TrimSpace(line))
		}
		for _, dir := range []string{"/usr/local/bin", "/usr/bin", "/bin"} {
			p := filepath.Join(dir, name)
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
				return p, nil
			}
		}
		return "", fmt.Errorf("%s: %s not found", script, name)
	}
	if !filepath.IsAbs(interp) {
		return "", fmt.Errorf("%s: relative interpreter %q", script, interp)
	}
	return interp, nil
}

// errKDCMismatch: the backup and the drill host use different KDCs.
var errKDCMismatch = errors.New("unsupported drill: KDC flavours differ")

// checkKDC refuses a backup made by a build with another KDC than the
// drill host's.
func checkKDC(backup, host string) error {
	if backup == host {
		return nil
	}
	return fmt.Errorf("%w: the backup was made by a Samba build with the %s KDC and this drill host's Samba uses the %s KDC "+
		"(for example a backup of a Debian DC on a Fedora drill host). Drilling across KDC flavours is not supported: "+
		"drill on a host whose Samba build matches the DC's", errKDCMismatch, kdcName(backup), kdcName(host))
}

func kdcName(f string) string {
	if f == sambaconf.KDCMIT {
		return "MIT Kerberos"
	}
	return "Heimdal"
}
