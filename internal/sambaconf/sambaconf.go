// Package sambaconf keeps the smb.conf that comes out of a backup from
// running anything on the restoring host.
//
// A Samba backup carries the backed-up DC's smb.conf, and smb.conf can make
// Samba run commands ("dns update command", "check password script",
// "panic action", "root preexec", ...), load modules ("vfs objects"), read
// other files ("include") or another configuration store ("config backend =
// registry"), and point shares anywhere ("[sysvol] path = /etc", where
// `samba-tool domain backup restore` then writes the archive's sysvol files
// as root). Whoever can produce a backup that verifies (the DC's signing key
// plus bucket write) controls that file, so it is never trusted:
//
//   - Before the restore, the archive's smb.conf is only read by this
//     package (never by Samba): a file that uses include, config backend,
//     config file or registry shares refuses the restore, and only the
//     workgroup is taken from it (checked). samba-tool gets a configuration
//     generated here (`--configfile`), so it never loads the archive's.
//   - After the restore, the smb.conf samba-tool wrote is checked against
//     an allowlist (the parameters `make_smbconf` writes for a restored DC,
//     with the values they must have) and rewritten in canonical form before
//     Samba starts. Anything else is dropped; a refused construct fails.
package sambaconf

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxSize bounds an smb.conf read from a backup.
const MaxSize = 1 << 20

// Param is one "name = value" line.
type Param struct {
	// Key is the name as written; Norm is the name Samba compares
	// (lower case, white space removed).
	Key, Norm, Value string
	Line             int
}

// Section is a [section] and its parameters in file order.
type Section struct {
	Name   string
	Params []Param
}

// Conf is a parsed smb.conf: Global holds [global] (and parameters before
// any section header), Shares every other section in file order.
type Conf struct {
	Global Section
	Shares []Section
	// Unparsed counts lines that are neither comments, section headers nor
	// "name = value" (Samba ignores them with a warning).
	Unparsed int
}

// RefusedError reports a construct that makes the configuration
// unusable for a restore (it would pull in configuration this package
// cannot see).
type RefusedError struct {
	Line   int
	Reason string
}

func (e *RefusedError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("smb.conf from the backup refused (line %d): %s", e.Line, e.Reason)
	}
	return "smb.conf from the backup refused: " + e.Reason
}

// Norm normalizes a parameter or section name the way Samba compares them
// (case-insensitive, white space ignored).
func Norm(k string) string {
	return strings.ToLower(strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, k))
}

// refusedKeys pull configuration from somewhere else: another file, the
// registry, or a whole new configuration file. Refused in any section.
var refusedKeys = map[string]string{
	"include":        "include pulls in another file",
	"configbackend":  "config backend selects another configuration store",
	"configfile":     "config file replaces the configuration",
	"registryshares": "registry shares loads shares from the registry",
}

// Parse reads an smb.conf the way Samba's parser splits it: comments start
// with '#' or ';', a trailing backslash continues a line, section names and
// parameter names compare case-insensitively without white space, and
// [global] is also spelled [globals].
func Parse(b []byte) (*Conf, error) {
	if len(b) > MaxSize {
		return nil, &RefusedError{Reason: fmt.Sprintf("larger than %d bytes", MaxSize)}
	}
	if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return nil, &RefusedError{Reason: "not UTF-8 text"}
	}
	c := &Conf{Global: Section{Name: "global"}}
	cur := &c.Global
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), MaxSize+1)
	lineNo, start := 0, 0
	var pending strings.Builder
	for sc.Scan() {
		lineNo++
		raw := strings.TrimRight(sc.Text(), "\r")
		if pending.Len() == 0 {
			start = lineNo
			t := strings.TrimSpace(raw)
			if t == "" || t[0] == '#' || t[0] == ';' {
				continue
			}
		}
		if strings.HasSuffix(raw, "\\") {
			pending.WriteString(strings.TrimSuffix(raw, "\\"))
			continue
		}
		pending.WriteString(raw)
		line := strings.TrimSpace(pending.String())
		pending.Reset()
		if strings.HasPrefix(line, "[") {
			end := strings.IndexByte(line, ']')
			if end < 0 {
				return nil, &RefusedError{Line: start, Reason: "unterminated section header"}
			}
			name := strings.TrimSpace(line[1:end])
			switch Norm(name) {
			case "global", "globals":
				cur = &c.Global
			default:
				c.Shares = append(c.Shares, Section{Name: name})
				cur = &c.Shares[len(c.Shares)-1]
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) == "" {
			c.Unparsed++
			continue
		}
		p := Param{Key: strings.TrimSpace(k), Norm: Norm(k), Value: strings.TrimSpace(v), Line: start}
		if reason, bad := refusedKeys[p.Norm]; bad {
			return nil, &RefusedError{Line: start, Reason: reason}
		}
		cur.Params = append(cur.Params, p)
	}
	if err := sc.Err(); err != nil {
		return nil, &RefusedError{Reason: err.Error()}
	}
	if pending.Len() > 0 {
		return nil, &RefusedError{Line: start, Reason: "continuation at the end of the file"}
	}
	return c, nil
}

// Get returns the last value of a [global] parameter (Samba's "last one
// wins") and how many times it is set.
func (c *Conf) Get(norm string) (string, int) {
	v, n := "", 0
	for _, p := range c.Global.Params {
		if p.Norm == norm {
			v, n = p.Value, n+1
		}
	}
	return v, n
}

var (
	// netbiosRE: NetBIOS host and domain names as this tool accepts them
	// (letters, digits, '-', '_' and '.', 1-15 characters).
	netbiosRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$`)
	realmRE   = regexp.MustCompile(`^[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$`)
	// pathRE: absolute paths without white space, quotes or Samba
	// substitutions (%).
	pathRE = regexp.MustCompile(`^/[A-Za-z0-9._/+-]+$`)
)

// Expect is what a restored DC's configuration must say.
type Expect struct {
	// NetbiosName of the restored DC (samba-tool's --newservername).
	NetbiosName string
	// Workgroup: the NetBIOS domain name.
	Workgroup string
	Realm     string
	// TargetDir is samba-tool's --targetdir (absolute, clean).
	TargetDir string
}

// Validate checks the expectation itself.
func (e Expect) Validate() error {
	switch {
	case !netbiosRE.MatchString(e.NetbiosName):
		return fmt.Errorf("invalid NetBIOS name %q", e.NetbiosName)
	case !netbiosRE.MatchString(e.Workgroup):
		return fmt.Errorf("invalid workgroup %q", e.Workgroup)
	case !realmRE.MatchString(e.Realm):
		return fmt.Errorf("invalid realm %q", e.Realm)
	case !pathRE.MatchString(e.TargetDir) || filepath.Clean(e.TargetDir) != e.TargetDir || strings.Contains(e.TargetDir, ".."):
		return fmt.Errorf("invalid target directory %q", e.TargetDir)
	}
	return nil
}

// global is the [global] allowlist with the value each parameter must
// have: exactly what samba-tool's make_smbconf writes for a restored DC
// (netbios name, workgroup, realm, server role and the five directories
// under the target). Nothing else is needed to start the restored domain:
// every other parameter keeps Samba's compiled-in default.
func (e Expect) global() []Param {
	t := e.TargetDir
	return []Param{
		{Key: "netbios name", Value: strings.ToUpper(e.NetbiosName)},
		{Key: "workgroup", Value: strings.ToUpper(e.Workgroup)},
		{Key: "realm", Value: strings.ToUpper(e.Realm)},
		{Key: "server role", Value: "active directory domain controller"},
		{Key: "private dir", Value: filepath.Join(t, "private")},
		{Key: "lock dir", Value: t},
		{Key: "state directory", Value: filepath.Join(t, "state")},
		{Key: "cache directory", Value: filepath.Join(t, "cache")},
		{Key: "binddns dir", Value: filepath.Join(t, "bind-dns")},
	}
}

// shares are the two shares of a DC, with their paths.
func (e Expect) shares() []Section {
	sysvol := filepath.Join(e.TargetDir, "state", "sysvol")
	return []Section{
		{Name: "sysvol", Params: []Param{{Key: "path", Value: sysvol}, {Key: "read only", Value: "no"}}},
		{Name: "netlogon", Params: []Param{{Key: "path", Value: filepath.Join(sysvol, strings.ToLower(e.Realm), "scripts")},
			{Key: "read only", Value: "no"}}},
	}
}

// aliases maps alternative spellings Samba accepts to the allowlisted name.
var aliases = map[string]string{
	"lockdirectory":    "lockdir",
	"privatedirectory": "privatedir",
	// Inverted spellings of "read only" are refused (see checkSection).
	"writeable": "readonly!",
	"writable":  "readonly!",
	"writeok":   "readonly!",
}

// Generate renders the configuration of a restored DC: the allowlist and
// nothing else, in the layout make_smbconf uses.
func Generate(e Expect) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("# Generated by conductor-backup for a restore: only the parameters a\n")
	b.WriteString("# restored domain controller needs (the backup's own smb.conf is not used).\n")
	b.WriteString("[global]\n")
	for _, p := range e.global() {
		fmt.Fprintf(&b, "\t%s = %s\n", p.Key, p.Value)
	}
	for _, s := range e.shares() {
		fmt.Fprintf(&b, "\n[%s]\n", s.Name)
		for _, p := range s.Params {
			fmt.Fprintf(&b, "\t%s = %s\n", p.Key, p.Value)
		}
	}
	return []byte(b.String()), nil
}

// FromBackup reads the smb.conf found in a backup before the restore: it
// refuses include, config backend, config file and registry shares, checks
// that its realm is the expected one, and returns the workgroup (the only
// value taken from it). Nothing else in the file is used.
func FromBackup(b []byte, realm string) (workgroup string, err error) {
	c, err := Parse(b)
	if err != nil {
		return "", err
	}
	if r, _ := c.Get("realm"); !strings.EqualFold(r, realm) {
		return "", &RefusedError{Reason: fmt.Sprintf("realm %q, the backup is of %q", r, realm)}
	}
	wg, n := c.Get("workgroup")
	if n == 0 {
		return "", &RefusedError{Reason: "no workgroup"}
	}
	if !netbiosRE.MatchString(wg) {
		return "", &RefusedError{Reason: fmt.Sprintf("workgroup %q is not a NetBIOS domain name this tool accepts", wg)}
	}
	return strings.ToUpper(wg), nil
}

// Report says what Sanitize removed.
type Report struct {
	// Dropped lists "section: parameter" entries that are not on the
	// allowlist (and whole sections as "[name]").
	Dropped []string
}

// Sanitize checks the smb.conf samba-tool wrote after a restore against
// the allowlist and returns its canonical form (Generate's output). Every
// allowlisted parameter must be present with exactly the expected value
// (paths are those under the target directory); parameters and sections
// that are not on the list are dropped and reported; include, config
// backend, config file and registry shares refuse it.
func Sanitize(b []byte, e Expect) ([]byte, Report, error) {
	var rep Report
	if err := e.Validate(); err != nil {
		return nil, rep, err
	}
	c, err := Parse(b)
	if err != nil {
		return nil, rep, err
	}
	if err := checkSection(c.Global, e.global(), "global", &rep); err != nil {
		return nil, rep, err
	}
	want := map[string]Section{}
	for _, s := range e.shares() {
		want[Norm(s.Name)] = s
	}
	seen := map[string]bool{}
	for _, s := range c.Shares {
		w, ok := want[Norm(s.Name)]
		if !ok {
			rep.Dropped = append(rep.Dropped, "["+s.Name+"]")
			continue
		}
		if seen[Norm(s.Name)] {
			return nil, rep, &RefusedError{Reason: fmt.Sprintf("section [%s] appears twice", s.Name)}
		}
		seen[Norm(s.Name)] = true
		if err := checkSection(s, w.Params, s.Name, &rep); err != nil {
			return nil, rep, err
		}
	}
	for _, s := range e.shares() {
		if !seen[Norm(s.Name)] {
			return nil, rep, &RefusedError{Reason: fmt.Sprintf("section [%s] is missing", s.Name)}
		}
	}
	sort.Strings(rep.Dropped)
	out, err := Generate(e)
	return out, rep, err
}

// checkSection verifies the allowlisted parameters of one section and
// records the others as dropped.
func checkSection(s Section, allowed []Param, name string, rep *Report) error {
	want := map[string]string{}
	for _, p := range allowed {
		want[Norm(p.Key)] = p.Value
	}
	found := map[string]bool{}
	for _, p := range s.Params {
		norm := p.Norm
		if a, ok := aliases[norm]; ok {
			norm = a
		}
		if _, governs := want["readonly"]; governs && strings.HasSuffix(norm, "!") {
			// "writeable = yes" is "read only = no" inverted: only the
			// canonical spelling is accepted, so a contradicting pair
			// cannot hide behind an alias.
			return &RefusedError{Line: p.Line, Reason: fmt.Sprintf("[%s] %q: use \"read only\"", name, p.Key)}
		}
		v, ok := want[norm]
		if !ok {
			rep.Dropped = append(rep.Dropped, name+": "+p.Key)
			continue
		}
		if !sameValue(norm, p.Value, v) {
			return &RefusedError{Line: p.Line, Reason: fmt.Sprintf("[%s] %s = %q, expected %q", name, p.Key, p.Value, v)}
		}
		found[norm] = true
	}
	for _, p := range allowed {
		if !found[Norm(p.Key)] {
			return &RefusedError{Reason: fmt.Sprintf("[%s] %s is missing", name, p.Key)}
		}
	}
	return nil
}

// sameValue compares a value with the expected one: names and roles
// case-insensitively, booleans by meaning, paths exactly (after cleaning,
// and only plain absolute paths: no substitutions).
func sameValue(norm, got, want string) bool {
	switch norm {
	case "path", "privatedir", "lockdir", "statedirectory", "cachedirectory", "binddnsdir":
		return pathRE.MatchString(got) && filepath.Clean(got) == want
	case "readonly":
		return falseWord(got) && falseWord(want)
	case "serverrole":
		g := strings.Join(strings.Fields(strings.ToLower(got)), " ")
		return g == want || g == "dc" || g == "active directory dc"
	default:
		return strings.EqualFold(got, want)
	}
}

func falseWord(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "no", "false", "0", "off":
		return true
	}
	return false
}

// ErrNoConf: the backup has no etc/smb.conf.
var ErrNoConf = errors.New("the Samba backup has no etc/smb.conf")
