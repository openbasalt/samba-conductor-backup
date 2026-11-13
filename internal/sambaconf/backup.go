package sambaconf

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"

	"github.com/openbasalt/samba-conductor-ad/sambatool"
)

// sysvolTar is the nested archive `samba-tool domain backup online`
// writes at the top of its backup (sysvol with its NT ACLs); `backup
// restore` extracts it with Python's tarfile as well.
const sysvolTar = "sysvol.tar.gz"

// ScanBackup reads a Samba backup file (`samba-tool domain backup`
// output: tar, bzip2 or gzip compressed) before samba-tool extracts it as
// root, and refuses anything an extraction could turn against the host:
// links (symbolic and hard), devices, FIFOs, absolute names or names with
// "..", set-user-ID or set-group-ID files and duplicate names, in the
// backup and in the sysvol archive nested in it. Python's tarfile filter
// would also refuse most of these, but it has had bypasses; a backup made
// by `samba-tool domain backup online` holds only directories and regular
// files. It returns the backup's etc/smb.conf (for FromBackup).
func ScanBackup(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	r, err := decompress(bufio.NewReader(f))
	if err != nil {
		return nil, err
	}
	var conf []byte
	err = scanTar(r, "", func(name string, hdr *tar.Header, body io.Reader) error {
		switch name {
		case "etc/smb.conf":
			if hdr.Size > MaxSize {
				return fmt.Errorf("etc/smb.conf is larger than %d bytes", MaxSize)
			}
			b, err := io.ReadAll(io.LimitReader(body, MaxSize+1))
			if err != nil {
				return err
			}
			conf = b
		case sysvolTar:
			z, err := gzip.NewReader(body)
			if err != nil {
				return fmt.Errorf("%s: %w", sysvolTar, err)
			}
			if err := scanTar(z, sysvolTar+": ", nil); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("samba backup refused: %w", err)
	}
	if conf == nil {
		return nil, ErrNoConf
	}
	return conf, nil
}

// decompress picks the decompressor from the magic bytes, as Python's
// tarfile.open does.
func decompress(br *bufio.Reader) (io.Reader, error) {
	head, err := br.Peek(3)
	if err != nil {
		return nil, fmt.Errorf("samba backup: %w", err)
	}
	switch {
	case bytes.HasPrefix(head, []byte("BZh")):
		return bzip2.NewReader(br), nil
	case head[0] == 0x1f && head[1] == 0x8b:
		return gzip.NewReader(br)
	default:
		return br, nil
	}
}

// scanTar walks a tar stream, checks every member and hands regular files
// to fn (nil: only check).
func scanTar(r io.Reader, label string, fn func(name string, hdr *tar.Header, body io.Reader) error) error {
	tr := tar.NewReader(r)
	seen := map[string]bool{}
	members := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%sunreadable tar: %w", label, err)
		}
		members++
		name, err := memberName(hdr.Name)
		if err != nil {
			return fmt.Errorf("%s%w", label, err)
		}
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeDir:
		default:
			return fmt.Errorf("%s%q: only directories and regular files are accepted (type %q)", label, hdr.Name, hdr.Typeflag)
		}
		if hdr.Mode&0o6000 != 0 {
			return fmt.Errorf("%s%q: set-user-ID or set-group-ID bit", label, hdr.Name)
		}
		if name == "" {
			continue
		}
		if seen[name] {
			return fmt.Errorf("%s%q appears twice", label, hdr.Name)
		}
		seen[name] = true
		if hdr.Typeflag == tar.TypeReg && fn != nil {
			if err := fn(name, hdr, tr); err != nil {
				return err
			}
		}
	}
	if members == 0 {
		return fmt.Errorf("%sempty archive", label)
	}
	return nil
}

// memberName returns the cleaned relative name of a member ("" for the
// archive's root, "./" in samba-tool's backups), or an error for absolute
// names, ".." and control characters.
func memberName(n string) (string, error) {
	if n == "" || len(n) > 4096 || strings.ContainsFunc(n, unicode.IsControl) || strings.ContainsRune(n, '\\') {
		return "", fmt.Errorf("member name %q refused", n)
	}
	if strings.HasPrefix(n, "/") {
		return "", fmt.Errorf("absolute member name %q", n)
	}
	for _, part := range strings.Split(n, "/") {
		if part == ".." {
			return "", fmt.Errorf("member name %q leaves the archive", n)
		}
	}
	c := path.Clean(n)
	if c == "." {
		return "", nil
	}
	return c, nil
}

// RestoreOp is `samba-tool domain backup restore` with --configfile: the
// configuration samba-tool loads (and copies over the backup's
// etc/smb.conf, keeping that one as smb.conf.orig) is the one Generate
// wrote, never the backup's.
type RestoreOp struct {
	sambatool.DomainBackupRestore
	// ConfigFile is Generate's output (absolute path).
	ConfigFile string
}

// Command implements sambatool.Operation.
func (o RestoreOp) Command() (sambatool.Command, error) {
	c, err := o.DomainBackupRestore.Command()
	if err != nil {
		return c, err
	}
	if !pathRE.MatchString(o.ConfigFile) || filepath.Clean(o.ConfigFile) != o.ConfigFile || strings.Contains(o.ConfigFile, "..") {
		return sambatool.Command{}, fmt.Errorf("sambaconf: invalid configuration path %q", o.ConfigFile)
	}
	c.Options = append(c.Options, "--configfile="+o.ConfigFile)
	return c, nil
}

// Prepare scans a Samba backup file, reads the workgroup from its
// smb.conf and writes the configuration samba-tool restores with
// (configPath, a new 0600 file). It returns the expectation Sanitize
// checks the restored configuration against.
func Prepare(backupFile, configPath, netbiosName, realm, targetDir string) (Expect, error) {
	raw, err := ScanBackup(backupFile)
	if err != nil {
		return Expect{}, err
	}
	wg, err := FromBackup(raw, realm)
	if err != nil {
		return Expect{}, err
	}
	e := Expect{NetbiosName: strings.ToUpper(netbiosName), Workgroup: wg, Realm: strings.ToUpper(realm), TargetDir: targetDir}
	conf, err := Generate(e)
	if err != nil {
		return Expect{}, err
	}
	f, err := os.OpenFile(configPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return Expect{}, err
	}
	if _, err := f.Write(conf); err != nil {
		_ = f.Close()
		return Expect{}, err
	}
	return e, f.Close()
}

// Finalize checks the smb.conf samba-tool left in TargetDir/etc against
// the expectation and replaces it with the canonical form (written to a
// new file, then renamed over it, so a link planted there is replaced,
// not followed).
func Finalize(e Expect) (Report, error) {
	p := filepath.Join(e.TargetDir, "etc", "smb.conf")
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Report{}, fmt.Errorf("restored smb.conf: %w", err)
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		return Report{}, errors.New("restored smb.conf is not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	_ = f.Close()
	if err != nil {
		return Report{}, err
	}
	out, rep, err := Sanitize(b, e)
	if err != nil {
		return rep, err
	}
	tmp := p + ".conductor-backup"
	_ = os.Remove(tmp)
	w, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return rep, err
	}
	if _, err := w.Write(out); err != nil {
		_ = w.Close()
		return rep, err
	}
	if err := w.Close(); err != nil {
		return rep, err
	}
	return rep, os.Rename(tmp, p)
}
