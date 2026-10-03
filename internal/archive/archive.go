// Package archive reads conductor-backup archives: age decryption with an
// operator- or drill-provided identity, then extraction of the tar members
// (format in ad/helper: ArchiveMeta first, then samba/, conductor/,
// files/). It also shreds the plaintext a restore leaves behind.
package archive

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/samba-conductor/ad/helper"
	"github.com/samba-conductor/conductor-backup/internal/sign"
)

// LoadIdentities reads an age identity file (AGE-SECRET-KEY-… lines). The
// file must not be accessible by group or others.
func LoadIdentities(path string) ([]age.Identity, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 && !sign.InCredentialsDir(path) {
		return nil, fmt.Errorf("archive: identity file %s is accessible by group or others (mode %o)", path, st.Mode().Perm())
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("archive: identity file: %w", err)
	}
	return ids, nil
}

// ErrWrongKey: none of the identities can decrypt the archive.
var ErrWrongKey = errors.New("archive: the identity does not match any recipient of this backup")

// MaxMember bounds one extracted member (64 GiB).
const MaxMember = 64 << 30

// Extract decrypts r and writes every member under dir (directories 0700,
// files 0600). It refuses unsafe member names and anything but regular
// files and directories. The metadata member must come first.
func Extract(r io.Reader, ids []age.Identity, dir string) (helper.ArchiveMeta, error) {
	var meta helper.ArchiveMeta
	pr, err := age.Decrypt(r, ids...)
	if err != nil {
		var nm *age.NoIdentityMatchError
		if errors.As(err, &nm) {
			return meta, ErrWrongKey
		}
		return meta, fmt.Errorf("archive: decrypt: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return meta, err
	}
	tr := tar.NewReader(pr)
	first := true
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// age authenticates every chunk: a modified ciphertext fails here.
			return meta, fmt.Errorf("archive: reading: %w", err)
		}
		if !helper.SafeMember(strings.TrimSuffix(h.Name, "/")) {
			return meta, fmt.Errorf("archive: unsafe member %q", h.Name)
		}
		if first {
			first = false
			if h.Name != helper.ArchiveMetaName || h.Size > 1<<20 {
				return meta, errors.New("archive: metadata is not the first member")
			}
			b, err := io.ReadAll(tr)
			if err != nil {
				return meta, err
			}
			dec := json.NewDecoder(bytes.NewReader(b))
			if err := dec.Decode(&meta); err != nil {
				return meta, fmt.Errorf("archive: metadata: %w", err)
			}
			if err := meta.Validate(); err != nil {
				return meta, fmt.Errorf("archive: %w", err)
			}
			if err := os.WriteFile(filepath.Join(dir, helper.ArchiveMetaName), b, 0o600); err != nil {
				return meta, err
			}
			continue
		}
		target := filepath.Join(dir, filepath.FromSlash(strings.TrimSuffix(h.Name, "/")))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return meta, err
			}
		case tar.TypeReg:
			if h.Size < 0 || h.Size > MaxMember {
				return meta, fmt.Errorf("archive: member %s too large", h.Name)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return meta, err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return meta, err
			}
			_, err = io.CopyN(f, tr, h.Size)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return meta, fmt.Errorf("archive: %s: %w", h.Name, err)
			}
		default:
			return meta, fmt.Errorf("archive: member %s has an unsupported type", h.Name)
		}
	}
	if first {
		return meta, errors.New("archive: empty")
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(meta.SambaFile))); err != nil {
		return meta, fmt.Errorf("archive: samba backup member missing: %w", err)
	}
	return meta, nil
}

// Shred overwrites a regular file with zeros, syncs and removes it. On
// copy-on-write or flash storage an overwrite is not a guarantee; the
// plaintext should live on tmpfs or an encrypted disk (documented).
func Shred(path string) error {
	st, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode().IsRegular() && st.Size() > 0 {
		if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			zero := make([]byte, 1<<20)
			for left := st.Size(); left > 0; {
				n := int64(len(zero))
				if left < n {
					n = left
				}
				if _, err := f.Write(zero[:n]); err != nil {
					break
				}
				left -= n
			}
			_ = f.Sync()
			_ = f.Close()
		}
	}
	return os.Remove(path)
}

// ShredTree shreds every regular file under dir, then removes dir.
func ShredTree(dir string) error {
	var errs []error
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if err := Shred(p); err != nil {
				errs = append(errs, err)
			}
		}
		return nil
	})
	if err := os.RemoveAll(dir); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
