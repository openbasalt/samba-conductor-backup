// Package dest stores backup objects in a destination: a local directory
// or an S3-compatible bucket. Object layout (relative to the destination's
// root or prefix):
//
//	domain/<realm>/<id>.tar.age              the encrypted archive
//	domain/<realm>/<id>.json                 its signed manifest
//	drills/<realm>/requests/<request>.json    signed drill requests (from the DC)
//	drills/<realm>/reports/<drill>.json      signed drill reports (from the drill host)
//
// <realm> is the lower-case realm, <id> "<UTC timestamp>-<dc>".
package dest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/openbasalt/samba-conductor-ad/helper"
	"github.com/openbasalt/samba-conductor-backup/internal/config"
	"github.com/openbasalt/samba-conductor-backup/internal/s3"
)

// Object is a stored object (key relative to the destination root).
type Object = s3.Object

// Store is one destination.
type Store interface {
	Name() string
	// Describe returns what may be shown to administrators (no secrets).
	Describe() helper.BackupDestination
	// PutFile uploads a local file whose SHA-256 and MD5 are known; the
	// destination verifies the SHA-256 while writing.
	PutFile(ctx context.Context, key, path string, size int64, sha256Hex, md5Base64 string) error
	// PutBytes stores a small object (manifests, requests, reports).
	PutBytes(ctx context.Context, key string, b []byte) error
	Get(ctx context.Context, key string) (io.ReadCloser, int64, error)
	List(ctx context.Context, prefix string) ([]Object, error)
	Delete(ctx context.Context, key string) error
}

// ErrNotFound is returned for a missing object.
var ErrNotFound = errors.New("dest: object not found")

// Key layout.

// RealmDir is the realm as it appears in keys.
func RealmDir(realm string) string { return strings.ToLower(realm) }

// DomainPrefix is where a realm's archives and manifests live.
func DomainPrefix(realm string) string { return "domain/" + RealmDir(realm) + "/" }

// ArchiveKey of a backup.
func ArchiveKey(realm, id string) string { return DomainPrefix(realm) + id + ".tar.age" }

// ManifestKey of a backup.
func ManifestKey(realm, id string) string { return DomainPrefix(realm) + id + ".json" }

// RequestPrefix holds drill requests.
func RequestPrefix(realm string) string { return "drills/" + RealmDir(realm) + "/requests/" }

// ReportPrefix holds drill reports.
func ReportPrefix(realm string) string { return "drills/" + RealmDir(realm) + "/reports/" }

var docIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

// DocKey is the key of a request or report document.
func DocKey(prefix, id string) (string, error) {
	if !docIDRE.MatchString(id) {
		return "", fmt.Errorf("dest: invalid document id %q", id)
	}
	return prefix + id + ".json", nil
}

// Open builds the store of a configured destination.
func Open(cfg *config.Config, d config.Destination) (Store, error) {
	switch d.Type {
	case "local":
		return &Local{name: d.Name, root: d.Path}, nil
	case "s3":
		var keys config.S3Keys
		if err := cfg.DecodeCredential(d.Credentials, &keys); err != nil {
			return nil, err
		}
		pool, err := config.CertPool(d.CAFile)
		if err != nil {
			return nil, err
		}
		c, err := s3.New(s3.Config{Endpoint: d.Endpoint, Region: d.Region, Bucket: d.Bucket, PathStyle: d.PathStyle,
			AccessKey: keys.AccessKeyID, SecretKey: keys.SecretAccessKey, RootCAs: pool})
		if err != nil {
			return nil, err
		}
		return &S3{d: d, c: c}, nil
	}
	return nil, fmt.Errorf("dest: unknown type %q", d.Type)
}

// ---- local directory ----

// Local stores objects as files under a root directory (0700 directories,
// 0600 files), written to a temporary name, synced and renamed.
type Local struct {
	name string
	root string
}

// Name implements Store.
func (l *Local) Name() string { return l.name }

// Describe implements Store.
func (l *Local) Describe() helper.BackupDestination {
	return helper.BackupDestination{Name: l.name, Type: "local", Location: l.root}
}

func (l *Local) path(key string) (string, error) {
	if !helper.SafeMember(key) {
		return "", fmt.Errorf("dest: unsafe key %q", key)
	}
	return filepath.Join(l.root, filepath.FromSlash(key)), nil
}

func (l *Local) write(key string, src io.Reader, wantSHA string) error {
	p, err := l.path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".partial-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), src); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if wantSHA != "" && hex.EncodeToString(h.Sum(nil)) != wantSHA {
		return errors.New("dest: SHA-256 mismatch while writing")
	}
	return os.Rename(tmp.Name(), p)
}

// PutFile implements Store.
func (l *Local) PutFile(_ context.Context, key, path string, _ int64, sha256Hex, _ string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return l.write(key, f, sha256Hex)
}

// PutBytes implements Store.
func (l *Local) PutBytes(_ context.Context, key string, b []byte) error {
	return l.write(key, strings.NewReader(string(b)), "")
}

// Get implements Store.
func (l *Local) Get(_ context.Context, key string) (io.ReadCloser, int64, error) {
	p, err := l.path(key)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, st.Size(), nil
}

// List implements Store.
func (l *Local) List(_ context.Context, prefix string) ([]Object, error) {
	dir := filepath.Join(l.root, filepath.FromSlash(strings.TrimSuffix(prefix, "/")))
	var out []Object
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || strings.HasPrefix(d.Name(), ".partial-") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(l.root, p)
		key := filepath.ToSlash(rel)
		if strings.HasPrefix(key, prefix) {
			out = append(out, Object{Key: key, Size: info.Size(), LastModified: info.ModTime().UTC()})
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, err
}

// Delete implements Store.
func (l *Local) Delete(_ context.Context, key string) error {
	p, err := l.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// ---- S3 ----

// S3 stores objects in a bucket under the configured prefix.
type S3 struct {
	d config.Destination
	c *s3.Client
}

// Name implements Store.
func (s *S3) Name() string { return s.d.Name }

// Describe implements Store.
func (s *S3) Describe() helper.BackupDestination {
	host := strings.TrimPrefix(strings.TrimPrefix(s.d.Endpoint, "https://"), "http://")
	return helper.BackupDestination{Name: s.d.Name, Type: "s3", Location: host + "/" + s.d.Bucket + "/" + s.d.Prefix,
		ObjectLockDays: s.d.ObjectLockDays}
}

// PutFile implements Store.
func (s *S3) PutFile(ctx context.Context, key, path string, size int64, sha256Hex, md5Base64 string) error {
	var lock *s3.Lock
	if s.d.ObjectLockDays > 0 && strings.HasSuffix(key, ".tar.age") {
		lock = &s3.Lock{Mode: s.d.ObjectLockMode, Until: time.Now().Add(time.Duration(s.d.ObjectLockDays) * 24 * time.Hour)}
	}
	open := func() (io.ReadCloser, error) { return os.Open(path) }
	return s.c.Put(ctx, s.d.Prefix+key, open, size, sha256Hex, md5Base64, lock)
}

// PutBytes implements Store.
func (s *S3) PutBytes(ctx context.Context, key string, b []byte) error {
	sum, md := Digests(b)
	open := func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(string(b))), nil }
	return s.c.Put(ctx, s.d.Prefix+key, open, int64(len(b)), sum, md, nil)
}

// Get implements Store.
func (s *S3) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	rc, n, err := s.c.Get(ctx, s.d.Prefix+key)
	if s3.IsNotFound(err) {
		return nil, 0, ErrNotFound
	}
	return rc, n, err
}

// List implements Store.
func (s *S3) List(ctx context.Context, prefix string) ([]Object, error) {
	objs, err := s.c.List(ctx, s.d.Prefix+prefix)
	for i := range objs {
		objs[i].Key = strings.TrimPrefix(objs[i].Key, s.d.Prefix)
	}
	return objs, err
}

// Delete implements Store.
func (s *S3) Delete(ctx context.Context, key string) error { return s.c.Delete(ctx, s.d.Prefix+key) }

// ReadAll reads a small object (at most limit bytes).
func ReadAll(ctx context.Context, st Store, key string, limit int64) ([]byte, error) {
	rc, _, err := st.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("dest: %s is larger than %d bytes", key, limit)
	}
	return b, nil
}
