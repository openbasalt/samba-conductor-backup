package runner

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/openbasalt/samba-conductor-backup/internal/config"
	"github.com/openbasalt/samba-conductor-backup/internal/dest"
	"github.com/openbasalt/samba-conductor-backup/internal/manifest"
	"github.com/openbasalt/samba-conductor-backup/internal/sign"
)

// Listed is one backup as found in a destination.
type Listed struct {
	ID          string
	Destination string
	Size        int64
	HasArchive  bool
	Manifest    *manifest.Manifest
	// ManifestErr explains why the manifest is not usable.
	ManifestErr string
}

// Usable reports a complete backup with a verified manifest that matches
// the archive's size.
func (l Listed) Usable() bool {
	return l.HasArchive && l.Manifest != nil && l.Manifest.Size == l.Size
}

// ListBackups lists the backups of a realm in a destination, newest first,
// verifying manifest signatures against trusted keys.
func ListBackups(ctx context.Context, s dest.Store, realm string, trusted []sign.PublicKey) ([]Listed, error) {
	objs, err := s.List(ctx, dest.DomainPrefix(realm))
	if err != nil {
		return nil, err
	}
	by := map[string]*Listed{}
	get := func(id string) *Listed {
		if by[id] == nil {
			by[id] = &Listed{ID: id, Destination: s.Name()}
		}
		return by[id]
	}
	for _, o := range objs {
		name := strings.TrimPrefix(o.Key, dest.DomainPrefix(realm))
		switch {
		case strings.HasSuffix(name, ".tar.age"):
			l := get(strings.TrimSuffix(name, ".tar.age"))
			l.HasArchive, l.Size = true, o.Size
		case strings.HasSuffix(name, ".json"):
			l := get(strings.TrimSuffix(name, ".json"))
			b, err := dest.ReadAll(ctx, s, o.Key, 1<<20)
			if err != nil {
				l.ManifestErr = err.Error()
				continue
			}
			var m manifest.Manifest
			if _, err := sign.Open(b, trusted, &m); err != nil {
				l.ManifestErr = err.Error()
				continue
			}
			if err := m.Validate(realm); err != nil || m.ID != l.ID {
				l.ManifestErr = fmt.Sprint("invalid manifest: ", err)
				continue
			}
			l.Manifest = &m
		}
	}
	out := make([]Listed, 0, len(by))
	for _, l := range by {
		if l.Manifest == nil && l.ManifestErr == "" {
			l.ManifestErr = "no manifest"
		}
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// Latest returns the newest usable backup (optionally a given ID).
func Latest(list []Listed, id string) (Listed, error) {
	for _, l := range list {
		if (id == "" || l.ID == id) && l.Usable() {
			return l, nil
		}
	}
	if id != "" {
		for _, l := range list {
			if l.ID == id {
				return l, fmt.Errorf("backup %s is not usable: %s", id, firstNonEmpty(l.ManifestErr, "archive missing or size differs from the manifest"))
			}
		}
		return Listed{}, fmt.Errorf("backup %s not found", id)
	}
	return Listed{}, errors.New("no usable backup found")
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// TrustedBackupKeys returns the keys that verify manifests: the configured
// public keys plus, when readable, the public half of this host's signing
// key.
func TrustedBackupKeys(cfg *config.Config) []sign.PublicKey {
	keys, _ := config.PublicKeys(cfg.BackupPublicKeys)
	if k, err := cfg.LoadSigningKey(cfg.SigningKey); err == nil {
		keys = append(keys, k.Public())
	}
	return keys
}

// Verify downloads a backup from a destination and checks it against its
// signed manifest, without decrypting.
func Verify(ctx context.Context, s dest.Store, realm, id string, trusted []sign.PublicKey) (Listed, error) {
	list, err := ListBackups(ctx, s, realm, trusted)
	if err != nil {
		return Listed{}, err
	}
	l, err := Latest(list, id)
	if err != nil {
		return l, err
	}
	return l, VerifyObject(ctx, s, dest.ArchiveKey(realm, l.ID), l.Manifest.Size, l.Manifest.SHA256)
}
