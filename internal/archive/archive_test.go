package archive

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/samba-conductor/ad/helper"
)

// build writes an archive the way conductor-helper does.
func build(t *testing.T, to age.Recipient, members map[string]string, order []string, meta *helper.ArchiveMeta) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := age.Encrypt(&out, to)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(w)
	add := func(name string, b []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), Typeflag: tar.TypeReg, ModTime: time.Now()}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write(b)
	}
	if meta != nil {
		b, _ := json.Marshal(meta)
		add(helper.ArchiveMetaName, b)
	}
	for _, n := range order {
		add(n, []byte(members[n]))
	}
	_ = tw.Close()
	_ = w.Close()
	return out.Bytes()
}

func validMeta() *helper.ArchiveMeta {
	return &helper.ArchiveMeta{Format: helper.ArchiveFormat, ID: "20261003T011350Z-dc1", Realm: "LAB.TEST", DC: "dc1",
		SambaFile: "samba/samba-backup.tar.bz2", Users: helper.CountRange{Min: 3, Max: 3}}
}

func TestExtract(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	other, _ := age.GenerateX25519Identity()
	members := map[string]string{"samba/samba-backup.tar.bz2": "BZh9…", "files/etc/samba/smb.conf": "[global]\n", "conductor/conductor.db": "SQLite"}
	order := []string{"samba/samba-backup.tar.bz2", "files/etc/samba/smb.conf", "conductor/conductor.db"}
	data := build(t, id.Recipient(), members, order, validMeta())

	dir := filepath.Join(t.TempDir(), "x")
	meta, err := Extract(bytes.NewReader(data), []age.Identity{id}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if meta.ID != "20261003T011350Z-dc1" {
		t.Fatalf("meta %+v", meta)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "files/etc/samba/smb.conf"))
	if string(b) != "[global]\n" {
		t.Fatal("content")
	}
	st, _ := os.Stat(filepath.Join(dir, "conductor/conductor.db"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}

	if _, err := Extract(bytes.NewReader(data), []age.Identity{other}, t.TempDir()); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong key: %v", err)
	}
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)-40] ^= 1
	if _, err := Extract(bytes.NewReader(tampered), []age.Identity{id}, t.TempDir()); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	evil := build(t, id.Recipient(), map[string]string{"../../etc/x": "x"}, []string{"../../etc/x"}, validMeta())
	if _, err := Extract(bytes.NewReader(evil), []age.Identity{id}, t.TempDir()); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("path traversal: %v", err)
	}
	noMeta := build(t, id.Recipient(), members, order, nil)
	if _, err := Extract(bytes.NewReader(noMeta), []age.Identity{id}, t.TempDir()); err == nil {
		t.Fatal("archive without metadata accepted")
	}
}

func TestIdentitiesAndShred(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	f := filepath.Join(t.TempDir(), "key.txt")
	_ = os.WriteFile(f, []byte("# created\n"+id.String()+"\n"), 0o644)
	if _, err := LoadIdentities(f); err == nil {
		t.Fatal("world-readable identity accepted")
	}
	_ = os.Chmod(f, 0o600)
	ids, err := LoadIdentities(f)
	if err != nil || len(ids) != 1 {
		t.Fatalf("identities %v", err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "a", "plain")
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	_ = os.WriteFile(p, []byte(strings.Repeat("secret", 1000)), 0o600)
	if err := ShredTree(filepath.Join(dir, "a")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a")); !os.IsNotExist(err) {
		t.Fatal("tree not removed")
	}
	if err := Shred(filepath.Join(dir, "none")); err != nil {
		t.Fatal(err)
	}
}
