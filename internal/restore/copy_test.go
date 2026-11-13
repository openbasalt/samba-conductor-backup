package restore

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCopyInto(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src", "key.pem")
	write(t, src, "KEY")
	root := filepath.Join(dir, "samba")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := copyInto(src, root, "private/tls/key.pem", 0o600, &owner{uid: os.Getuid(), gid: os.Getgid()}); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(root, "private", "tls", "key.pem")
	if read(t, dst) != "KEY" {
		t.Fatal("content")
	}
	if st, _ := os.Lstat(dst); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	// Overwrites a regular file in place.
	write(t, src, "KEY2")
	if err := copyInto(src, root, "private/tls/key.pem", 0o644, nil); err != nil || read(t, dst) != "KEY2" {
		t.Fatalf("overwrite: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(root, "private", "tls"))
	if len(entries) != 1 {
		t.Fatalf("temporary files left: %v", entries)
	}
}

// TestCopyIntoPlantedLink: a symbolic link planted at the destination is
// replaced, and the file it points to is untouched.
func TestCopyIntoPlantedLink(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	write(t, src, "NEW")
	victim := filepath.Join(dir, "victim")
	write(t, victim, "ORIGINAL")
	root := filepath.Join(dir, "samba")
	if err := os.MkdirAll(filepath.Join(root, "private"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(root, "private", "cert.pem")); err != nil {
		t.Fatal(err)
	}
	if err := copyInto(src, root, "private/cert.pem", 0o644, nil); err != nil {
		t.Fatal(err)
	}
	if read(t, victim) != "ORIGINAL" {
		t.Fatal("wrote through the planted link")
	}
	if st, _ := os.Lstat(filepath.Join(root, "private", "cert.pem")); !st.Mode().IsRegular() {
		t.Fatal("link not replaced")
	}
}

func TestCopyIntoRefuses(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	write(t, src, "X")
	outside := filepath.Join(dir, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "samba")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	// A directory on the way that is a link, inside or outside the root.
	_ = os.Symlink(outside, filepath.Join(root, "private"))
	if err := copyInto(src, root, "private/tls/key.pem", 0o600, nil); err == nil {
		t.Fatal("link to the outside followed")
	}
	_ = os.Remove(filepath.Join(root, "private"))
	_ = os.MkdirAll(filepath.Join(root, "real"), 0o700)
	_ = os.Symlink("real", filepath.Join(root, "private"))
	if err := copyInto(src, root, "private/key.pem", 0o600, nil); err == nil {
		t.Fatal("link inside the root followed")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("written outside: %v", entries)
	}
	// The root itself as a link.
	link := filepath.Join(dir, "rootlink")
	_ = os.Symlink(outside, link)
	if err := copyInto(src, link, "x", 0o600, nil); err == nil {
		t.Fatal("linked root accepted")
	}
	// A linked source.
	lsrc := filepath.Join(dir, "lsrc")
	_ = os.Symlink(src, lsrc)
	if err := copyInto(lsrc, root, "y", 0o600, nil); err == nil {
		t.Fatal("linked source accepted")
	}
	// Names that leave the root.
	for _, rel := range []string{"../x", "..", "", "."} {
		if err := copyInto(src, root, rel, 0o600, nil); err == nil {
			t.Errorf("%q accepted", rel)
		}
	}
	// A directory at the destination.
	_ = os.MkdirAll(filepath.Join(root, "real", "d"), 0o700)
	if err := copyInto(src, root, "real/d", 0o600, nil); err == nil {
		t.Fatal("directory replaced")
	}
}
