package dest

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalStore(t *testing.T) {
	root := t.TempDir()
	l := &Local{name: "local", root: root}
	ctx := context.Background()
	src := filepath.Join(t.TempDir(), "a")
	if err := os.WriteFile(src, []byte("ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	size, sum, md, err := FileDigests(src)
	if err != nil {
		t.Fatal(err)
	}
	key := ArchiveKey("LAB.TEST", "20261003T011350Z-dc1")
	if key != "domain/lab.test/20261003T011350Z-dc1.tar.age" {
		t.Fatalf("key %q", key)
	}
	if err := l.PutFile(ctx, key, src, size, sum, md); err != nil {
		t.Fatal(err)
	}
	if err := l.PutFile(ctx, "domain/lab.test/bad.tar.age", src, size, "00"+sum[2:], md); err == nil {
		t.Fatal("SHA mismatch accepted")
	}
	if err := l.PutBytes(ctx, ManifestKey("LAB.TEST", "20261003T011350Z-dc1"), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(filepath.Join(root, "domain", "lab.test"))
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", st.Mode().Perm())
	}
	objs, err := l.List(ctx, DomainPrefix("LAB.TEST"))
	if err != nil || len(objs) != 2 {
		t.Fatalf("list %+v %v", objs, err)
	}
	rc, n, err := l.Get(ctx, key)
	if err != nil || n != size {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(b) != "ciphertext" {
		t.Fatal("content")
	}
	if _, _, err := l.Get(ctx, "domain/lab.test/none"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	for _, bad := range []string{"../x", "/etc/passwd", "a/../../b"} {
		if err := l.PutBytes(ctx, bad, nil); err == nil {
			t.Errorf("unsafe key %q accepted", bad)
		}
	}
	if err := l.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if objs, _ := l.List(ctx, "domain/"); len(objs) != 1 {
		t.Fatalf("after delete %d", len(objs))
	}
	if objs, err := l.List(ctx, "drills/"); err != nil || len(objs) != 0 {
		t.Fatalf("empty prefix: %v %v", objs, err)
	}
	if _, err := DocKey(RequestPrefix("LAB.TEST"), "../x"); err == nil {
		t.Fatal("bad doc id accepted")
	}
}
