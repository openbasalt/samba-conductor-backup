package restore

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"syscall"
)

// owner of a copied file (root writes files for another user).
type owner struct{ uid, gid int }

// openDirRoot opens dir as an os.Root after checking that dir itself is a
// directory and not a symbolic link.
func openDirRoot(dir string) (*os.Root, error) {
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory (a symbolic link?)", dir)
	}
	return os.OpenRoot(dir)
}

// copyInto copies the regular file src to rel inside root, as root may do
// in a tree that came out of a backup (restored Samba files) or that
// another user owns (conductor's state):
//
//   - src is opened with O_NOFOLLOW and must be a regular file;
//   - every directory on the way is created inside an os.Root (no path can
//     leave root) and must be a real directory, not a symbolic link;
//   - the data goes to a new file (O_CREAT|O_EXCL|O_NOFOLLOW), gets its
//     owner and mode through the descriptor, and is renamed over rel, so
//     a link or file planted at rel is replaced, never written through.
func copyInto(src, root, rel string, mode os.FileMode, own *owner) error {
	rel = path.Clean(strings.TrimPrefix(rel, "/"))
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return fmt.Errorf("invalid destination %q", rel)
	}
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	if st, err := in.Stat(); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	r, err := openDirRoot(root)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	if dir := path.Dir(rel); dir != "." {
		if err := r.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		parts := strings.Split(dir, "/")
		for i := range parts {
			p := strings.Join(parts[:i+1], "/")
			st, err := r.Lstat(p)
			if err != nil {
				return err
			}
			if !st.IsDir() {
				return fmt.Errorf("%s/%s is not a directory (a symbolic link?)", root, p)
			}
		}
	}
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	tmp := path.Join(path.Dir(rel), "."+path.Base(rel)+".restore-"+hex.EncodeToString(rnd[:]))
	out, err := r.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		_ = out.Close()
		_ = r.Remove(tmp)
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		return fail(err)
	}
	if own != nil {
		if err := out.Chown(own.uid, own.gid); err != nil {
			return fail(err)
		}
	}
	if err := out.Chmod(mode); err != nil {
		return fail(err)
	}
	if err := out.Sync(); err != nil {
		return fail(err)
	}
	if err := out.Close(); err != nil {
		_ = r.Remove(tmp)
		return err
	}
	if st, err := r.Lstat(rel); err == nil && st.IsDir() {
		_ = r.Remove(tmp)
		return errors.New(root + "/" + rel + " is a directory")
	}
	if err := r.Rename(tmp, rel); err != nil {
		_ = r.Remove(tmp)
		return err
	}
	return nil
}
