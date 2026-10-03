package dest

import (
	"crypto/md5" //nolint:gosec // Content-MD5 for S3 (transport check); integrity relies on SHA-256
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
)

// Digests returns the SHA-256 (hex) and MD5 (base64, for Content-MD5) of b.
func Digests(b []byte) (string, string) {
	s := sha256.Sum256(b)
	m := md5.Sum(b)
	return hex.EncodeToString(s[:]), base64.StdEncoding.EncodeToString(m[:])
}

// FileDigests reads a file once and returns its size, SHA-256 and MD5.
func FileDigests(path string) (int64, string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", "", err
	}
	defer func() { _ = f.Close() }()
	return ReaderDigests(f)
}

// ReaderDigests hashes a stream.
func ReaderDigests(r io.Reader) (int64, string, string, error) {
	s, m := sha256.New(), md5.New()
	n, err := io.Copy(io.MultiWriter(s, m), r)
	if err != nil {
		return n, "", "", err
	}
	return n, hex.EncodeToString(s.Sum(nil)), base64.StdEncoding.EncodeToString(m.Sum(nil)), nil
}
