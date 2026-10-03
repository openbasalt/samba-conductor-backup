package s3

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// AWS's published SigV4 examples for S3 ("Examples: Signature Calculations
// in AWS Signature Version 4", Authenticating Requests: Using the
// Authorization Header).
func TestSignatureAWSExamples(t *testing.T) {
	const ak, sk = "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	get, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	get.Header.Set("Range", "bytes=0-9")
	get.Header.Set("x-amz-content-sha256", emptySHA256)
	get.Header.Set("x-amz-date", "20130524T000000Z")
	got := signature(get, ak, sk, "us-east-1", "20130524", "20130524T000000Z", emptySHA256)
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if got != want {
		t.Fatalf("GET object:\n got %s\nwant %s", got, want)
	}

	list, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/", nil)
	list.URL.RawQuery = canonicalQuery(url.Values{"max-keys": {"2"}, "prefix": {"J"}})
	list.Header.Set("x-amz-content-sha256", emptySHA256)
	list.Header.Set("x-amz-date", "20130524T000000Z")
	got = signature(list, ak, sk, "us-east-1", "20130524", "20130524T000000Z", emptySHA256)
	if !strings.HasSuffix(got, "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7") {
		t.Fatalf("list: %s", got)
	}
}

func TestEscape(t *testing.T) {
	if got := escape("domain/lab.test/a b+c~_-.", true); got != "domain/lab.test/a%20b%2Bc~_-." {
		t.Fatalf("path escape %q", got)
	}
	if got := escape("a/b", false); got != "a%2Fb" {
		t.Fatalf("query escape %q", got)
	}
}

func TestConfigValidation(t *testing.T) {
	ok := Config{Endpoint: "https://s3.example.com", Bucket: "backups", AccessKey: "a", SecretKey: "b"}
	if _, err := New(ok); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]Config{
		"plain http remote": {Endpoint: "http://s3.example.com", Bucket: "backups", AccessKey: "a", SecretKey: "b"},
		"path in endpoint":  {Endpoint: "https://s3.example.com/x", Bucket: "backups", AccessKey: "a", SecretKey: "b"},
		"bucket":            {Endpoint: "https://s3.example.com", Bucket: "Bad_Bucket", AccessKey: "a", SecretKey: "b"},
		"no keys":           {Endpoint: "https://s3.example.com", Bucket: "backups"},
		"user info":         {Endpoint: "https://u:p@s3.example.com", Bucket: "backups", AccessKey: "a", SecretKey: "b"},
	} {
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// fakeS3 is a path-style bucket that checks every request's signature and
// the payload hash of PUTs.
type fakeS3 struct {
	mu       sync.Mutex
	objects  map[string][]byte
	failPuts int // answer this many PUTs with 500 first
	puts     int
	lockHdr  string
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	date := r.Header.Get("x-amz-date")
	clone := r.Clone(context.Background())
	clone.Header.Del("Authorization")
	clone.URL.Host = r.Host
	if want := signature(clone, "AK", "SK", "us-east-1", date[:8], date, r.Header.Get("x-amz-content-sha256")); want != auth {
		http.Error(w, "<Error><Code>SignatureDoesNotMatch</Code><Message>bad</Message></Error>", http.StatusForbidden)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.TrimPrefix(r.URL.Path, "/bucket/")
	switch r.Method {
	case http.MethodPut:
		f.puts++
		body, _ := io.ReadAll(r.Body)
		if f.failPuts > 0 {
			f.failPuts--
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != r.Header.Get("x-amz-content-sha256") {
			http.Error(w, "<Error><Code>XAmzContentSHA256Mismatch</Code><Message>x</Message></Error>", http.StatusBadRequest)
			return
		}
		f.lockHdr = r.Header.Get("x-amz-object-lock-mode")
		f.objects[key] = body
	case http.MethodGet:
		if r.URL.Query().Get("list-type") == "2" {
			prefix := r.URL.Query().Get("prefix")
			var keys []string
			for k := range f.objects {
				if strings.HasPrefix(k, prefix) {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			// Page by one to exercise continuation tokens.
			start := 0
			if tok := r.URL.Query().Get("continuation-token"); tok != "" {
				_, _ = fmt.Sscanf(tok, "%d", &start)
			}
			fmt.Fprint(w, "<ListBucketResult>")
			if start < len(keys) {
				k := keys[start]
				fmt.Fprintf(w, "<Contents><Key>%s</Key><Size>%d</Size><LastModified>2026-10-03T01:02:03.000Z</LastModified><ETag>\"x\"</ETag></Contents>", k, len(f.objects[k]))
			}
			if start+1 < len(keys) {
				fmt.Fprintf(w, "<IsTruncated>true</IsTruncated><NextContinuationToken>%d</NextContinuationToken>", start+1)
			}
			fmt.Fprint(w, "</ListBucketResult>")
			return
		}
		b, ok := f.objects[key]
		if !ok {
			http.Error(w, "<Error><Code>NoSuchKey</Code><Message>none</Message></Error>", http.StatusNotFound)
			return
		}
		_, _ = w.Write(b)
	case http.MethodHead:
		b, ok := f.objects[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
	case http.MethodDelete:
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)
	}
}

func digests(b []byte) (string, string) {
	s := sha256.Sum256(b)
	m := md5.Sum(b)
	return hex.EncodeToString(s[:]), base64.StdEncoding.EncodeToString(m[:])
}

func TestClientAgainstFake(t *testing.T) {
	fake := &fakeS3{objects: map[string][]byte{}, failPuts: 1}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c, err := New(Config{Endpoint: srv.URL, Bucket: "bucket", PathStyle: true, AccessKey: "AK", SecretKey: "SK"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	body := []byte("ciphertext")
	sum, md := digests(body)
	open := func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	lock := &Lock{Mode: "GOVERNANCE", Until: time.Now().Add(24 * time.Hour)}
	if err := c.Put(ctx, "domain/lab.test/20261003T011350Z-dc1.tar.age", open, int64(len(body)), sum, md, lock); err != nil {
		t.Fatal(err)
	}
	if fake.puts != 2 || fake.lockHdr != "GOVERNANCE" {
		t.Fatalf("puts %d (one retry expected), lock %q", fake.puts, fake.lockHdr)
	}
	// A body that does not match its declared hash is refused by the server.
	badSum, _ := digests([]byte("other"))
	if err := c.Put(ctx, "x", open, int64(len(body)), badSum, md, nil); err == nil || !strings.Contains(err.Error(), "XAmzContentSHA256Mismatch") {
		t.Fatalf("mismatch: %v", err)
	}
	for _, k := range []string{"domain/lab.test/a.json", "domain/lab.test/b.json", "drills/x.json"} {
		s, m := digests([]byte(k))
		if err := c.Put(ctx, k, func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(k)), nil }, int64(len(k)), s, m, nil); err != nil {
			t.Fatal(err)
		}
	}
	objs, err := c.List(ctx, "domain/")
	if err != nil || len(objs) != 3 {
		t.Fatalf("list: %+v %v", objs, err)
	}
	rc, n, err := c.Get(ctx, "domain/lab.test/20261003T011350Z-dc1.tar.age")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(got) != "ciphertext" || n != int64(len(body)) {
		t.Fatalf("get %q %d", got, n)
	}
	if o, err := c.Head(ctx, "domain/lab.test/a.json"); err != nil || o.Size != int64(len("domain/lab.test/a.json")) {
		t.Fatalf("head %+v %v", o, err)
	}
	if _, err := c.Head(ctx, "missing"); !IsNotFound(err) {
		t.Fatalf("head missing: %v", err)
	}
	if _, _, err := c.Get(ctx, "missing"); !IsNotFound(err) {
		t.Fatalf("get missing: %v", err)
	}
	if err := c.Delete(ctx, "domain/lab.test/a.json"); err != nil {
		t.Fatal(err)
	}
	if objs, _ := c.List(ctx, "domain/"); len(objs) != 2 {
		t.Fatalf("after delete %d", len(objs))
	}
	// Wrong secret: the server refuses the signature.
	bad, _ := New(Config{Endpoint: srv.URL, Bucket: "bucket", PathStyle: true, AccessKey: "AK", SecretKey: "nope"})
	if _, err := bad.List(ctx, ""); err == nil || !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
		t.Fatalf("bad secret: %v", err)
	}
}
