// Package s3 is a small client for S3-compatible object storage (AWS S3,
// MinIO, OCI Object Storage's S3 API, …): PUT, GET, HEAD, DELETE and
// ListObjectsV2 with AWS Signature Version 4. It exists instead of a full
// SDK to keep conductor-backup's dependency tree small; it does only what
// backups need.
//
// Integrity: every PUT signs the SHA-256 of the body
// (x-amz-content-sha256) and sends Content-MD5, so the server refuses a
// body that does not match what was hashed locally. Objects up to 5 GiB
// (a single PUT; no multipart).
package s3

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MaxObjectSize is the largest object a single PUT may carry.
const MaxObjectSize = 5 << 30

// emptySHA256 is the SHA-256 of an empty body.
const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// Config describes a bucket.
type Config struct {
	// Endpoint is "https://host[:port]" (http only for loopback hosts).
	Endpoint  string
	Region    string
	Bucket    string
	PathStyle bool
	AccessKey string
	SecretKey string
	// RootCAs pins the CA of the endpoint; nil means the system pool.
	RootCAs *x509.CertPool
	// Timeout per request (default 10 minutes, generous for large
	// uploads); dialing has its own 15 s limit.
	Timeout time.Duration
}

// Client talks to one bucket.
type Client struct {
	cfg  Config
	base *url.URL
	http *http.Client
	now  func() time.Time
}

var bucketRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// New validates the configuration and builds a client.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.User != nil {
		return nil, fmt.Errorf("s3: invalid endpoint %q", cfg.Endpoint)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, errors.New("s3: plain http is only allowed to a loopback endpoint")
		}
	default:
		return nil, fmt.Errorf("s3: invalid endpoint scheme %q", u.Scheme)
	}
	if !bucketRE.MatchString(cfg.Bucket) {
		return nil, fmt.Errorf("s3: invalid bucket name %q", cfg.Bucket)
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, errors.New("s3: access key and secret key are required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Minute
	}
	u.Path = ""
	tr := &http.Transport{
		Proxy:                 nil, // never through an environment proxy
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		MaxIdleConns:          4,
		IdleConnTimeout:       60 * time.Second,
	}
	return &Client{cfg: cfg, base: u, http: &http.Client{Transport: tr, Timeout: cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		now: time.Now}, nil
}

func isLoopback(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Error is an S3 error response.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("s3: HTTP %d", e.Status)
	}
	return fmt.Sprintf("s3: %s (HTTP %d): %s", e.Code, e.Status, e.Message)
}

// IsNotFound reports a missing object or bucket.
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && (e.Status == http.StatusNotFound)
}

// Object is one listed or inspected object.
type Object struct {
	Key          string
	Size         int64
	LastModified time.Time
	ETag         string
}

// Lock asks for an object-lock retention on PUT (the bucket must have
// object lock enabled). Mode is "GOVERNANCE" or "COMPLIANCE".
type Lock struct {
	Mode  string
	Until time.Time
}

// Put uploads size bytes from open() (called again on a retry) under key.
// sha256Hex and md5Base64 are the body's digests, computed beforehand.
func (c *Client) Put(ctx context.Context, key string, open func() (io.ReadCloser, error), size int64, sha256Hex, md5Base64 string, lock *Lock) error {
	if size < 0 || size > MaxObjectSize {
		return fmt.Errorf("s3: object of %d bytes exceeds the single-PUT limit", size)
	}
	if len(sha256Hex) != 64 {
		return errors.New("s3: body SHA-256 required")
	}
	h := http.Header{}
	h.Set("Content-MD5", md5Base64)
	h.Set("Content-Type", "application/octet-stream")
	if lock != nil {
		if lock.Mode != "GOVERNANCE" && lock.Mode != "COMPLIANCE" {
			return fmt.Errorf("s3: invalid object lock mode %q", lock.Mode)
		}
		h.Set("x-amz-object-lock-mode", lock.Mode)
		h.Set("x-amz-object-lock-retain-until-date", lock.Until.UTC().Format(time.RFC3339))
	}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * 2 * time.Second):
			}
		}
		body, err := open()
		if err != nil {
			return err
		}
		resp, err := c.do(ctx, http.MethodPut, key, nil, h, body, size, sha256Hex)
		if err == nil {
			_ = resp.Body.Close()
			return nil
		}
		last = err
		if !retryable(err) {
			return err
		}
	}
	return last
}

// retryable: network errors and 5xx answers.
func retryable(err error) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Status >= 500
	}
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

// Get downloads an object; the caller closes the body.
func (c *Client) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	resp, err := c.do(ctx, http.MethodGet, key, nil, nil, nil, 0, emptySHA256)
	if err != nil {
		return nil, 0, err
	}
	return resp.Body, resp.ContentLength, nil
}

// Head returns an object's size and metadata.
func (c *Client) Head(ctx context.Context, key string) (Object, error) {
	resp, err := c.do(ctx, http.MethodHead, key, nil, nil, nil, 0, emptySHA256)
	if err != nil {
		return Object{}, err
	}
	_ = resp.Body.Close()
	o := Object{Key: key, Size: resp.ContentLength, ETag: strings.Trim(resp.Header.Get("ETag"), `"`)}
	o.LastModified, _ = http.ParseTime(resp.Header.Get("Last-Modified"))
	return o, nil
}

// Delete removes an object (a missing object is not an error).
func (c *Client) Delete(ctx context.Context, key string) error {
	resp, err := c.do(ctx, http.MethodDelete, key, nil, nil, nil, 0, emptySHA256)
	if err != nil {
		if IsNotFound(err) {
			return nil
		}
		return err
	}
	_ = resp.Body.Close()
	return nil
}

type listResult struct {
	Contents []struct {
		Key          string `xml:"Key"`
		Size         int64  `xml:"Size"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
	} `xml:"Contents"`
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
}

// List returns every object whose key starts with prefix (paged, at most
// 100,000 objects).
func (c *Client) List(ctx context.Context, prefix string) ([]Object, error) {
	var out []Object
	token := ""
	for page := 0; page < 100; page++ {
		q := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {"1000"}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := c.do(ctx, http.MethodGet, "", q, nil, nil, 0, emptySHA256)
		if err != nil {
			return nil, err
		}
		var lr listResult
		err = xml.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&lr)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("s3: list response: %w", err)
		}
		for _, o := range lr.Contents {
			t, _ := time.Parse(time.RFC3339Nano, o.LastModified)
			out = append(out, Object{Key: o.Key, Size: o.Size, LastModified: t, ETag: strings.Trim(o.ETag, `"`)})
		}
		if !lr.IsTruncated || lr.NextContinuationToken == "" {
			return out, nil
		}
		token = lr.NextContinuationToken
	}
	return nil, errors.New("s3: listing too large")
}

// do builds, signs and sends a request; non-2xx answers become *Error.
func (c *Client) do(ctx context.Context, method, key string, q url.Values, h http.Header, body io.ReadCloser, size int64, payloadHash string) (*http.Response, error) {
	u := *c.base
	host := u.Host
	p := "/"
	if c.cfg.PathStyle {
		p += c.cfg.Bucket + "/"
	} else {
		host = c.cfg.Bucket + "." + host
	}
	p += key
	u.Host = host
	u.Path = p
	u.RawPath = escapePath(p)
	if q != nil {
		u.RawQuery = canonicalQuery(q)
	}
	var rd io.Reader
	if body != nil {
		rd = body
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		if body != nil {
			_ = body.Close()
		}
		return nil, err
	}
	if body != nil {
		req.ContentLength = size
	}
	for k, v := range h {
		req.Header[k] = v
	}
	c.sign(req, payloadHash)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("s3: %s %s: %w", method, key, err)
	}
	if resp.StatusCode/100 != 2 {
		defer func() { _ = resp.Body.Close() }()
		e := &Error{Status: resp.StatusCode}
		if method != http.MethodHead {
			var x struct {
				Code    string `xml:"Code"`
				Message string `xml:"Message"`
			}
			if xml.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&x) == nil {
				e.Code, e.Message = x.Code, x.Message
			}
		}
		return nil, e
	}
	return resp, nil
}

// sign adds the SigV4 headers. Signed: host, every x-amz-* header and
// Content-MD5, Content-Type and Range when present.
func (c *Client) sign(req *http.Request, payloadHash string) {
	t := c.now().UTC()
	amzDate := t.Format("20060102T150405Z")
	date := t.Format("20060102")
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	auth := signature(req, c.cfg.AccessKey, c.cfg.SecretKey, c.cfg.Region, date, amzDate, payloadHash)
	req.Header.Set("Authorization", auth)
}

func signature(req *http.Request, accessKey, secretKey, region, date, amzDate, payloadHash string) string {
	headers := map[string]string{"host": req.URL.Host}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") || lk == "content-md5" || lk == "content-type" || lk == "range" {
			headers[lk] = strings.TrimSpace(strings.Join(v, ","))
		}
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n + ":" + headers[n] + "\n")
	}
	signed := strings.Join(names, ";")
	creq := strings.Join([]string{req.Method, req.URL.EscapedPath(), req.URL.RawQuery, ch.String(), signed, payloadHash}, "\n")
	scope := date + "/" + region + "/s3/aws4_request"
	sum := sha256.Sum256([]byte(creq))
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
	k := hmacSHA256([]byte("AWS4"+secretKey), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, "s3")
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, sts))
	return "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + sig
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// escape is S3's URI encoding: unreserved characters stay, everything else
// is %XX (upper case); keepSlash keeps "/" (object key paths).
func escape(s string, keepSlash bool) string {
	var b bytes.Buffer
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' || (keepSlash && c == '/') {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%" + strings.ToUpper(strconv.FormatInt(int64(c)|0x100, 16)[1:]))
	}
	return b.String()
}

func escapePath(p string) string { return escape(p, true) }

// canonicalQuery encodes and sorts query parameters as SigV4 requires; the
// same string is sent, so the signature matches.
func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, escape(k, false)+"="+escape(v, false))
		}
	}
	return strings.Join(parts, "&")
}
