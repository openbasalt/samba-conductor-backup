// Package sign holds conductor-backup's Ed25519 signing keys and the signed
// envelope used for every object it writes next to a backup (manifests,
// drill requests, drill reports).
//
// Why signatures: age encryption is not sender-authenticated (anyone with
// a recipient's public key can produce a valid ciphertext), and anyone who
// can write to the bucket could replace an archive together with a
// manifest carrying its new hash. A manifest signed with a key that lives
// only on the DC (and a drill report signed with the drill host's key)
// cannot be forged from the bucket alone.
//
// Envelope: {"payload": base64(JSON), "key_id": "…", "signature":
// base64(ed25519(payload bytes))}. The signature covers the exact payload
// bytes, so no canonical re-encoding is involved.
package sign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Text forms of the keys.
const (
	privatePrefix = "cbsigkey1:"
	publicPrefix  = "cbsig1:"
)

// PrivateKey is a signing key.
type PrivateKey struct{ k ed25519.PrivateKey }

// PublicKey verifies signatures.
type PublicKey struct{ k ed25519.PublicKey }

// Generate creates a new signing key.
func Generate() (PrivateKey, error) {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return PrivateKey{}, err
	}
	return PrivateKey{k: k}, nil
}

// String encodes the private key ("cbsigkey1:<base64 seed>").
func (p PrivateKey) String() string {
	return privatePrefix + base64.RawURLEncoding.EncodeToString(p.k.Seed())
}

// Public returns the public half.
func (p PrivateKey) Public() PublicKey { return PublicKey{k: p.k.Public().(ed25519.PublicKey)} }

// ParsePrivate decodes a private key (surrounding white space ignored).
func ParsePrivate(s string) (PrivateKey, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, privatePrefix) {
		return PrivateKey{}, errors.New("sign: not a conductor-backup signing key")
	}
	seed, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, privatePrefix))
	if err != nil || len(seed) != ed25519.SeedSize {
		return PrivateKey{}, errors.New("sign: malformed signing key")
	}
	return PrivateKey{k: ed25519.NewKeyFromSeed(seed)}, nil
}

// LoadPrivate reads a private key file. The file must not be readable by
// group or others.
func LoadPrivate(path string) (PrivateKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("sign: %w", err)
	}
	if st.Mode().Perm()&0o077 != 0 && !InCredentialsDir(path) {
		return PrivateKey{}, fmt.Errorf("sign: %s is accessible by group or others (mode %o)", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return PrivateKey{}, fmt.Errorf("sign: %w", err)
	}
	return ParsePrivate(string(b))
}

// InCredentialsDir reports whether path is inside $CREDENTIALS_DIRECTORY
// (systemd may present credentials with mode 0440 there; the directory
// itself is private to the service).
func InCredentialsDir(path string) bool {
	d := os.Getenv("CREDENTIALS_DIRECTORY")
	return d != "" && strings.HasPrefix(path, strings.TrimSuffix(d, "/")+"/")
}

// String encodes the public key ("cbsig1:<base64>").
func (p PublicKey) String() string { return publicPrefix + base64.RawURLEncoding.EncodeToString(p.k) }

// ID is a short identifier of the key: the first 16 hex digits of the
// SHA-256 of the public key.
func (p PublicKey) ID() string {
	sum := sha256.Sum256(p.k)
	return hex.EncodeToString(sum[:8])
}

// ParsePublic decodes a public key.
func ParsePublic(s string) (PublicKey, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, publicPrefix) {
		return PublicKey{}, fmt.Errorf("sign: %q is not a conductor-backup public key", s)
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, publicPrefix))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return PublicKey{}, errors.New("sign: malformed public key")
	}
	return PublicKey{k: b}, nil
}

// Envelope is a signed JSON document.
type Envelope struct {
	Payload   string `json:"payload"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// MaxEnvelope bounds what Open reads.
const MaxEnvelope = 1 << 20

// Seal marshals v and signs it.
func Seal(key PrivateKey, v any) ([]byte, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key.k, payload)
	return json.MarshalIndent(Envelope{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		KeyID:     key.Public().ID(),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, "", "  ")
}

// ErrBadSignature is returned when no trusted key verifies an envelope.
var ErrBadSignature = errors.New("sign: signature not valid for any trusted key")

// Open verifies an envelope against the trusted keys and decodes its
// payload into v (unknown fields rejected). It returns the key that
// signed it.
func Open(data []byte, trusted []PublicKey, v any) (PublicKey, error) {
	if len(data) > MaxEnvelope {
		return PublicKey{}, errors.New("sign: envelope too large")
	}
	var env Envelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return PublicKey{}, fmt.Errorf("sign: envelope: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return PublicKey{}, errors.New("sign: envelope payload is not base64")
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return PublicKey{}, ErrBadSignature
	}
	for _, k := range trusted {
		if k.ID() == env.KeyID && ed25519.Verify(k.k, payload, sig) {
			pd := json.NewDecoder(bytes.NewReader(payload))
			pd.DisallowUnknownFields()
			if err := pd.Decode(v); err != nil {
				return k, fmt.Errorf("sign: payload: %w", err)
			}
			return k, nil
		}
	}
	return PublicKey{}, ErrBadSignature
}
