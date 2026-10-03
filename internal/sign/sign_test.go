package sign

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type doc struct {
	ID   string `json:"id"`
	Size int64  `json:"size"`
}

func TestSealOpen(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := Generate()
	b, err := Seal(k, doc{ID: "a", Size: 42})
	if err != nil {
		t.Fatal(err)
	}
	var got doc
	signer, err := Open(b, []PublicKey{other.Public(), k.Public()}, &got)
	if err != nil || got.Size != 42 || signer.ID() != k.Public().ID() {
		t.Fatalf("open: %+v %v", got, err)
	}
	if _, err := Open(b, []PublicKey{other.Public()}, &got); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("untrusted key: %v", err)
	}
	// Tampered payload.
	var env Envelope
	_ = json.Unmarshal(b, &env)
	env.Payload = base64.StdEncoding.EncodeToString([]byte(`{"id":"a","size":43}`))
	tampered, _ := json.Marshal(env)
	if _, err := Open(tampered, []PublicKey{k.Public()}, &got); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered: %v", err)
	}
	// A signed payload with unknown fields is refused.
	b2, _ := Seal(k, map[string]any{"id": "a", "cmd": "x"})
	if _, err := Open(b2, []PublicKey{k.Public()}, &got); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestKeyText(t *testing.T) {
	k, _ := Generate()
	k2, err := ParsePrivate(" " + k.String() + "\n")
	if err != nil || k2.Public().String() != k.Public().String() {
		t.Fatalf("round trip: %v", err)
	}
	p, err := ParsePublic(k.Public().String())
	if err != nil || p.ID() != k.Public().ID() || len(p.ID()) != 16 {
		t.Fatalf("public: %v", err)
	}
	for _, bad := range []string{"", "cbsig1:xx", "age1abc", k.String()} {
		if _, err := ParsePublic(bad); err == nil {
			t.Errorf("public %q accepted", bad)
		}
	}
	if _, err := ParsePrivate(k.Public().String()); err == nil {
		t.Error("public key accepted as private")
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "k")
	if err := os.WriteFile(f, []byte(k.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivate(f); err == nil || !strings.Contains(err.Error(), "group or others") {
		t.Fatalf("world-readable key accepted: %v", err)
	}
	_ = os.Chmod(f, 0o600)
	if _, err := LoadPrivate(f); err != nil {
		t.Fatal(err)
	}
}
