package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExamplesLoad(t *testing.T) {
	for _, f := range []string{"../../conductor-backup.toml.example", "../../drill.toml.example"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		// The drill example carries a placeholder key.
		text := strings.Replace(string(b), "cbsig1:REPLACE-WITH-THE-DC-PUBLIC-KEY", "cbsig1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 1)
		p := filepath.Join(t.TempDir(), "c.toml")
		_ = os.WriteFile(p, []byte(text), 0o600)
		c, err := Load(p)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if c.Realm != "EXAMPLE.COM" || len(c.Destinations) != 1 || *c.VerifyAfterUpload != true {
			t.Fatalf("%s: %+v", f, c)
		}
	}
}

func TestValidation(t *testing.T) {
	bad := map[string]string{
		"unknown key":    "realm = \"EXAMPLE.COM\"\ntypo = 1\n",
		"realm":          "realm = \"example\"\n",
		"plain smtp":     "realm = \"EXAMPLE.COM\"\n[alert]\nemail_to=[\"a@b.c\"]\nemail_from=\"x@b.c\"\nsmtp_server=\"mail.b.c:25\"\nsmtp_security=\"none\"\n",
		"header inject":  "realm = \"EXAMPLE.COM\"\n[alert]\nemail_to=[\"a@b.c\\r\\nBcc: x@y\"]\nemail_from=\"x@b.c\"\nsmtp_server=\"mail.b.c:25\"\n",
		"http webhook":   "realm = \"EXAMPLE.COM\"\n[alert]\nwebhook_url=\"http://hooks.example.com/x\"\n",
		"s3 no creds":    "realm = \"EXAMPLE.COM\"\n[[destination]]\nname=\"s3\"\ntype=\"s3\"\nendpoint=\"https://s\"\nbucket=\"b\"\n",
		"bad prefix":     "realm = \"EXAMPLE.COM\"\n[[destination]]\nname=\"s3\"\ntype=\"s3\"\nendpoint=\"https://s\"\nbucket=\"b\"\ncredentials=\"s3\"\nprefix=\"../x\"\n",
		"lock w/o mode":  "realm = \"EXAMPLE.COM\"\n[[destination]]\nname=\"l\"\ntype=\"local\"\npath=\"/x\"\nobject_lock_days=3\n",
		"duplicate dest": "realm = \"EXAMPLE.COM\"\n[[destination]]\nname=\"l\"\ntype=\"local\"\npath=\"/x\"\n[[destination]]\nname=\"l\"\ntype=\"local\"\npath=\"/y\"\n",
		"relative path":  "realm = \"EXAMPLE.COM\"\nstate_dir = \"var/lib\"\n",
		"bad public key": "realm = \"EXAMPLE.COM\"\ndrill_public_keys = [\"age1xyz\"]\n",
	}
	for name, text := range bad {
		p := filepath.Join(t.TempDir(), "c.toml")
		_ = os.WriteFile(p, []byte(text), 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCredentials(t *testing.T) {
	dir := t.TempDir()
	c := &Config{CredentialsDir: dir}
	_ = os.WriteFile(filepath.Join(dir, "s3"), []byte("access_key_id = \"a\"\nsecret_access_key = \"b\"\n"), 0o600)
	var k S3Keys
	if err := c.DecodeCredential("s3", &k); err != nil || k.SecretAccessKey != "b" {
		t.Fatalf("%v %+v", err, k)
	}
	_ = os.WriteFile(filepath.Join(dir, "open"), []byte("x"), 0o644)
	if _, err := c.Credential("open"); err == nil {
		t.Fatal("world-readable credential accepted")
	}
	if _, err := c.Credential("../etc/passwd"); err == nil {
		t.Fatal("path in a credential name accepted")
	}
	// systemd's directory wins (files there may be 0440).
	sd := t.TempDir()
	_ = os.WriteFile(filepath.Join(sd, "open"), []byte("x"), 0o440)
	t.Setenv("CREDENTIALS_DIRECTORY", sd)
	if p, err := c.Credential("open"); err != nil || filepath.Dir(p) != sd {
		t.Fatalf("credentials directory: %q %v", p, err)
	}
}
