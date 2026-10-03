package alert

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-backup/internal/config"
)

// fakeSMTP accepts one message without TLS (loopback) and records it.
func fakeSMTP(t *testing.T) (string, func() string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var data strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		r := bufio.NewReader(c)
		w := func(s string) { _, _ = io.WriteString(c, s+"\r\n") }
		w("220 fake ESMTP")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					w("250 queued")
					continue
				}
				mu.Lock()
				data.WriteString(line)
				mu.Unlock()
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"):
				w("250-fake")
				w("250 8BITMIME")
			case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
				w("250 ok")
			case cmd == "DATA":
				inData = true
				w("354 go")
			case cmd == "QUIT":
				w("221 bye")
				return
			default:
				w("502 no")
			}
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), func() string {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		mu.Lock()
		defer mu.Unlock()
		return data.String()
	}
}

func TestEmailAndWebhook(t *testing.T) {
	addr, got := fakeSMTP(t)
	creds := t.TempDir()
	if err := os.WriteFile(filepath.Join(creds, "hook"), []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var hookBody []byte
	var hookSig string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hookBody, _ = io.ReadAll(r.Body)
		hookSig = r.Header.Get("X-Conductor-Signature")
	}))
	defer hook.Close()
	cfg := &config.Config{Realm: "LAB.TEST", DC: "dc1", CredentialsDir: creds, Alert: config.Alert{
		EmailTo: []string{"ops@lab.test"}, EmailFrom: "backup@lab.test", SMTPServer: addr, SMTPSecurity: "none",
		WebhookURL: hook.URL, WebhookSecret: "hook"}}
	s := New(cfg)
	m := Message{Kind: "failed", Realm: "LAB.TEST", Host: "dc1", Subject: "backup failed\r\nBcc: x@evil", Text: "line 1\n.dot line", At: time.Now()}
	if err := s.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	mail := got()
	if !strings.Contains(mail, "Subject: backup failed  Bcc: x@evil\r\n") || strings.Contains(mail, "\r\nBcc:") {
		t.Fatalf("header injection not neutralized:\n%s", mail)
	}
	if !strings.Contains(mail, "\r\n..dot line\r\n") {
		t.Fatalf("dot stuffing:\n%s", mail)
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(hookBody)
	if hookSig != "sha256="+hex.EncodeToString(mac.Sum(nil)) || !strings.Contains(string(hookBody), `"kind":"failed"`) {
		t.Fatalf("webhook %s %s", hookSig, hookBody)
	}
}

func TestStartTLSRequired(t *testing.T) {
	addr, _ := fakeSMTP(t)
	cfg := &config.Config{DC: "dc1", Alert: config.Alert{EmailTo: []string{"ops@lab.test"}, EmailFrom: "b@lab.test",
		SMTPServer: addr, SMTPSecurity: "starttls"}}
	err := New(cfg).Send(context.Background(), Message{Subject: "x", At: time.Now()})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("plain server accepted with starttls: %v", err)
	}
}
