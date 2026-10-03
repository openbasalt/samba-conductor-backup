// Package alert sends conductor-backup's alerts: e-mail (SMTP with
// STARTTLS or implicit TLS; plain SMTP only to a loopback relay) and an
// optional JSON webhook. Messages carry no secret and no backup content.
package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/samba-conductor/conductor-backup/internal/config"
)

// Message is one alert.
type Message struct {
	Kind    string    `json:"kind"`
	Realm   string    `json:"realm"`
	Host    string    `json:"host"`
	Subject string    `json:"subject"`
	Text    string    `json:"text"`
	At      time.Time `json:"at"`
}

// Sender delivers alerts.
type Sender struct {
	cfg  *config.Config
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// New builds a sender for the configuration's [alert] section.
func New(cfg *config.Config) *Sender {
	d := &net.Dialer{Timeout: 20 * time.Second}
	return &Sender{cfg: cfg, dial: d.DialContext}
}

// Enabled reports whether any channel is configured.
func (s *Sender) Enabled() bool {
	return len(s.cfg.Alert.EmailTo) > 0 || s.cfg.Alert.WebhookURL != ""
}

// Send delivers m on every configured channel; errors are joined.
func (s *Sender) Send(ctx context.Context, m Message) error {
	var errs []error
	if len(s.cfg.Alert.EmailTo) > 0 {
		if err := s.email(ctx, m); err != nil {
			errs = append(errs, fmt.Errorf("alert e-mail: %w", err))
		}
	}
	if s.cfg.Alert.WebhookURL != "" {
		if err := s.webhook(ctx, m); err != nil {
			errs = append(errs, fmt.Errorf("alert webhook: %w", err))
		}
	}
	return errors.Join(errs...)
}

// clean removes line breaks from header values.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, s)
}

// Compose renders the RFC 5322 message.
func Compose(from string, to []string, m Message) []byte {
	var b bytes.Buffer
	id := make([]byte, 12)
	_, _ = rand.Read(id)
	domain := "localhost"
	if i := strings.LastIndex(from, "@"); i >= 0 {
		domain = from[i+1:]
	}
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\n",
		clean(from), clean(strings.Join(to, ", ")), clean(m.Subject), m.At.UTC().Format(time.RFC1123Z), hex.EncodeToString(id), clean(domain))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n")
	fmt.Fprintf(&b, "X-Conductor-Backup-Alert: %s\r\n\r\n", clean(m.Kind))
	// net/smtp's data writer does the dot-stuffing.
	for _, line := range strings.Split(m.Text, "\n") {
		b.WriteString(strings.TrimRight(line, "\r") + "\r\n")
	}
	return b.Bytes()
}

func (s *Sender) email(ctx context.Context, m Message) error {
	a := s.cfg.Alert
	host, _, err := net.SplitHostPort(a.SMTPServer)
	if err != nil {
		return err
	}
	var pool *x509.CertPool
	if pool, err = config.CertPool(a.SMTPCAFile); err != nil {
		return err
	}
	tlsCfg := &tls.Config{ServerName: host, RootCAs: pool, MinVersion: tls.VersionTLS12}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	conn, err := s.dial(ctx, "tcp", a.SMTPServer)
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if a.SMTPSecurity == "tls" {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return err
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = c.Close() }()
	if err := c.Hello(helloName(s.cfg)); err != nil {
		return err
	}
	if a.SMTPSecurity == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("server does not offer STARTTLS")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if a.SMTPCredentials != "" {
		var up config.UserPassword
		if err := s.cfg.DecodeCredential(a.SMTPCredentials, &up); err != nil {
			return err
		}
		// PLAIN only over TLS (net/smtp refuses it otherwise, except to
		// localhost).
		if err := c.Auth(smtp.PlainAuth("", up.Username, up.Password, host)); err != nil {
			return err
		}
	}
	if err := c.Mail(a.EmailFrom); err != nil {
		return err
	}
	for _, to := range a.EmailTo {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(Compose(a.EmailFrom, a.EmailTo, m)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func helloName(cfg *config.Config) string {
	if cfg.DC != "" {
		return cfg.DC
	}
	return "localhost"
}

func (s *Sender) webhook(ctx context.Context, m Message) error {
	a := s.cfg.Alert
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	pool, err := config.CertPool(a.WebhookCAFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.WebhookSecret != "" {
		secret, err := s.cfg.ReadCredential(a.WebhookSecret)
		if err != nil {
			return err
		}
		mac := hmac.New(sha256.New, bytes.TrimSpace(secret))
		mac.Write(body)
		req.Header.Set("X-Conductor-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
