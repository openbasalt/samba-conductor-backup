// Package config loads conductor-backup's configuration
// (/etc/conductor-backup/conductor-backup.toml). The file holds no secret:
// keys and passwords are credentials, read from systemd's
// $CREDENTIALS_DIRECTORY (LoadCredential=) or, for an operator running the
// CLI as root, from credentials_dir (root-only). Unknown keys are an error.
//
// One file format serves both roles:
//   - on a domain controller: realm, dc, state_dir, helper_socket,
//     signing_key, destinations, alert (the `run` side);
//   - on a drill host: realm, destinations (read access), the [drill]
//     section and alert.
package config

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/openbasalt/samba-conductor-ad/helper"
	"github.com/openbasalt/samba-conductor-backup/internal/sign"
)

// DefaultPath is where the configuration lives.
const DefaultPath = "/etc/conductor-backup/conductor-backup.toml"

// Config is the whole file.
type Config struct {
	// Realm of the domain, e.g. "EXAMPLE.COM".
	Realm string `toml:"realm"`
	// DC is this domain controller's short name (object names); default:
	// the host name up to the first dot.
	DC string `toml:"dc"`
	// StateDir holds state.json, policy.json, requests/ and spool/.
	StateDir string `toml:"state_dir"`
	// HelperSocket is conductor-helper's socket.
	HelperSocket string `toml:"helper_socket"`
	// CredentialsDir is where credentials are read when the process does
	// not run under systemd with LoadCredential (CLI as root).
	CredentialsDir string `toml:"credentials_dir"`
	// SigningKey is the credential holding this DC's signing key
	// (manifests, drill requests).
	SigningKey string `toml:"signing_key"`
	// BackupPublicKeys verify manifests and drill requests (restore,
	// verify, drill). On the DC the signing key's own public half is
	// always trusted.
	BackupPublicKeys []string `toml:"backup_public_keys"`
	// DrillPublicKeys verify drill reports.
	DrillPublicKeys []string `toml:"drill_public_keys"`
	// RecipientsFile lists the age recipients (public keys). The helper
	// encrypts to it; conductor-backup only reports the fingerprints.
	RecipientsFile string `toml:"recipients_file"`
	// VerifyAfterUpload downloads every uploaded archive again and checks
	// its SHA-256 (default true).
	VerifyAfterUpload *bool `toml:"verify_after_upload"`

	Destinations []Destination `toml:"destination"`
	Alert        Alert         `toml:"alert"`
	Drill        Drill         `toml:"drill"`
}

// Destination is a place backups are copied to.
type Destination struct {
	Name string `toml:"name"`
	// Type: "local" (a directory) or "s3" (S3-compatible object storage).
	Type string `toml:"type"`
	// Path of a local destination.
	Path string `toml:"path"`
	// S3: endpoint ("https://host[:port]"), region, bucket, key prefix,
	// path-style addressing, CA file pinning the endpoint's certificate
	// (default: system CAs), credential name (a TOML file with
	// access_key_id and secret_access_key).
	Endpoint    string `toml:"endpoint"`
	Region      string `toml:"region"`
	Bucket      string `toml:"bucket"`
	Prefix      string `toml:"prefix"`
	PathStyle   bool   `toml:"path_style"`
	CAFile      string `toml:"ca_file"`
	Credentials string `toml:"credentials"`
	// ObjectLockMode ("GOVERNANCE" or "COMPLIANCE") and ObjectLockDays
	// set a retention on every archive (the bucket must support it).
	ObjectLockMode string `toml:"object_lock_mode"`
	ObjectLockDays int    `toml:"object_lock_days"`
}

// Alert is how failures are reported.
type Alert struct {
	EmailTo   []string `toml:"email_to"`
	EmailFrom string   `toml:"email_from"`
	// SMTPServer "host:port"; SMTPSecurity "starttls" (default), "tls"
	// (implicit, port 465) or "none" (loopback servers only).
	SMTPServer   string `toml:"smtp_server"`
	SMTPSecurity string `toml:"smtp_security"`
	SMTPCAFile   string `toml:"smtp_ca_file"`
	// SMTPCredentials: credential with "username" and "password" (TOML).
	SMTPCredentials string `toml:"smtp_credentials"`
	// WebhookURL receives a JSON POST (https, or http to loopback).
	WebhookURL    string `toml:"webhook_url"`
	WebhookCAFile string `toml:"webhook_ca_file"`
	// WebhookSecret: credential; when set, requests carry an
	// X-Conductor-Signature HMAC-SHA256 of the body.
	WebhookSecret string `toml:"webhook_secret"`
}

// Drill configures a drill host.
type Drill struct {
	// Identity: credential holding the drill's age identity (private key).
	Identity string `toml:"identity"`
	// SigningKey: credential with the drill host's signing key (reports).
	SigningKey string `toml:"signing_key"`
	// ProbeUser is a plain domain account (no privileges) used for the
	// Kerberos and LDAP checks; ProbePassword is its credential.
	ProbeUser     string `toml:"probe_user"`
	ProbePassword string `toml:"probe_password"`
	// WorkDir holds downloads and the throwaway restore (on disk: the
	// restore needs extended attributes for sysvol ACLs).
	WorkDir string `toml:"work_dir"`
	// ServerName is the NetBIOS name of the restored DC (default DRILL).
	ServerName string `toml:"server_name"`
	// Destination to read from (default: the first one).
	Destination string `toml:"destination"`
	// MaxBackupAgeHours: the drill host alerts when the newest backup in
	// the destination is older (an off-DC watchdog); 0 turns it off.
	MaxBackupAgeHours int `toml:"max_backup_age_hours"`
	// SambaBinary and SambaTool (absolute paths).
	SambaBinary string `toml:"samba_binary"`
	SambaTool   string `toml:"samba_tool"`
	// TimeoutMinutes bounds one drill (default 30).
	TimeoutMinutes int `toml:"timeout_minutes"`
}

// Load reads and validates a configuration file.
func Load(path string) (*Config, error) {
	c := &Config{}
	md, err := toml.DecodeFile(path, c)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("config: unknown keys: %s", strings.Join(keys, ", "))
	}
	c.defaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) defaults() {
	if c.DC == "" {
		if h, err := os.Hostname(); err == nil {
			c.DC = strings.ToLower(strings.SplitN(h, ".", 2)[0])
		}
	}
	if c.StateDir == "" {
		c.StateDir = "/var/lib/conductor-backup"
	}
	if c.HelperSocket == "" {
		c.HelperSocket = helper.DefaultBackupSocketPath
	}
	if c.CredentialsDir == "" {
		c.CredentialsDir = "/etc/conductor-backup/credentials"
	}
	if c.SigningKey == "" {
		c.SigningKey = "signing-key"
	}
	if c.RecipientsFile == "" {
		c.RecipientsFile = "/etc/conductor-backup/recipients.txt"
	}
	if c.VerifyAfterUpload == nil {
		t := true
		c.VerifyAfterUpload = &t
	}
	for i := range c.Destinations {
		if c.Destinations[i].Region == "" {
			c.Destinations[i].Region = "us-east-1"
		}
	}
	if c.Alert.SMTPSecurity == "" {
		c.Alert.SMTPSecurity = "starttls"
	}
	d := &c.Drill
	if d.WorkDir == "" {
		d.WorkDir = "/var/lib/conductor-backup-drill"
	}
	if d.ServerName == "" {
		d.ServerName = "DRILL"
	}
	if d.SambaBinary == "" {
		d.SambaBinary = "/usr/sbin/samba"
	}
	if d.SambaTool == "" {
		d.SambaTool = "/usr/bin/samba-tool"
	}
	if d.TimeoutMinutes <= 0 {
		d.TimeoutMinutes = 30
	}
	if d.Identity == "" {
		d.Identity = "drill-identity"
	}
	if d.SigningKey == "" {
		d.SigningKey = "drill-signing-key"
	}
	if d.ProbePassword == "" {
		d.ProbePassword = "drill-probe-password"
	}
}

var (
	realmRE  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)
	dcRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	nameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	credRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	prefixRE = regexp.MustCompile(`^([A-Za-z0-9._-]+/)*$`)
	userRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	netbios  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,14}$`)
)

// Validate checks the file.
func (c *Config) Validate() error {
	var errs []error
	add := func(f string, a ...any) { errs = append(errs, fmt.Errorf("config: "+f, a...)) }
	if !realmRE.MatchString(c.Realm) {
		add("realm %q is not a DNS domain", c.Realm)
	}
	if !dcRE.MatchString(c.DC) {
		add("dc %q must be a lower-case host name", c.DC)
	}
	for _, p := range []struct{ k, v string }{{"state_dir", c.StateDir}, {"helper_socket", c.HelperSocket},
		{"credentials_dir", c.CredentialsDir}, {"recipients_file", c.RecipientsFile}, {"drill.work_dir", c.Drill.WorkDir},
		{"drill.samba_binary", c.Drill.SambaBinary}, {"drill.samba_tool", c.Drill.SambaTool}} {
		if !filepath.IsAbs(p.v) || filepath.Clean(p.v) != p.v {
			add("%s must be a clean absolute path", p.k)
		}
	}
	for _, k := range []struct{ k, v string }{{"signing_key", c.SigningKey}, {"drill.identity", c.Drill.Identity},
		{"drill.signing_key", c.Drill.SigningKey}, {"drill.probe_password", c.Drill.ProbePassword}} {
		if !credRE.MatchString(k.v) {
			add("%s must be a credential name", k.k)
		}
	}
	for _, k := range append(append([]string(nil), c.BackupPublicKeys...), c.DrillPublicKeys...) {
		if _, err := sign.ParsePublic(k); err != nil {
			add("%v", err)
		}
	}
	seen := map[string]bool{}
	for i, d := range c.Destinations {
		if !nameRE.MatchString(d.Name) || seen[d.Name] {
			add("destination %d: name %q must be unique, [a-z0-9_-]", i+1, d.Name)
		}
		seen[d.Name] = true
		switch d.Type {
		case "local":
			if !filepath.IsAbs(d.Path) || filepath.Clean(d.Path) != d.Path {
				add("destination %s: path must be a clean absolute path", d.Name)
			}
		case "s3":
			if u, err := url.Parse(d.Endpoint); err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
				add("destination %s: endpoint must be https://host[:port]", d.Name)
			}
			if d.Bucket == "" || !credRE.MatchString(d.Credentials) {
				add("destination %s: bucket and credentials are required", d.Name)
			}
			if !prefixRE.MatchString(d.Prefix) {
				add("destination %s: prefix must be empty or end with '/' ([A-Za-z0-9._-] segments)", d.Name)
			}
			if d.CAFile != "" && !filepath.IsAbs(d.CAFile) {
				add("destination %s: ca_file must be absolute", d.Name)
			}
		default:
			add("destination %s: type must be local or s3", d.Name)
		}
		if d.ObjectLockDays < 0 || d.ObjectLockDays > 3650 || (d.ObjectLockDays > 0 && d.ObjectLockMode != "GOVERNANCE" && d.ObjectLockMode != "COMPLIANCE") ||
			(d.ObjectLockDays == 0 && d.ObjectLockMode != "") {
			add("destination %s: object_lock_mode GOVERNANCE|COMPLIANCE with object_lock_days 1-3650, or neither", d.Name)
		}
	}
	a := c.Alert
	if len(a.EmailTo) > 0 {
		if a.EmailFrom == "" || a.SMTPServer == "" {
			add("alert: email_from and smtp_server are required with email_to")
		}
		if host, _, err := net.SplitHostPort(a.SMTPServer); err != nil {
			add("alert: smtp_server must be host:port")
		} else if a.SMTPSecurity == "none" && !loopback(host) {
			add("alert: smtp_security none is only allowed for a loopback server")
		}
		if a.SMTPSecurity != "starttls" && a.SMTPSecurity != "tls" && a.SMTPSecurity != "none" {
			add("alert: smtp_security must be starttls, tls or none")
		}
		if a.SMTPCredentials != "" && !credRE.MatchString(a.SMTPCredentials) {
			add("alert: smtp_credentials must be a credential name")
		}
		for _, addr := range append([]string{a.EmailFrom}, a.EmailTo...) {
			if strings.ContainsAny(addr, "\r\n<>,; ") || !strings.Contains(addr, "@") {
				add("alert: invalid address %q", addr)
			}
		}
	}
	if a.WebhookURL != "" {
		u, err := url.Parse(a.WebhookURL)
		if err != nil || u.Host == "" || !(u.Scheme == "https" || u.Scheme == "http" && loopback(u.Hostname())) {
			add("alert: webhook_url must be https (http only to loopback)")
		}
		if a.WebhookSecret != "" && !credRE.MatchString(a.WebhookSecret) {
			add("alert: webhook_secret must be a credential name")
		}
	}
	d := c.Drill
	if d.ProbeUser != "" && !userRE.MatchString(d.ProbeUser) {
		add("drill: invalid probe_user")
	}
	if !netbios.MatchString(d.ServerName) {
		add("drill: server_name must be a NetBIOS name (1-15 characters)")
	}
	if d.Destination != "" && !seen[d.Destination] {
		add("drill: destination %q is not configured", d.Destination)
	}
	if d.MaxBackupAgeHours < 0 {
		add("drill: max_backup_age_hours must be >= 0")
	}
	return errors.Join(errs...)
}

func loopback(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Credential returns the path of a credential: $CREDENTIALS_DIRECTORY/name
// when it exists (systemd LoadCredential), else credentials_dir/name.
func (c *Config) Credential(name string) (string, error) {
	if !credRE.MatchString(name) {
		return "", fmt.Errorf("config: invalid credential name %q", name)
	}
	if d := os.Getenv("CREDENTIALS_DIRECTORY"); d != "" {
		p := filepath.Join(d, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	p := filepath.Join(c.CredentialsDir, name)
	st, err := os.Stat(p)
	if err != nil {
		return "", fmt.Errorf("config: credential %q not found (LoadCredential=%s:… or %s)", name, name, p)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("config: credential %s is accessible by group or others (mode %o)", p, st.Mode().Perm())
	}
	return p, nil
}

// ReadCredential returns a credential's content.
func (c *Config) ReadCredential(name string) ([]byte, error) {
	p, err := c.Credential(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("config: credential %q: %w", name, err)
	}
	return b, nil
}

// S3Keys are the contents of an S3 credential.
type S3Keys struct {
	AccessKeyID     string `toml:"access_key_id"`
	SecretAccessKey string `toml:"secret_access_key"`
}

// UserPassword is an SMTP credential.
type UserPassword struct {
	Username string `toml:"username"`
	Password string `toml:"password"`
}

// DecodeCredential reads a TOML credential strictly into v.
func (c *Config) DecodeCredential(name string, v any) error {
	b, err := c.ReadCredential(name)
	if err != nil {
		return err
	}
	md, err := toml.Decode(string(b), v)
	if err != nil {
		return fmt.Errorf("config: credential %q is not valid TOML", name)
	}
	if len(md.Undecoded()) > 0 {
		return fmt.Errorf("config: credential %q has unknown keys", name)
	}
	return nil
}

// SigningKey loads this host's signing key (DC or drill host).
func (c *Config) LoadSigningKey(name string) (sign.PrivateKey, error) {
	p, err := c.Credential(name)
	if err != nil {
		return sign.PrivateKey{}, err
	}
	return sign.LoadPrivate(p)
}

// PublicKeys parses a list of public keys.
func PublicKeys(list []string) ([]sign.PublicKey, error) {
	out := make([]sign.PublicKey, 0, len(list))
	for _, s := range list {
		k, err := sign.ParsePublic(s)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// CertPool reads a PEM CA file ("" = nil, the system pool).
func CertPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("config: no certificate in %s", path)
	}
	return pool, nil
}

// Destination returns a destination by name.
func (c *Config) Destination(name string) (Destination, bool) {
	for _, d := range c.Destinations {
		if d.Name == name {
			return d, true
		}
	}
	return Destination{}, false
}
