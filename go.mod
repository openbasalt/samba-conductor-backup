module github.com/samba-conductor/conductor-backup

go 1.27.0

// The ad library is local only until the family's GitHub home is decided
// (planning/docs/decisions.md); the family go.work resolves it too.
replace github.com/samba-conductor/ad => ../ad

require (
	filippo.io/age v1.3.2
	github.com/BurntSushi/toml v1.6.0
	github.com/go-ldap/ldap/v3 v3.4.14
	github.com/samba-conductor/ad v0.0.0
)

require (
	filippo.io/hpke v0.4.0 // indirect
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/go-crypt/x v0.4.12 // indirect
	github.com/go-krb5/krb5 v0.1.0 // indirect
	github.com/go-krb5/x v0.3.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
