# conductor-backup: guidelines

Encrypted (age) Samba domain backups to S3-compatible storage, restore tooling and scheduled restore drills.

- Read `../CLAUDE.md` (family rules) and [architecture.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/architecture.md).
- Go: `go test ./...`, `go vet ./...`, gofmt, govulncheck. Code comments and docs in English.
- Commit with explicit paths (never `git add -A`).
