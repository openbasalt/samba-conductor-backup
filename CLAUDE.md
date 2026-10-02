# conductor-backup — Guidelines

Encrypted (age) Samba domain backups to S3-compatible storage, restore tooling and scheduled restore drills.

- Read `../CLAUDE.md` (family rules) and `../planning/docs/architecture.md`.
- Go: `go test ./...`, `go vet ./...`, gofmt, govulncheck. Code comments and docs in English.
- Commit with explicit paths (never `git add -A`).
