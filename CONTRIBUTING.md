# Contributing to conductor-backup (encrypted backups and restore drills)

Thank you for helping. This repository is one of the Samba Conductor
repositories; each one has its own issues, pull requests and releases:

| Repository | Component |
|---|---|
| [samba-conductor](https://github.com/openbasalt/samba-conductor) | conductor: web administration, self-service, conductor-helper |
| [samba-conductor-idp](https://github.com/openbasalt/samba-conductor-idp) | conductor-idp: OpenID Connect and SAML identity provider |
| [samba-conductor-sync](https://github.com/openbasalt/samba-conductor-sync) | conductor-sync: provisioning to Google Workspace |
| [samba-conductor-backup](https://github.com/openbasalt/samba-conductor-backup) | conductor-backup: encrypted backups and restore drills |
| [samba-conductor-files](https://github.com/openbasalt/samba-conductor-files) | conductor-files: agent on domain-member file servers |
| [samba-conductor-ad](https://github.com/openbasalt/samba-conductor-ad) | the `ad` Go library shared by the components |

Security problems: do not open an issue, follow [SECURITY.md](SECURITY.md).

## Before you start

- Bugs and small fixes: open a pull request directly, or an issue first if
  you are not sure it is a bug.
- New features, new dependencies or changes to a security rule (who may do
  what, what is previewed, audited or re-authenticated, what runs as root):
  open an issue first to agree on the design. Security comes first in this
  project: every directory operation runs with the signed-in user's own
  identity, root is limited to small typed helpers, and every change is
  previewed and audited. Contributions keep these properties.

## Development setup

You need Go (the version in `go.mod`; with `GOTOOLCHAIN=auto` the go command
fetches it), git, and for packaging changes Docker or Podman (lintian runs
in a Debian 13 container) and Python 3.

The components are separate Go modules that import each other by their
repository paths (for example `github.com/openbasalt/samba-conductor-ad`).
`go.mod` pins the sibling modules it uses (`samba-conductor-ad`) by version, so this repository builds and tests on its own:

```sh
git clone https://github.com/openbasalt/samba-conductor-backup.git
cd samba-conductor-backup
make check      # gofmt, go vet, staticcheck, govulncheck, go test -race
```

While the repositories are private, the go command needs to know they are
private and git needs credentials for GitHub:

```sh
go env -w GOPRIVATE='github.com/openbasalt/*'
gh auth setup-git     # or any git credential helper for github.com
```

To change several repositories together, clone them side by side and use a
Go workspace in the parent directory, so each build uses your local copies
instead of the pinned versions:

```sh
go work init ./samba-conductor-ad ./samba-conductor ./samba-conductor-idp \
  ./samba-conductor-sync ./samba-conductor-backup ./samba-conductor-files
```

The `Makefile` sets `GOWORK=off` by default, so `make check` always checks
the repository against its pinned versions (what CI and a release build
use); run `make check GOWORK=$PWD/../go.work` to check it against the
workspace. After a change in a sibling module is merged, update the pin here
in a separate pull request (the pin must name a commit that is on GitHub):

```sh
GOWORK=off go get github.com/openbasalt/samba-conductor-ad@<commit or tag>
GOWORK=off go mod tidy
```

## Pull requests

- Keep them focused; one topic per pull request.
- `make check` passes. Add or update tests with the change; changes to the
  web interface also need the end-to-end tests updated (conductor's `e2e/`).
- Packaging changes: `make package` and `make lintian` pass (lintian clean
  at warning level; an override needs a justification in the override file).
- Code comments, documentation and commit messages in English. User-facing
  text goes through the translation catalogs, never hard-coded.
- Do not commit secrets, real host names, addresses or customer data, not
  even in tests: use the lab names (`lab.conductor.test`) and documentation
  addresses (192.0.2.0/24, `example.com`).
- Commit messages: a short summary line prefixed with the area
  (`web: ...`, `helper: ...`), then what changed and why.

By submitting a contribution you agree that it is licensed under the
Apache License, Version 2.0, this repository's license (see [LICENSE](LICENSE)
and [NOTICE](NOTICE)), as section 5 of that license provides.

## Code of conduct

Be respectful and constructive. The OpenBasalt code of conduct applies to
every repository of the organization.
