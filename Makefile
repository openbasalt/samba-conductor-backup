# Quality gates and builds for conductor-backup.
# GOWORK=off by default: the module is checked on its own, against the
# versions go.mod pins (what CI and release builds use), not through a
# family go.work; `make check GOWORK=$PWD/../go.work` checks it against
# local copies of the sibling modules instead.
export GOWORK ?= off
GOBIN := $(shell go env GOPATH)/bin
STATICCHECK := $(GOBIN)/staticcheck
GOVULNCHECK := $(GOBIN)/govulncheck
VERSION ?= $(shell git describe --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test check fmt vet staticcheck vulncheck tools package lintian rpmlint

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/conductor-backup ./cmd/conductor-backup

test:
	go test -race ./...

check: fmt vet staticcheck vulncheck test

fmt:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...

staticcheck: tools
	$(STATICCHECK) ./...

vulncheck: tools
	$(GOVULNCHECK) ./...

tools:
	@test -x $(STATICCHECK) || go install honnef.co/go/tools/cmd/staticcheck@latest
	@test -x $(GOVULNCHECK) || go install golang.org/x/vuln/cmd/govulncheck@latest

# Debian and RPM packages, the SELinux policy package and their SBOMs in
# dist/ (amd64/x86_64 and arm64/aarch64 by default; version from the git tag,
# VERSION= overrides; FORMATS=deb or rpm builds one format). Layout and
# release process: https://github.com/openbasalt/samba-conductor-docs/blob/main/packaging.md.
ARCHES ?= amd64 arm64
FORMATS ?= deb rpm
package:
	case " $(FORMATS) " in *" rpm "*) packaging/selinux/build.sh ;; esac
	FORMATS="$(FORMATS)" packaging/build.sh $(ARCHES)

lintian:
	packaging/lintian.sh dist/*.deb

rpmlint:
	packaging/rpmlint.sh dist/*.rpm
