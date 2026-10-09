# Quality gates and builds for conductor-backup.
# GOWORK=off by default: the module is checked on its own, against the
# versions go.mod pins (what CI and release builds use), not through a
# family go.work; `make check GOWORK=$PWD/../go.work` checks it against
# local copies of the sibling modules instead.
export GOWORK ?= off
# Gate tools, pinned (the same versions as CI) and built into
# .tools/<go version>/, so a stale or mismatched binary on $GOPATH/bin
# never runs the gates. staticcheck v0.8.1 pins golang.org/x/tools v0.44,
# which cannot read the export data version 5 written by Go 1.27.2, so it
# is built against XTOOLS_VERSION until a staticcheck release carries it.
STATICCHECK_VERSION := v0.8.1
XTOOLS_VERSION := v0.51.0
GOVULNCHECK_VERSION := v1.8.0
TOOLS_DIR := $(CURDIR)/.tools/$(shell go env GOVERSION)
STATICCHECK := $(TOOLS_DIR)/staticcheck-$(STATICCHECK_VERSION)-xtools-$(XTOOLS_VERSION)
GOVULNCHECK := $(TOOLS_DIR)/govulncheck-$(GOVULNCHECK_VERSION)
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

tools: $(STATICCHECK) $(GOVULNCHECK)

$(STATICCHECK):
	@mkdir -p $(TOOLS_DIR)
	tmp="$$(mktemp -d)" && trap 'rm -rf "$$tmp"' EXIT && cd "$$tmp" && \
		go mod init gatetools >/dev/null 2>&1 && \
		go get honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) golang.org/x/tools@$(XTOOLS_VERSION) && \
		go build -o $@ honnef.co/go/tools/cmd/staticcheck

$(GOVULNCHECK):
	@mkdir -p $(TOOLS_DIR)
	tmp="$$(mktemp -d)" && trap 'rm -rf "$$tmp"' EXIT && \
		GOBIN="$$tmp" go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) && \
		mv "$$tmp/govulncheck" $@

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
