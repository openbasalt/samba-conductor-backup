#!/usr/bin/env bash
# Build this repository's Debian package(s) for one or more architectures:
# static binaries (CGO off), systemd units with packaged paths, man pages and
# changelog, the .deb (nfpm) and one CycloneDX SBOM per package, all in dist/.
#
#   packaging/build.sh [amd64] [arm64]      (default: both)
#   VERSION=1.2.3 packaging/build.sh        (override the version from git)
#   PACKAGE_GOWORK=../go.work packaging/build.sh
#                                           (lab builds: the sibling modules from
#                                           a Go workspace instead of go.mod's pins)
#
# Reproducible: the same commit, Go toolchain and tool versions give the same
# bytes (-trimpath, empty build ID, SOURCE_DATE_EPOCH = commit time for every
# timestamp nfpm and gzip write). Shared by every component repository; the
# per-repository parts are packaging/package.conf and packaging/*.yaml.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NFPM_VERSION="v2.47.0"
CYCLONEDX_GOMOD_VERSION="v1.12.0"

# shellcheck source=/dev/null
. packaging/package.conf # PACKAGES (name=nfpm yaml) and BINARIES (package=binaries)

# Release builds use the sibling module versions go.mod pins (GOWORK=off);
# a workspace is for lab builds of unpushed sibling changes only.
export GOWORK="${PACKAGE_GOWORK:-off}" CGO_ENABLED=0 GOOS=linux
local_family=()
if [ "$GOWORK" != off ]; then local_family=(--local-family); fi
# nfpm and cyclonedx-gomod at pinned versions, built for the build host
# (not for the target architecture) into build/tools.
TOOLS="$PWD/build/tools"
install_tool() {
  local name="$1" mod="$2"
  [ -x "$TOOLS/$name.$3" ] && return
  (cd / && GOBIN="$TOOLS" GOOS= GOARCH= GOFLAGS= go install "$mod@$3")
  mv "$TOOLS/$name" "$TOOLS/$name.$3"
}
# NFPM / CYCLONEDX_GOMOD may point at the same versions already installed
# (the release builder image, planning/release/Dockerfile).
if [ -z "${NFPM:-}" ]; then
  install_tool nfpm github.com/goreleaser/nfpm/v2/cmd/nfpm "$NFPM_VERSION"
  NFPM="$TOOLS/nfpm.$NFPM_VERSION"
fi
if [ -z "${CYCLONEDX_GOMOD:-}" ]; then
  install_tool cyclonedx-gomod github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod "$CYCLONEDX_GOMOD_VERSION"
  CYCLONEDX_GOMOD="$TOOLS/cyclonedx-gomod.$CYCLONEDX_GOMOD_VERSION"
fi

die() { printf 'build.sh: %s\n' "$*" >&2; exit 1; }

# deb_version: X.Y.Z for tag vX.Y.Z on HEAD, X.Y.Z~rc.N for vX.Y.Z-rc.N, and
# <last tag or 0.0.0>+git<commit time>.<sha12> between tags (sorts after the
# tag and by date). A dirty tree gets ".dirty" (never released).
deb_version() {
  if [ -n "${VERSION:-}" ]; then printf '%s\n' "${VERSION#v}"; return; fi
  local tag v base when sha
  if tag="$(git describe --tags --exact-match --match 'v[0-9]*' 2>/dev/null)"; then
    v="${tag#v}"
    case "$v" in *-*) v="${v%%-*}~${v#*-}" ;; esac
  else
    base="$(git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || echo v0.0.0)"
    when="$(TZ=UTC git log -1 --date=format-local:%Y%m%d%H%M%S --format=%cd)"
    sha="$(git rev-parse --short=12 HEAD)"
    v="${base#v}+git${when}.${sha}"
  fi
  if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then v="$v.dirty"; fi
  printf '%s\n' "$v"
}

VERSION_UPSTREAM="$(deb_version)"
[[ "$VERSION_UPSTREAM" =~ ^[0-9][0-9A-Za-z.+~]*$ ]] || die "bad version $VERSION_UPSTREAM"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
MTIME="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
CHANGELOG_DATE="$(LC_ALL=C date -u -d "@$SOURCE_DATE_EPOCH" -R)"
MAINTAINER="$(awk -F': ' '/^maintainer:/{print $2; exit}' "packaging/${PACKAGES[0]#*=}")"
REVISION="1"

ARCHES=("$@")
[ "${#ARCHES[@]}" -gt 0 ] || ARCHES=(amd64 arm64)
mkdir -p dist

for arch in "${ARCHES[@]}"; do
  case "$arch" in amd64 | arm64) ;; *) die "unsupported architecture $arch" ;; esac
  out="build/$arch"
  rm -rf "$out"
  mkdir -p "$out/bin" "$out/systemd" "$out/man" "$out/doc"

  # 1. Binaries: static, no build ID, version stamped.
  for spec in "${BINARIES[@]}"; do
    for bin in ${spec#*=}; do
      GOARCH="$arch" go build -trimpath -ldflags "-s -w -buildid= -X main.version=$VERSION_UPSTREAM" \
        -o "$out/bin/$bin" "./cmd/$bin"
    done
  done

  # 2. The repository's units, with the packaged binary path. Nothing else
  #    changes (the sandboxing stays exactly as reviewed).
  while IFS= read -r -d '' f; do
    rel="${f#deploy/systemd/}"
    mkdir -p "$out/systemd/$(dirname "$rel")"
    sed 's#/usr/local/bin/#/usr/bin/#g' "$f" >"$out/systemd/$rel"
  done < <(find deploy/systemd -type f -print0)
  if grep -rq '/usr/local/' "$out/systemd"; then die "a unit still refers to /usr/local"; fi

  # 3. Man pages and changelog, compressed without names or timestamps.
  for page in packaging/man/*.8; do gzip -9n <"$page" >"$out/man/$(basename "$page").gz"; done

  for entry in "${PACKAGES[@]}"; do
    pkg="${entry%%=*}"
    yaml="packaging/${entry#*=}"
    mkdir -p "$out/doc/$pkg"
    printf '%s (%s-%s) stable; urgency=medium\n\n  * Upstream release %s.\n\n -- %s  %s\n' \
      "$pkg" "$VERSION_UPSTREAM" "$REVISION" "$VERSION_UPSTREAM" "$MAINTAINER" "$CHANGELOG_DATE" |
      gzip -9n >"$out/doc/$pkg/changelog.Debian.gz"

    # 4. The package.
    ARCH="$arch" DEB_VERSION="$VERSION_UPSTREAM" DEB_REVISION="$REVISION" BUILD="$out" \
      "$NFPM" package \
      --config "$PWD/$yaml" --packager deb --target "$PWD/dist/" >/dev/null
    deb="dist/${pkg}_${VERSION_UPSTREAM}-${REVISION}_${arch}.deb"
    [ -f "$deb" ] || die "nfpm did not write $deb"

    # 5. SBOM of what the package ships: every binary's module graph and the
    #    Go standard library, with licenses; merged into one document.
    sboms=()
    for spec in "${BINARIES[@]}"; do
      [ "${spec%%=*}" = "$pkg" ] || continue
      for bin in ${spec#*=}; do
        GOARCH="$arch" "$CYCLONEDX_GOMOD" app -json -licenses -std -noserial \
          -main "cmd/$bin" -output "$out/$bin.cdx.json" . 2>/dev/null
        sboms+=("$out/$bin.cdx.json")
      done
    done
    python3 packaging/sbom-merge.py --name "$pkg" --version "$VERSION_UPSTREAM-$REVISION" \
      --arch "$arch" --timestamp "$MTIME" --out "${deb%.deb}.cdx.json" "${local_family[@]}" "${sboms[@]}"
    printf '%s\n' "$deb" "${deb%.deb}.cdx.json"
  done
done
