#!/usr/bin/env bash
# Build this repository's packages for one or more architectures: static
# binaries (CGO off), systemd units with packaged paths, man pages and
# changelogs, third-party license texts, the .deb and the .rpm (nfpm, one
# configuration for both), the noarch SELinux policy package (.rpm) and one
# CycloneDX SBOM per package, all in dist/.
#
#   packaging/build.sh [amd64] [arm64]      (default: both)
#   FORMATS=deb packaging/build.sh          (only .deb; FORMATS=rpm only .rpm)
#   VERSION=1.2.3 packaging/build.sh        (override the version from git)
#   PACKAGE_GOWORK=../go.work packaging/build.sh
#                                           (lab builds: the sibling modules from
#                                           a Go workspace instead of go.mod's pins)
#
# Reproducible: the same commit, Go toolchain and tool versions give the same
# bytes (-trimpath, empty build ID, SOURCE_DATE_EPOCH = commit time for every
# timestamp nfpm and gzip write, a fixed RPM build host). The SELinux modules
# come from packaging/selinux/build.sh (a pinned Fedora 44 policy toolchain;
# reused from build/selinux when already built). Shared by every component
# repository; the per-repository parts are packaging/package.conf,
# packaging/*.yaml, packaging/rpm/ and packaging/selinux/*.{te,fc,if,cil}.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NFPM_VERSION="v2.47.0"
CYCLONEDX_GOMOD_VERSION="v1.12.0"

# shellcheck source=/dev/null
. packaging/package.conf # PACKAGES (name=nfpm yaml), BINARIES (package=binaries), SELINUX

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

# rpm_version: the same version in RPM terms. "~" (pre-release) means the
# same in both; a snapshot after a release uses RPM's "^" (Fedora's
# versioning guidelines) where Debian uses "+".
rpm_version() { printf '%s\n' "${1/+git/^git}"; }

VERSION_UPSTREAM="$(deb_version)"
[[ "$VERSION_UPSTREAM" =~ ^[0-9][0-9A-Za-z.+~]*$ ]] || die "bad version $VERSION_UPSTREAM"
VERSION_RPM="$(rpm_version "$VERSION_UPSTREAM")"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
MTIME="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
CHANGELOG_DATE="$(LC_ALL=C date -u -d "@$SOURCE_DATE_EPOCH" -R)"
MAINTAINER="$(awk -F': ' '/^maintainer:/{print $2; exit}' "packaging/${PACKAGES[0]#*=}")"
REVISION="1"

FORMATS="${FORMATS:-deb rpm}"
want() { case " $FORMATS " in *" $1 "*) return 0 ;; esac; return 1; }
want deb || want rpm || die "FORMATS must name deb and/or rpm"

ARCHES=("$@")
[ "${#ARCHES[@]}" -gt 0 ] || ARCHES=(amd64 arm64)
mkdir -p dist

# The RPM scriptlets create the system user before the payload is unpacked
# (packaging/rpm/pre, from the same line as packaging/sysusers.conf); a
# drift between the two would create a different user than sysusers.d says.
if want rpm && [ -f packaging/sysusers.conf ]; then
  mkdir -p build
  grep -v '^#' packaging/sysusers.conf | grep . >build/sysusers.expected
  sed -n "/<<'SYSUSERS'/,/^SYSUSERS\$/p" packaging/rpm/pre | sed '1d;$d' >build/sysusers.inline
  cmp -s build/sysusers.expected build/sysusers.inline ||
    die "packaging/rpm/pre and packaging/sysusers.conf name different users"
fi

# write_changelog_rpm FILE: the RPM %changelog entry, in nfpm's chglog format.
write_changelog_rpm() {
  cat >"$1" <<EOT
- semver: ${VERSION_RPM}-${REVISION}
  date: ${MTIME}
  packager: ${MAINTAINER}
  changes:
    - note: Upstream release ${VERSION_UPSTREAM}.
EOT
}

# rpm_config YAML OUT CHANGELOG: nfpm's changelog setting is global (the deb
# carries its own changelog.Debian.gz), so the RPM build reads a copy of the
# configuration with the changelog added.
rpm_config() {
  { cat "$1"; printf '\nchangelog: %s\n' "$3"; } >"$2"
}

for arch in "${ARCHES[@]}"; do
  case "$arch" in
  amd64) rpmarch=x86_64 ;;
  arm64) rpmarch=aarch64 ;;
  *) die "unsupported architecture $arch" ;;
  esac
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

    # License texts and notices of everything the binaries link: the Go
    # standard library and each module, from the binaries' build info and the
    # module cache (packaging/third-party-licenses.py; fails on a module
    # without a license or with a NOTICE the repository NOTICE does not carry).
    # The .deb ships it gzipped in /usr/share/doc, the .rpm as is in
    # /usr/share/licenses (Fedora's %license); same text.
    bins=()
    for spec in "${BINARIES[@]}"; do
      [ "${spec%%=*}" = "$pkg" ] || continue
      for bin in ${spec#*=}; do bins+=("$out/bin/$bin"); done
    done
    python3 packaging/third-party-licenses.py --notice NOTICE "${bins[@]}" >"$out/doc/$pkg/THIRD-PARTY-LICENSES"
    gzip -9n <"$out/doc/$pkg/THIRD-PARTY-LICENSES" >"$out/doc/$pkg/THIRD-PARTY-LICENSES.gz"

    # 4. The SBOM inputs: every binary's module graph and the Go standard
    #    library, with licenses (merged per package and format in step 6).
    sboms=()
    for spec in "${BINARIES[@]}"; do
      [ "${spec%%=*}" = "$pkg" ] || continue
      for bin in ${spec#*=}; do
        GOARCH="$arch" "$CYCLONEDX_GOMOD" app -json -licenses -std -noserial \
          -main "cmd/$bin" -output "$out/$bin.cdx.json" . 2>/dev/null
        sboms+=("$out/$bin.cdx.json")
      done
    done

    # 5-6. The packages and their SBOMs.
    if want deb; then
      PKG_VERSION="$VERSION_UPSTREAM" PKG_REVISION="$REVISION" ARCH="$arch" BUILD="$out" \
        "$NFPM" package --config "$PWD/$yaml" --packager deb --target "$PWD/dist/" >/dev/null
      deb="dist/${pkg}_${VERSION_UPSTREAM}-${REVISION}_${arch}.deb"
      [ -f "$deb" ] || die "nfpm did not write $deb"
      python3 packaging/sbom-merge.py --type deb --name "$pkg" --version "$VERSION_UPSTREAM-$REVISION" \
        --arch "$arch" --timestamp "$MTIME" --out "${deb%.deb}.cdx.json" "${local_family[@]}" "${sboms[@]}"
      printf '%s\n' "$deb" "${deb%.deb}.cdx.json"
    fi
    if want rpm; then
      write_changelog_rpm "$out/doc/$pkg/changelog.yml"
      rpm_config "$yaml" "$out/$pkg.rpm.yaml" "$PWD/$out/doc/$pkg/changelog.yml"
      PKG_VERSION="$VERSION_RPM" PKG_REVISION="$REVISION" ARCH="$arch" BUILD="$out" \
        "$NFPM" package --config "$PWD/$out/$pkg.rpm.yaml" --packager rpm --target "$PWD/dist/" >/dev/null
      rpm="dist/${pkg}-${VERSION_RPM}-${REVISION}.${rpmarch}.rpm"
      [ -f "$rpm" ] || die "nfpm did not write $rpm"
      python3 packaging/sbom-merge.py --type rpm --name "$pkg" --version "$VERSION_RPM-$REVISION" \
        --arch "$rpmarch" --timestamp "$MTIME" --out "${rpm%.rpm}.cdx.json" "${local_family[@]}" "${sboms[@]}"
      printf '%s\n' "$rpm" "${rpm%.rpm}.cdx.json"
    fi
  done
done

# 7. The SELinux policy package (RPM only, noarch, once): the compiled
#    modules from packaging/selinux/build.sh, their interface files, and the
#    license texts (the compiled policy expands macros of the distribution's
#    reference policy, GPL-2.0-or-later).
if want rpm && [ "${#SELINUX[@]}" -gt 0 ]; then
  sel="build/selinux"
  # Built here when missing; "make package" always rebuilds it first (the
  # release builder image has no container engine: the modules are built
  # before entering it, planning/release/build-all.sh).
  [ -s "$sel/policy-version" ] || packaging/selinux/build.sh
  SELINUX_POLICY_VERSION="$(cat "$sel/policy-version")"
  # The scriptlets name the modules (every .te and .cil in packaging/selinux).
  modules="$(find packaging/selinux -maxdepth 1 \( -name '*.te' -o -name '*.cil' \) -printf '%f\n' |
    sed 's/\.[a-z]*$//' | LC_ALL=C sort -u | tr '\n' ' ')"
  mkdir -p "$sel/scripts"
  for s in pre post postun posttrans; do
    sed "s/@MODULES@/${modules% }/" "packaging/selinux/scripts/$s" >"$sel/scripts/$s"
  done
  for entry in "${SELINUX[@]}"; do
    pkg="${entry%%=*}"
    yaml="packaging/${entry#*=}"
    mkdir -p "$sel/doc/$pkg"
    {
      printf 'Third-party license texts of %s\n\n' "$pkg"
      printf 'The policy modules are compiled from this repository'"'"'s sources\n'
      printf '(Apache-2.0) with the macros and interfaces of the SELinux reference\n'
      printf 'policy as shipped by selinux-policy-devel %s (GPL-2.0-or-later),\n' "$SELINUX_POLICY_VERSION"
      printf 'whose expansions the compiled modules contain.\n\n'
      printf '==== selinux-policy %s: COPYING ====\n\n' "$SELINUX_POLICY_VERSION"
      cat "$sel/COPYING.selinux-policy"
    } >"$sel/doc/$pkg/THIRD-PARTY-LICENSES"
    write_changelog_rpm "$sel/doc/$pkg/changelog.yml"
    rpm_config "$yaml" "$sel/$pkg.rpm.yaml" "$PWD/$sel/doc/$pkg/changelog.yml"
    PKG_VERSION="$VERSION_RPM" PKG_REVISION="$REVISION" SELINUX_POLICY_VERSION="$SELINUX_POLICY_VERSION" \
      SELINUX_BUILD="$sel" "$NFPM" package --config "$PWD/$sel/$pkg.rpm.yaml" --packager rpm --target "$PWD/dist/" >/dev/null
    rpm="dist/${pkg}-${VERSION_RPM}-${REVISION}.noarch.rpm"
    [ -f "$rpm" ] || die "nfpm did not write $rpm"
    python3 packaging/sbom-merge.py --type rpm --name "$pkg" --version "$VERSION_RPM-$REVISION" \
      --arch noarch --timestamp "$MTIME" --license "Apache-2.0 AND GPL-2.0-or-later" \
      --tool "selinux-policy-devel@$SELINUX_POLICY_VERSION" --out "${rpm%.rpm}.cdx.json"
    printf '%s\n' "$rpm" "${rpm%.rpm}.cdx.json"
  done
fi
