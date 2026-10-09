#!/usr/bin/env bash
# Compile this repository's SELinux policy modules for the targeted policy of
# Fedora 44 (Basalt OS): packaging/selinux/<module>.te/.fc/.if become
# build/selinux/<module>.pp.bz2; <module>.cil files (port labels, which a .te
# module cannot declare) are copied as they are. Also written:
# build/selinux/policy-version (the selinux-policy-devel used; the package
# requires at least that policy) and COPYING.selinux-policy (its license).
#
#   packaging/selinux/build.sh
#
# Runs where selinux-policy-devel is installed when SELINUX_LOCAL=1;
# otherwise in a Fedora 44 container (docker or podman) pinned by digest,
# with selinux-policy-devel pinned to SELINUX_POLICY_DEVEL (older builds stay
# installable from Fedora's updates-archive repository). Reproducible: the
# same sources and policy toolchain give the same bytes (checked by the
# release workflow and the Basalt package lab). Shared by every component
# repository.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
FEDORA_IMAGE="${FEDORA_IMAGE:-registry.fedoraproject.org/fedora:44@sha256:7011f51bd8089d345be42d41f0aa3190d258823528852a5e7ec976fe2fd20f53}"
SELINUX_POLICY_DEVEL="${SELINUX_POLICY_DEVEL:-44.11-1.fc44}"
OUT=build/selinux

compile() {
  # In the build environment: one module at a time, in a scratch copy.
  set -euo pipefail
  local work
  work="$(mktemp -d)"
  rm -rf "$OUT"
  mkdir -p "$OUT"
  for te in packaging/selinux/*.te; do
    m="$(basename "$te" .te)"
    cp "packaging/selinux/$m.te" "packaging/selinux/$m.fc" "packaging/selinux/$m.if" "$work/"
    make -s -C "$work" -f /usr/share/selinux/devel/Makefile NAME=targeted "$m.pp" >/dev/null
    bzip2 -9 -c "$work/$m.pp" >"$OUT/$m.pp.bz2"
    cp "packaging/selinux/$m.if" "$OUT/$m.if"
  done
  for cil in packaging/selinux/*.cil; do
    [ -e "$cil" ] || continue
    cp "$cil" "$OUT/"
  done
  rpm -q --qf '%{VERSION}\n' selinux-policy-devel >"$OUT/policy-version"
  cp /usr/share/licenses/selinux-policy/COPYING "$OUT/COPYING.selinux-policy"
  rm -rf "$work"
}

if [ "${SELINUX_LOCAL:-0}" = 1 ] || [ "${1:-}" = --in-container ]; then
  compile
  exit 0
fi

engine="$(command -v docker || command -v podman || true)"
[ -n "$engine" ] || { echo "selinux/build.sh: no docker/podman; install selinux-policy-devel and set SELINUX_LOCAL=1" >&2; exit 1; }
image="samba-conductor-selinux:$SELINUX_POLICY_DEVEL"
if ! "$engine" image inspect "$image" >/dev/null 2>&1; then
  ctx="$(mktemp -d)"
  # Not quiet: a failed install shows dnf's own error in the build log. The
  # loop retries the whole install after a clean, so a Fedora mirror that
  # serves stale or half-synced metadata does not fail the build; dnf itself
  # already retries each download.
  printf 'FROM %s\nRUN for i in 1 2 3; do \\\n  dnf -y --setopt=install_weak_deps=False install fedora-repos-archive \\\n  && dnf -y --setopt=install_weak_deps=False install selinux-policy-devel-%s selinux-policy-%s selinux-policy-targeted-%s make bzip2 \\\n  && break; \\\n  [ "$i" = 3 ] && exit 1; dnf clean all; sleep $((i * 15)); \\\n done \\\n && dnf clean all\n' \
    "$FEDORA_IMAGE" "$SELINUX_POLICY_DEVEL" "$SELINUX_POLICY_DEVEL" "$SELINUX_POLICY_DEVEL" |
    "$engine" build ${SELINUX_BUILDER_NETWORK:+--network="$SELINUX_BUILDER_NETWORK"} -t "$image" -f - "$ctx" >&2
  rmdir "$ctx"
fi
exec "$engine" run --rm --network=none --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD:/src:z" -w /src "$image" packaging/selinux/build.sh --in-container
