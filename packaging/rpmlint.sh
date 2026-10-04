#!/usr/bin/env bash
# Run Fedora 44's rpmlint on built packages; fails on errors and on warnings
# (--strict). Filters are in packaging/rpmlintrc, each justified there.
# Uses a local rpmlint when RPMLINT_LOCAL=1, otherwise a Fedora 44 container
# (docker or podman) pinned by digest.
#
#   packaging/rpmlint.sh dist/*.rpm
set -euo pipefail
[ "$#" -gt 0 ] || { echo "usage: $0 PACKAGE.rpm..." >&2; exit 2; }
cd "$(dirname "${BASH_SOURCE[0]}")/.."
FEDORA_IMAGE="${FEDORA_IMAGE:-registry.fedoraproject.org/fedora:44@sha256:7011f51bd8089d345be42d41f0aa3190d258823528852a5e7ec976fe2fd20f53}"
ARGS=(--strict --info --rpmlintrc packaging/rpmlintrc)

if [ "${RPMLINT_LOCAL:-0}" = 1 ]; then
  exec rpmlint "${ARGS[@]}" "$@"
fi
engine="$(command -v docker || command -v podman || true)"
[ -n "$engine" ] || { echo "rpmlint.sh: neither docker nor podman found (RPMLINT_LOCAL=1 for a local rpmlint)" >&2; exit 1; }
names=()
for f in "$@"; do names+=("/pkgs/$(basename "$f")"); done
dir="$(cd "$(dirname "$1")" && pwd)"
exec "$engine" run --rm ${RPMLINT_NETWORK:+--network="$RPMLINT_NETWORK"} \
  -v "$dir:/pkgs:ro,z" -v "$PWD/packaging/rpmlintrc:/rpmlintrc:ro,z" "$FEDORA_IMAGE" sh -c \
  'dnf -y -q install --setopt=install_weak_deps=False rpmlint >/dev/null && exec rpmlint "$@"' \
  rpmlint --strict --info --rpmlintrc /rpmlintrc "${names[@]}"
