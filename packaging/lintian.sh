#!/usr/bin/env bash
# Run Debian 13's lintian on built packages; fails on errors and warnings.
# Uses a local lintian when present, otherwise a Debian 13 container
# (docker or podman). Overrides are shipped in each package
# (/usr/share/lintian/overrides/<package>) and justified there.
#
#   packaging/lintian.sh dist/*.deb
set -euo pipefail
[ "$#" -gt 0 ] || { echo "usage: $0 PACKAGE.deb..." >&2; exit 2; }
DEBIAN_IMAGE="${DEBIAN_IMAGE:-docker.io/library/debian:trixie@sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c}"
ARGS=(--fail-on error,warning --display-info --show-overrides --suppress-tags package-has-long-file-name)

if command -v lintian >/dev/null; then
  exec lintian "${ARGS[@]}" "$@"
fi
engine="$(command -v docker || command -v podman || true)"
[ -n "$engine" ] || { echo "lintian.sh: neither lintian nor docker/podman found" >&2; exit 1; }
dir="$(cd "$(dirname "$1")" && pwd)"
names=()
for f in "$@"; do names+=("/pkgs/$(basename "$f")"); done
exec "$engine" run --rm -v "$dir:/pkgs:ro,z" "$DEBIAN_IMAGE" sh -c \
  'apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends lintian >/dev/null && exec lintian "$@"' \
  lintian "${ARGS[@]}" "${names[@]}"
