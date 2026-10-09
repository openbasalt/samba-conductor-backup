#!/usr/bin/env bash
# Install a built package in a clean container of the target architecture
# (under QEMU when it is not the host's) and run every binary it ships in
# /usr/bin with its version flag. deb: Debian 13; rpm: Fedora 44.
#
#   packaging/smoke.sh deb arm64
#   packaging/smoke.sh rpm arm64
#
# The images are pinned by their multi-arch index digest (the same pins as
# lintian.sh and rpmlint.sh). With docker, the container runs from the
# platform's own manifest digest, resolved from that pinned index: the index
# digest is already bound to the host-architecture image by the lint steps,
# and Docker refuses to bind it to a second image ("cannot overwrite digest").
# Needs docker (with buildx and jq) or podman.
set -euo pipefail
[ "$#" -eq 2 ] || { echo "usage: $0 deb|rpm amd64|arm64" >&2; exit 2; }
format="$1"
arch="$2"
DEBIAN_IMAGE="${DEBIAN_IMAGE:-docker.io/library/debian:trixie@sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c}"
FEDORA_IMAGE="${FEDORA_IMAGE:-registry.fedoraproject.org/fedora:44@sha256:7011f51bd8089d345be42d41f0aa3190d258823528852a5e7ec976fe2fd20f53}"

case "$arch" in
  amd64) rpm_arch=x86_64 ;;
  arm64) rpm_arch=aarch64 ;;
  *) echo "smoke.sh: unknown architecture $arch" >&2; exit 2 ;;
esac

# The version flag of each binary: conductor-helper takes -version, every
# other binary the version subcommand.
check_binaries='for b in $(cat /tmp/binaries); do
    case "$b" in */conductor-helper) "$b" -version ;; *) "$b" version ;; esac || exit 1
  done'
case "$format" in
  deb)
    image="$DEBIAN_IMAGE"
    shopt -s nullglob
    pkgs=(dist/*_"$arch".deb)
    install='apt-get -o Acquire::Retries=5 update -qq &&
  apt-get -o Acquire::Retries=5 install -y -qq --no-install-recommends "$PKG" >/dev/null &&
  dpkg -L "$(dpkg-deb -f "$PKG" Package)" | grep "^/usr/bin/" >/tmp/binaries'
    ;;
  rpm)
    image="$FEDORA_IMAGE"
    shopt -s nullglob
    pkgs=(dist/*."$rpm_arch".rpm)
    # dnf already retries each download; the loop also survives a mirror
    # that serves stale or half-synced metadata, and errors stay visible.
    install='for i in 1 2 3; do
    dnf -y --setopt=install_weak_deps=False install "$PKG" >/tmp/dnf.log 2>&1 && break
    cat /tmp/dnf.log >&2
    [ "$i" = 3 ] && exit 1
    dnf clean all >/dev/null; sleep $((i * 15))
  done &&
  rpm -ql "$(rpm -qp --qf "%{NAME}\n" "$PKG")" | grep "^/usr/bin/" >/tmp/binaries'
    ;;
  *) echo "smoke.sh: unknown format $format" >&2; exit 2 ;;
esac
[ "${#pkgs[@]}" -eq 1 ] || { echo "smoke.sh: expected one $format package for $arch in dist/, found ${#pkgs[@]}" >&2; exit 1; }

engine="$(command -v docker || command -v podman || true)"
[ -n "$engine" ] || { echo "smoke.sh: neither docker nor podman found" >&2; exit 1; }
ref="$image"
if [ "$(basename "$engine")" = docker ]; then
  digest="$(docker buildx imagetools inspect --raw "$image" |
    jq -er --arg arch "$arch" \
      '[.manifests[] | select(.platform.os == "linux" and .platform.architecture == $arch)][0].digest')"
  ref="${image%@*}@$digest"
fi
echo "smoke.sh: $(basename "${pkgs[0]}") in $ref" >&2
"$engine" run --rm --platform "linux/$arch" -v "$PWD/dist:/dist:ro,z" \
  -e DEBIAN_FRONTEND=noninteractive -e PKG="/dist/$(basename "${pkgs[0]}")" "$ref" \
  sh -c "set -e; $install; $check_binaries"
