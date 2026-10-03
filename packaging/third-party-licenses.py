#!/usr/bin/env python3
"""Collect the license texts and notices of what a package's binaries embed.

The binaries are statically linked Go programs, so their packages carry the
copyright notices, license texts and NOTICE files of every module linked
into them (MIT, BSD and Apache-2.0 require it for binary distributions).

The module list is read from the binaries' own build information
(`go version -m`), so it is exactly what was linked, and each module's
files come from the module cache the build used (the Go standard library's
from GOROOT). The output is written to stdout, sorted by module path, with
no timestamps: the same binaries give the same bytes.

Fails when a module has no license file, when a module is replaced by a
local directory outside the family (its license could not be pinned), or
when a module ships a NOTICE file that the repository's NOTICE does not
mention (Apache-2.0 section 4(d): those notices must travel with the
binaries, so a new one is a deliberate change to NOTICE).

    third-party-licenses.py --notice NOTICE BINARY... > THIRD-PARTY-LICENSES

Standard library only.
"""
import argparse
import os
import re
import subprocess
import sys

# Modules of the Samba Conductor family: covered by the package's own
# license and NOTICE, not third-party.
FAMILY = "github.com/openbasalt/samba-conductor"

# Files of a module's root directory that carry its license terms.
LICENSE_FILE = re.compile(r"^(licen[cs]e|copying|notice|patents|unlicense)([-._].*)?$", re.I)
NOTICE_FILE = re.compile(r"^notice([-._].*)?$", re.I)


def die(msg):
    sys.stderr.write(f"third-party-licenses.py: {msg}\n")
    sys.exit(1)


def go_env(name):
    return subprocess.run(["go", "env", name], check=True, capture_output=True,
                          text=True).stdout.strip()


def escape_path(path):
    """Module cache path escaping: an upper-case letter becomes '!' + lower."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), path)


def build_info(binary):
    """Return (go version, {module path: version}) from a binary's build info."""
    out = subprocess.run(["go", "version", "-m", binary], check=True,
                         capture_output=True, text=True).stdout
    lines = out.splitlines()
    if not lines or ": go" not in lines[0]:
        die(f"{binary}: no Go build information")
    goversion = lines[0].split(": ", 1)[1].strip()
    mods = {}
    last = None
    for line in lines[1:]:
        f = line.strip().split("\t")
        if f[0] == "dep":
            last = f[1]
            mods[last] = f[2]
        elif f[0] == "=>":
            # A replacement: a module version, or a local directory (no hash).
            if last is None:
                continue
            if len(f) >= 4:
                mods[last] = (f[1], f[2])
            elif last.startswith(FAMILY):
                mods[last] = None
            else:
                die(f"{binary}: {last} is replaced by a local directory")
    return goversion, mods


def license_files(directory):
    names = sorted(n for n in os.listdir(directory)
                   if LICENSE_FILE.match(n) and os.path.isfile(os.path.join(directory, n)))
    return [(n, os.path.join(directory, n)) for n in names]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--notice", required=True,
                    help="the repository's NOTICE, which must name every module with a NOTICE file")
    ap.add_argument("binaries", nargs="+")
    args = ap.parse_args()

    with open(args.notice, encoding="utf-8") as f:
        notice = f.read()

    goversion = None
    modules = {}
    for binary in args.binaries:
        v, mods = build_info(binary)
        if goversion not in (None, v):
            die(f"{binary}: built with {v}, another binary with {goversion}")
        goversion = v
        modules.update(mods)

    goroot = go_env("GOROOT")
    if go_env("GOVERSION") != goversion:
        die(f"binaries built with {goversion}, but go is {go_env('GOVERSION')}")
    modcache = go_env("GOMODCACHE")

    sections = [("std", goversion, "Go standard library", goroot)]
    for path in sorted(modules):
        if path.startswith(FAMILY):
            continue
        version = modules[path]
        if isinstance(version, tuple):
            path_in_cache, version = version
        else:
            path_in_cache = path
        directory = os.path.join(modcache, f"{escape_path(path_in_cache)}@{escape_path(version)}")
        if not os.path.isdir(directory):
            die(f"{path}@{version} is not in the module cache ({directory})")
        sections.append((path, version, path, directory))

    # Everything is checked before anything is written.
    out = bytearray()
    out += (b"Third-party software in this package\n"
              b"====================================\n\n"
              b"The programs in this package are statically linked Go binaries. They\n"
              b"include the Go standard library and the Go modules below. Each section\n"
              b"reproduces the license, notice and patent files of one module, as\n"
              b"published with the version that was linked.\n")
    for path, version, title, directory in sections:
        files = license_files(directory)
        if path == "std":
            # GOROOT also holds files of other licenses' tools; LICENSE and
            # PATENTS are the standard library's.
            files = [f for f in files if f[0] in ("LICENSE", "PATENTS")]
        if not any(not NOTICE_FILE.match(n) and n.upper() != "PATENTS" for n, _ in files):
            die(f"{path}@{version}: no license file in {directory}")
        if path != "std" and any(NOTICE_FILE.match(n) for n, _ in files) and path not in notice:
            die(f"{path} has a NOTICE file: add its notice to {args.notice}")
        heading = f"{title} {version}"
        out += b"\n\n" + b"=" * 78 + b"\n" + heading.encode() + b"\n" + b"=" * 78 + b"\n"
        for name, file in files:
            with open(file, "rb") as f:
                text = f.read().replace(b"\r\n", b"\n").strip(b"\n")
            out += f"\n--- {name}\n\n".encode() + text + b"\n"
    sys.stdout.buffer.write(out)


if __name__ == "__main__":
    main()
