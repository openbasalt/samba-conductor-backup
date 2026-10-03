#!/usr/bin/env python3
"""Merge the CycloneDX SBOMs of a package's binaries into one document.

cyclonedx-gomod describes one Go application per document. A package that
ships several binaries gets one SBOM: the union of their components (deduped
by bom-ref) and dependency edges, with the package itself as the subject.
Timestamp and serial number are derived from the inputs, so the result is
reproducible. Standard library only.
"""
import argparse
import json
import uuid

# Modules of the Samba Conductor family (local replace directives).
FAMILY = "github.com/samba-conductor/"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--arch", required=True)
    ap.add_argument("--timestamp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("inputs", nargs="+")
    args = ap.parse_args()

    docs = []
    for path in args.inputs:
        with open(path, encoding="utf-8") as f:
            docs.append(json.load(f))

    purl = f"pkg:deb/openbasalt/{args.name}@{args.version}?arch={args.arch}"
    subject = {
        "type": "application",
        "bom-ref": purl,
        "name": args.name,
        "version": args.version,
        "purl": purl,
        "licenses": [{"license": {"id": "MIT"}}],
    }

    components = {}
    deps = {}
    binaries = []
    for doc in docs:
        app = doc.get("metadata", {}).get("component")
        if app:
            # Each binary becomes a component of the package.
            components.setdefault(app["bom-ref"], app)
            binaries.append(app["bom-ref"])
        for c in doc.get("components", []):
            if c.get("name", "").startswith(FAMILY):
                # A sibling resolved through `replace ../<repo>`: its hash is
                # computed over a working directory (build output included),
                # so it is not reproducible; the version names the commit.
                c.pop("hashes", None)
            components.setdefault(c["bom-ref"], c)
        for d in doc.get("dependencies", []):
            deps.setdefault(d["ref"], set()).update(d.get("dependsOn", []))
    deps[purl] = set(binaries)

    tools = docs[0].get("metadata", {}).get("tools")
    out = {
        "bomFormat": "CycloneDX",
        "specVersion": docs[0].get("specVersion", "1.6"),
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, purl)),
        "version": 1,
        "metadata": {"timestamp": args.timestamp, "component": subject},
        "components": [components[k] for k in sorted(components)],
        "dependencies": [{"ref": k, "dependsOn": sorted(v)} for k, v in sorted(deps.items())],
    }
    if tools:
        out["metadata"]["tools"] = tools
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
