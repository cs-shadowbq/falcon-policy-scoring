#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 SBOM from a directory of bundled wheels.

Used by scripts/build-airgap.sh. Reads each wheel's METADATA to build the
component list, then emits a CycloneDX document describing the application and
all bundled dependencies.

Usage:
    gen_sbom.py <wheels_dir> <output_sbom_json> <app_version>
"""
import datetime
import email.parser
import json
import os
import sys
import zipfile


def build_components(wheels_dir: str) -> list:
    components = []
    for fname in sorted(os.listdir(wheels_dir)):
        if not fname.endswith(".whl"):
            continue
        whl_path = os.path.join(wheels_dir, fname)
        with zipfile.ZipFile(whl_path) as zf:
            metadata_files = [n for n in zf.namelist() if n.endswith("/METADATA")]
            if not metadata_files:
                continue
            with zf.open(metadata_files[0]) as mf:
                meta = email.parser.BytesParser().parsebytes(mf.read())
        name = meta.get("Name", "")
        version = meta.get("Version", "")
        purl = f"pkg:pypi/{name.lower()}@{version}"
        component = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
            "bom-ref": purl,
        }
        license_val = meta.get("License-Expression") or ""
        if not license_val or len(license_val) > 80:
            # Fallback: try Classifier for SPDX-style short identifiers
            classifiers = meta.get_all("Classifier") or []
            for c in classifiers:
                if c.startswith("License :: OSI Approved ::"):
                    license_val = c.split("::")[-1].strip()
                    break
        if not license_val:
            license_val = meta.get("License", "")
        if license_val and license_val.strip() and license_val.strip() != "UNKNOWN":
            # Truncate full license texts to just the first line (likely the name)
            short = license_val.strip().split("\n")[0].strip()
            if len(short) <= 80:
                component["licenses"] = [{"expression": short}]
            else:
                component["licenses"] = [{"license": {"name": short[:200]}}]
        author = meta.get("Author") or meta.get("Author-email", "")
        if author:
            component["author"] = author
        # Add the wheel filename as evidence of what's bundled
        component["evidence"] = {
            "identity": {
                "field": "filename",
                "methods": [{"technique": "filename", "value": fname}],
            }
        }
        components.append(component)
    return components


def main(wheels_dir: str, out_path: str, app_version: str) -> int:
    components = build_components(wheels_dir)
    sbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "component": {
                "type": "application",
                "name": "falcon-policy-scoring",
                "version": app_version,
                "purl": f"pkg:pypi/falcon-policy-scoring@{app_version}",
                "bom-ref": f"pkg:pypi/falcon-policy-scoring@{app_version}",
            },
            "tools": [{"name": "build-airgap.sh", "version": app_version}],
        },
        "components": components,
    }
    with open(out_path, "w") as f:
        json.dump(sbom, f, indent=2)
    print(f"  {len(components)} components in sbom.cdx.json")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: gen_sbom.py <wheels_dir> <output_sbom_json> <app_version>")
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3]))
