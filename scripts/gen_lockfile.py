#!/usr/bin/env python3
"""Generate a hash-pinned pip requirements lockfile from a directory of wheels.

Used by scripts/build-airgap.sh so the offline install can run with
`pip install --require-hashes`. Groups wheels by (name, version) and emits all
SHA256 hashes for each so pip can pick the best-matching file. Covers the
project wheel and every transitive dependency.

Usage:
    gen_lockfile.py <wheels_dir> <output_lockfile>
"""
import hashlib
import os
import sys
from collections import defaultdict


def main(wheels_dir: str, out_path: str) -> int:
    groups = defaultdict(list)  # (name, version) -> [sha256, ...]
    for fname in sorted(os.listdir(wheels_dir)):
        if not fname.endswith(".whl"):
            continue
        # Wheel filename: {name}-{version}-{pytag}-{abitag}-{plat}.whl
        parts = fname[:-4].split("-")
        if len(parts) < 2:
            continue
        name, version = parts[0], parts[1]
        with open(os.path.join(wheels_dir, fname), "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        groups[(name, version)].append(digest)

    lines = [
        "# Auto-generated hash-pinned lockfile for airgap install. DO NOT EDIT.",
        "# Install with: pip install --no-index --find-links=wheels \\",
        "#   --require-hashes -r requirements.lock",
        "",
    ]
    for (name, version), digests in sorted(groups.items()):
        hash_args = " \\\n    ".join(f"--hash=sha256:{d}" for d in digests)
        lines.append(f"{name}=={version} \\\n    {hash_args}")
    with open(out_path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"  {len(groups)} pinned packages in requirements.lock")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: gen_lockfile.py <wheels_dir> <output_lockfile>")
    sys.exit(main(sys.argv[1], sys.argv[2]))
