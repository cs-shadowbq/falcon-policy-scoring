#!/bin/bash
# Build airgap deployment bundle for falcon-policy-scoring
# Run on a machine WITH internet to produce a transferable bundle.
#
# Usage:
#   ./scripts/build-airgap.sh                  # defaults: Python 3.9, RHEL 9 x86_64
#   ./scripts/build-airgap.sh --python 311     # Python 3.11 target
#   ./scripts/build-airgap.sh --python 39,311  # both versions
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults
PYTHON_VERSIONS="39"
PLATFORM="manylinux_2_28_x86_64"
# DIST_DIR is set below, once VERSION is known, so artifacts are version-scoped.

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --python|-p)
            PYTHON_VERSIONS="$2"
            shift 2
            ;;
        --platform)
            PLATFORM="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--python VERSION] [--platform PLATFORM]"
            echo ""
            echo "Options:"
            echo "  --python, -p    Python version(s): 39, 311, or 39,311 (default: 39)"
            echo "  --platform      Wheel platform tag (default: manylinux_2_28_x86_64)"
            echo ""
            echo "Examples:"
            echo "  $0                        # Python 3.9, RHEL 9 x86_64"
            echo "  $0 --python 311           # Python 3.11"
            echo "  $0 --python 39,311        # Both versions"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Read version from pyproject.toml
VERSION=$(python3 -c "
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib
print(tomllib.load(open('$PROJECT_DIR/pyproject.toml', 'rb'))['project']['version'])
")

# Build artifacts are written to a version-scoped subdirectory so different
# versions never mingle and SHA256SUMS only ever covers a single release.
DIST_DIR="$PROJECT_DIR/dist/$VERSION"

echo "=== Building falcon-policy-scoring v${VERSION} airgap bundles ==="
echo "Target platform: ${PLATFORM}"
echo "Python versions: ${PYTHON_VERSIONS}"
echo ""

# Build the project wheel if not already present in dist/
echo "--- Checking for project wheel ---"
cd "$PROJECT_DIR"
mkdir -p "$DIST_DIR"
PROJECT_WHEEL="$(find "$DIST_DIR" -maxdepth 1 -name 'falcon_policy_scoring-*.whl' -print -quit 2>/dev/null || true)"
if [ -z "$PROJECT_WHEEL" ]; then
    echo "No wheel found in dist/, building..."
    python3 -m pip install --quiet build 2>/dev/null || true
    python3 -m build --wheel --outdir "$DIST_DIR"
    PROJECT_WHEEL="$(find "$DIST_DIR" -maxdepth 1 -name 'falcon_policy_scoring-*.whl' -print -quit)"
fi
echo "Using: $(basename "$PROJECT_WHEEL")"
echo ""

# Build bundles for each Python version
IFS=',' read -ra VERSIONS <<< "$PYTHON_VERSIONS"
for PYVER in "${VERSIONS[@]}"; do
    PYVER_DOT="${PYVER:0:1}.${PYVER:1}"
    BUNDLE_NAME="falcon-policy-scoring-${VERSION}-airgap-rhel9-cp${PYVER}-x86_64"
    BUNDLE_DIR="$DIST_DIR/$BUNDLE_NAME"

    echo "--- Building bundle for Python ${PYVER_DOT} ---"

    rm -rf "$BUNDLE_DIR"
    mkdir -p "$BUNDLE_DIR/wheels"

    # Copy project wheel
    cp "$PROJECT_WHEEL" "$BUNDLE_DIR/wheels/"

    # Bundle runtime config (grading definitions + example config) and docs so
    # the workspace can be prepped offline. These live at the repo root, outside
    # the wheel, and are required at runtime relative to the working directory.
    echo "Bundling config/ and docs/ ..."
    cp -R "$PROJECT_DIR/config" "$BUNDLE_DIR/config"
    if [ -d "$PROJECT_DIR/docs" ]; then
        cp -R "$PROJECT_DIR/docs" "$BUNDLE_DIR/docs"
    fi

    # Bundle the systemd unit template so install.sh can render it for a
    # hardened bare-metal deployment. Lives at repo root under dist-templates/.
    if [ -f "$PROJECT_DIR/dist-templates/falcon-policy-audit.service" ]; then
        cp "$PROJECT_DIR/dist-templates/falcon-policy-audit.service" \
            "$BUNDLE_DIR/falcon-policy-audit.service"
    fi

    # Bundle the generated man page so install.sh can install it offline.
    # Produced by `make man` (argparse-manpage) into build/; `make airgap`
    # regenerates it first.
    if [ -f "$PROJECT_DIR/build/policy-audit.1" ]; then
        cp "$PROJECT_DIR/build/policy-audit.1" "$BUNDLE_DIR/policy-audit.1"
    fi

    # Bundle the standalone readiness_map helper. It is a self-contained stdlib
    # script (NOT a pip console script), so install.sh must place it next to
    # policy-audit itself; pip never installs it.
    if [ -f "$PROJECT_DIR/bin/readiness_map" ]; then
        cp "$PROJECT_DIR/bin/readiness_map" "$BUNDLE_DIR/readiness_map"
    fi

    # Bundle the install / security / support docs next to install.sh so an
    # airgapped operator has them offline. Only copy if not already present.
    for doc in INSTALL.md SECURITY.md SUPPORT.md; do
        if [ -f "$PROJECT_DIR/$doc" ] && [ ! -f "$BUNDLE_DIR/$doc" ]; then
            cp "$PROJECT_DIR/$doc" "$BUNDLE_DIR/$doc"
        fi
    done

    # Download platform-specific dependencies. ruamel.yaml is required by
    # upgrade.sh (comment-preserving config merge); its optional C ext is
    # platform-specific, so include it in the platform pass too.
    echo "Downloading dependencies for cp${PYVER} / ${PLATFORM}..."
    pip download \
        --platform "$PLATFORM" \
        --python-version "$PYVER" \
        --implementation cp \
        --abi "cp${PYVER}" \
        --only-binary=:all: \
        --dest "$BUNDLE_DIR/wheels/" \
        crowdstrike-falconpy tinydb schedule pyyaml rich python-dotenv ruamel.yaml \
        2>&1 | grep -E "^(Downloading|Saved|File was already)" || true

    # tomli only needed for Python < 3.11
    if [[ "${PYVER}" -lt 311 ]]; then
        pip download \
            --platform "$PLATFORM" \
            --python-version "$PYVER" \
            --implementation cp \
            --abi "cp${PYVER}" \
            --only-binary=:all: \
            --dest "$BUNDLE_DIR/wheels/" \
            tomli \
            2>&1 | grep -E "^(Downloading|Saved|File was already)" || true
    fi

    # Also grab pure-python fallbacks (none-any wheels). ruamel.yaml ships a
    # pure-python wheel, so this pass covers hosts without the C extension.
    pip download \
        --platform any \
        --python-version "$PYVER" \
        --implementation cp \
        --abi none \
        --only-binary=:all: \
        --dest "$BUNDLE_DIR/wheels/" \
        crowdstrike-falconpy tinydb schedule pyyaml rich python-dotenv ruamel.yaml \
        2>/dev/null || true

    # Deduplicate: if both platform-specific and pure-python exist, keep both
    # (pip --find-links resolves the best match automatically)

    # Generate a hash-pinned lockfile over every downloaded wheel so the offline
    # install can run with `pip install --require-hashes`.
    echo "Generating hash-pinned requirements.lock ..."
    python3 "$SCRIPT_DIR/gen_lockfile.py" "$BUNDLE_DIR/wheels" "$BUNDLE_DIR/requirements.lock"

    # Copy the installer and uninstaller from the repo templates. They are
    # static (no build-time interpolation), so they live as standalone,
    # syntax-checkable scripts under dist-templates/ rather than inline heredocs.
    echo "Bundling install.sh / uninstall.sh ..."
    cp "$PROJECT_DIR/dist-templates/install.sh"   "$BUNDLE_DIR/install.sh"
    cp "$PROJECT_DIR/dist-templates/uninstall.sh" "$BUNDLE_DIR/uninstall.sh"
    cp "$PROJECT_DIR/dist-templates/upgrade.sh"   "$BUNDLE_DIR/upgrade.sh"
    cp "$PROJECT_DIR/dist-templates/merge_config.py" "$BUNDLE_DIR/merge_config.py"
    chmod +x "$BUNDLE_DIR/install.sh" "$BUNDLE_DIR/uninstall.sh" "$BUNDLE_DIR/upgrade.sh"

    # Generate CycloneDX SBOM from the bundled wheels
    echo "Generating SBOM (CycloneDX)..."
    python3 "$SCRIPT_DIR/gen_sbom.py" "$BUNDLE_DIR/wheels" "$BUNDLE_DIR/sbom.cdx.json" "$VERSION"

    # Create README
    cat > "$BUNDLE_DIR/README.md" << EOF
# falcon-policy-scoring v${VERSION} — Airgap Bundle

**Target:** RHEL 9 x86_64, Python ${PYVER_DOT}

## Quick Install

\`\`\`bash
chmod +x install.sh
./install.sh
\`\`\`

Use \`--type WORKSPACE -w <dir>\` to prepare a self-contained run directory. It
creates \`<dir>/{grading,data,logs}\`, seeds \`<dir>/config.yaml\` (mode 0600), and
pins an absolute sqlite path. Grading resolves next to config.yaml, so you can
run from anywhere:

\`\`\`bash
./install.sh --type WORKSPACE -w /opt/falcon-policy-audit
policy-audit -c /opt/falcon-policy-audit/config.yaml fetch
\`\`\`

Install state is recorded to a **manifest** (\`falcon-policy-audit.manifest\`) and
activity to an append-only **log** (\`falcon-policy-audit-installation.log\`), both
under \`/var/log/falcon-policy-audit\` for a service install or
\`~/.config/falcon-policy-audit\` otherwise (override with \`--state-dir\`).

## Run as a systemd service (hardened RHEL9)

\`\`\`bash
sudo ./install.sh --service -y     # SYSTEM layout (FHS paths)
sudo systemctl enable --now falcon-policy-audit
systemd-analyze security falcon-policy-audit   # verify the sandbox
\`\`\`

## Uninstall

\`\`\`bash
./uninstall.sh             # remove package/CLI/man/unit/user; keep config + data
./uninstall.sh --purge     # also delete config, grading, data, and output
\`\`\`

\`uninstall.sh\` reads the manifest to know exactly what to remove and appends its
actions to the shared installation log. \`--purge\` keeps the manifest + log for
audit. Pass \`--state-dir DIR\` if they aren't in the default location.

## Upgrade (from a newer bundle)

Extract a newer bundle and run its \`upgrade.sh\`. It reuses the layout recorded
in the manifest, upgrades the package (hash-verified), and reconciles grading
and config without touching your data or overwriting your config:

\`\`\`bash
./upgrade.sh --check-install   # show installed version/layout/paths, then exit
./upgrade.sh --dry-run         # preview every change and diff
./upgrade.sh -y                # apply: keep customized graders as .new, merge config
\`\`\`

Grading: unchanged files are updated; locally-customized ones are kept with the
new version saved as \`<file>.new\`; brand-new graders are added (the manifest
baseline is advanced so the next upgrade compares correctly). Config: your
\`config.yaml\` is never overwritten — a \`config.yaml.upgraded\` candidate (your
values + new keys, comments preserved) is written for you to review and adopt.
Pass \`--state-dir DIR\` if the manifest isn't in the default location.

## Manual Install (no pip, no root)

\`\`\`bash
mkdir -p ~/pylibs
for whl in wheels/*.whl; do unzip -q -o "\$whl" -d ~/pylibs/; done
export PYTHONPATH=~/pylibs:\$PYTHONPATH
python3 -m falcon_policy_scoring --help
\`\`\`

## Integrity

\`\`\`bash
# Verify the offline wheels against the hash-pinned lockfile (done automatically
# by install.sh when pip is available):
pip install --no-index --find-links=wheels --require-hashes -r requirements.lock

# Review the CycloneDX SBOM of everything bundled:
cat sbom.cdx.json
\`\`\`

## Contents

- \`install.sh\`               — installer (writes the state manifest + activity log)
- \`uninstall.sh\`             — uninstaller (\`--purge\` to also delete config/data)
- \`upgrade.sh\`               — upgrade an existing install to this bundle's version
- \`merge_config.py\`          — helper: comment-preserving config merge for upgrade.sh
- \`falcon-policy-audit.service\` — hardened systemd unit template
- \`policy-audit.1\`            — man page (installed by install.sh; \`man policy-audit\`)
- \`readiness_map\`            — helper installed next to policy-audit (transforms host output)
- \`requirements.lock\`        — hash-pinned dependency lockfile
- \`sbom.cdx.json\`            — CycloneDX 1.5 SBOM
- \`INSTALL.md\` \`SECURITY.md\` \`SUPPORT.md\` — install, security, and support docs
- \`config/\`                  — grading definitions + example config
- \`wheels/\`:
$(ls "$BUNDLE_DIR/wheels/"*.whl 2>/dev/null | xargs -I{} basename {} | sed 's/^/  - /')

## Verify

\`\`\`bash
policy-audit --version
\`\`\`
EOF

    # Create tarball
    cd "$DIST_DIR"
    tar -czf "${BUNDLE_NAME}.tar.gz" "$BUNDLE_NAME"/
    rm -rf "$BUNDLE_DIR"

    BUNDLE_SIZE=$(du -h "${BUNDLE_NAME}.tar.gz" | cut -f1)
    echo "Created: ${DIST_DIR#"$PROJECT_DIR"/}/${BUNDLE_NAME}.tar.gz (${BUNDLE_SIZE})"
    echo ""
done

echo "=== Build complete ==="
echo ""

# Generate SHA256 checksums for all dist artifacts
echo "--- Generating checksums ---"
cd "$DIST_DIR"
shasum -a 256 ./*.whl ./*.tar.gz 2>/dev/null > SHA256SUMS
cat SHA256SUMS
echo ""

# Optionally sign the checksum file so an airgapped host can verify authenticity,
# not just integrity (a plain SHA256SUMS is trust-on-first-use). Signs when a GPG
# signing key is available; warns (does not fail) otherwise.
#   Override the key with:  GPG_SIGNING_KEY=<keyid> make airgap
if command -v gpg &>/dev/null && \
   { [ -n "${GPG_SIGNING_KEY:-}" ] || gpg --list-secret-keys &>/dev/null && [ -n "$(gpg --list-secret-keys 2>/dev/null)" ]; }; then
    echo "--- Signing SHA256SUMS (detached, ASCII) ---"
    if [ -n "${GPG_SIGNING_KEY:-}" ]; then
        gpg --batch --yes --local-user "$GPG_SIGNING_KEY" \
            --armor --detach-sign --output SHA256SUMS.asc SHA256SUMS
    else
        gpg --batch --yes --armor --detach-sign --output SHA256SUMS.asc SHA256SUMS
    fi
    echo "Signature: SHA256SUMS.asc"
    echo "Verify on target with:  gpg --verify SHA256SUMS.asc SHA256SUMS"
else
    echo "NOTE: gpg unavailable or no signing key found; skipping SHA256SUMS.asc."
    echo "      Set GPG_SIGNING_KEY=<keyid> to enable release signing."
fi
echo ""

echo "Artifacts in: $DIST_DIR/"
ls -lh "$DIST_DIR"/*.tar.gz "$DIST_DIR"/*.whl "$DIST_DIR"/SHA256SUMS "$DIST_DIR"/SHA256SUMS.asc 2>/dev/null || true
echo ""
echo "Upload to GitHub release or transfer to airgapped host."
