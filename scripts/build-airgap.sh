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
    # Produced by `make man` (argparse-manpage); `make airgap` regenerates it first.
    if [ -f "$PROJECT_DIR/dist-templates/policy-audit.1" ]; then
        cp "$PROJECT_DIR/dist-templates/policy-audit.1" "$BUNDLE_DIR/policy-audit.1"
    fi

    # Bundle the install / security / support docs next to install.sh so an
    # airgapped operator has them offline. Only copy if not already present.
    for doc in INSTALL.md SECURITY.md SUPPORT.md; do
        if [ -f "$PROJECT_DIR/$doc" ] && [ ! -f "$BUNDLE_DIR/$doc" ]; then
            cp "$PROJECT_DIR/$doc" "$BUNDLE_DIR/$doc"
        fi
    done

    # Download platform-specific dependencies
    echo "Downloading dependencies for cp${PYVER} / ${PLATFORM}..."
    pip download \
        --platform "$PLATFORM" \
        --python-version "$PYVER" \
        --implementation cp \
        --abi "cp${PYVER}" \
        --only-binary=:all: \
        --dest "$BUNDLE_DIR/wheels/" \
        crowdstrike-falconpy tinydb schedule pyyaml rich python-dotenv \
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

    # Also grab pure-python fallbacks (none-any wheels)
    pip download \
        --platform any \
        --python-version "$PYVER" \
        --implementation cp \
        --abi none \
        --only-binary=:all: \
        --dest "$BUNDLE_DIR/wheels/" \
        crowdstrike-falconpy tinydb schedule pyyaml rich python-dotenv \
        2>/dev/null || true

    # Deduplicate: if both platform-specific and pure-python exist, keep both
    # (pip --find-links resolves the best match automatically)

    # Generate a hash-pinned lockfile over every downloaded wheel so the offline
    # install can run with `pip install --require-hashes`. Groups wheels by
    # (name, version) and emits all SHA256 hashes for each so pip can pick the
    # best-matching file. Covers the project wheel and every transitive dep.
    echo "Generating hash-pinned requirements.lock ..."
    python3 - "$BUNDLE_DIR/wheels" "$BUNDLE_DIR/requirements.lock" << 'LOCK_EOF'
import hashlib
import os
import sys
from collections import defaultdict

wheels_dir, out_path = sys.argv[1], sys.argv[2]
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
LOCK_EOF

    # Create install script
    cat > "$BUNDLE_DIR/install.sh" << 'INSTALL_EOF'
#!/bin/bash
# falcon-policy-scoring airgap installer
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WHEEL_DIR="$SCRIPT_DIR/wheels"
MANIFEST="$SCRIPT_DIR/install.log"

echo "=== falcon-policy-scoring Airgap Installer ==="
echo ""

# --- Install manifest -------------------------------------------------------
# Every artifact this installer creates is recorded to install.log so a cleanup
# (see uninstall.sh) or a post-install security assessment is deterministic.
# Format:  ISO8601 | CATEGORY | PATH-or-VALUE | how-it-got-there
manifest() {
    # $1=category  $2=path/value  $3=note
    printf '%s | %s | %s | %s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" "${3:-}" >> "$MANIFEST"
}

{
    echo "# falcon-policy-scoring install manifest"
    echo "# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by install.sh"
    echo "# Columns: timestamp | category | path/value | note"
} >> "$MANIFEST"

IS_ROOT="no"
[ "$(id -u)" -eq 0 ] && IS_ROOT="yes"
manifest run root="$IS_ROOT" "invoked-by=$(id -un)"

# Detect Python
PYTHON=""
for candidate in python3.12 python3.11 python3.9 python3; do
    if command -v "$candidate" &>/dev/null; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "ERROR: No python3 found in PATH"
    exit 1
fi

PYVER=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "Using: $PYTHON (Python $PYVER)"
manifest python "$(command -v "$PYTHON")" "version=$PYVER"
echo ""

INSTALL_MODE=""
CLI_PATH=""

# Prefer a hash-pinned install when the lockfile is present (supply-chain
# integrity for the offline bundle); fall back to a plain --no-index install.
pip_install() {
    if [ -f "$SCRIPT_DIR/requirements.lock" ]; then
        echo "Installing with pip (--no-index, hash-verified)..."
        if $PYTHON -m pip install --no-index --find-links="$WHEEL_DIR" \
            --require-hashes -r "$SCRIPT_DIR/requirements.lock"; then
            manifest pip-lockfile "$SCRIPT_DIR/requirements.lock" "hash-verified install"
            return 0
        fi
        echo "Hash-verified install failed; retrying without --require-hashes..."
    fi
    echo "Installing with pip (--no-index)..."
    $PYTHON -m pip install --no-index --find-links="$WHEEL_DIR" falcon-policy-scoring
}

# Record where pip actually placed the package + console script.
record_pip_layout() {
    local loc
    loc=$($PYTHON -m pip show falcon-policy-scoring 2>/dev/null \
        | awk -F': ' '/^Location:/ {print $2}')
    [ -n "$loc" ] && manifest package "$loc/falcon_policy_scoring" "pip site-packages"
    CLI_PATH=$(command -v policy-audit 2>/dev/null || true)
    [ -n "$CLI_PATH" ] && manifest cli "$CLI_PATH" "pip console script"
}

# Check if pip is available
if $PYTHON -m pip --version &>/dev/null; then
    INSTALL_MODE="pip"
    pip_install
    record_pip_layout
    echo ""
    echo "Done! Run: policy-audit --help"
elif $PYTHON -m ensurepip --help &>/dev/null; then
    INSTALL_MODE="ensurepip"
    echo "Bootstrapping pip via ensurepip..."
    $PYTHON -m ensurepip --user 2>/dev/null || $PYTHON -m ensurepip
    pip_install
    record_pip_layout
    echo ""
    echo "Done! Run: policy-audit --help"
else
    INSTALL_MODE="manual"
    echo "pip not available. Installing via manual extraction..."
    echo ""

    # Determine install location
    INSTALL_DIR="$HOME/.local/lib/python${PYVER}/site-packages"
    mkdir -p "$INSTALL_DIR"

    echo "Extracting wheels to: $INSTALL_DIR"
    for whl in "$WHEEL_DIR"/*.whl; do
        echo "  $(basename "$whl")"
        unzip -q -o "$whl" -d "$INSTALL_DIR"
    done
    manifest package "$INSTALL_DIR" "manual wheel extraction"

    # Create CLI wrapper
    BIN_DIR="$HOME/.local/bin"
    mkdir -p "$BIN_DIR"
    cat > "$BIN_DIR/policy-audit" << EOF
#!/bin/bash
export PYTHONPATH="$INSTALL_DIR:\$PYTHONPATH"
exec $PYTHON -m falcon_policy_scoring "\$@"
EOF
    chmod +x "$BIN_DIR/policy-audit"
    CLI_PATH="$BIN_DIR/policy-audit"
    manifest cli "$CLI_PATH" "manual wrapper"

    echo ""
    echo "Done!"
    echo "Ensure ~/.local/bin is in PATH:  export PATH=\$HOME/.local/bin:\$PATH"
    echo "Run: policy-audit --help"
fi
manifest mode "$INSTALL_MODE" "install method"

# --- Install the man page (best effort) ------------------------------------
# Install policy-audit.1 into the first writable man1 directory so
# `man policy-audit` works offline. Skips gracefully if none is writable.
if [ -f "$SCRIPT_DIR/policy-audit.1" ]; then
    if [ "$IS_ROOT" = "yes" ]; then
        MAN_DIR="/usr/local/share/man/man1"
    else
        MAN_DIR="$HOME/.local/share/man/man1"
    fi
    if mkdir -p "$MAN_DIR" 2>/dev/null && [ -w "$MAN_DIR" ]; then
        cp "$SCRIPT_DIR/policy-audit.1" "$MAN_DIR/policy-audit.1"
        chmod 644 "$MAN_DIR/policy-audit.1" 2>/dev/null || true
        manifest man "$MAN_DIR/policy-audit.1" "man page installed"
        echo "Installed man page: $MAN_DIR/policy-audit.1  (try: man policy-audit)"
        # Non-root man dirs are often not on MANPATH by default.
        if [ "$IS_ROOT" != "yes" ]; then
            echo "  If 'man policy-audit' isn't found, add to MANPATH:"
            echo "    export MANPATH=\"\$HOME/.local/share/man:\$MANPATH\""
        fi
    else
        echo "NOTE: no writable man1 dir; skipping man page install."
        echo "      View it directly with:  man $SCRIPT_DIR/policy-audit.1"
    fi
fi

# Rewrite the sqlite datastore path in a seeded config to an ABSOLUTE path under
# the given data dir. The example config uses a relative './data/db.sqlite',
# which resolves against the process CWD — unsafe for a service (the systemd
# sandbox only permits writes under ReadWritePaths). An absolute path in the
# writable data dir avoids the daemon failing to open its DB.
set_sqlite_path() {
    # $1=config file  $2=data dir
    local cfg="$1" data_dir="$2"
    [ -f "$cfg" ] || return 0
    if grep -qE '^[[:space:]]*path:[[:space:]]*\./data/db\.sqlite' "$cfg"; then
        sed -i -E "s#^([[:space:]]*)path:[[:space:]]*\./data/db\.sqlite.*#\1path: ${data_dir}/db.sqlite#" "$cfg"
        manifest sqlite-path "${data_dir}/db.sqlite" "absolute path set in $cfg"
    fi
}

# --- Optional workspace preparation ---------------------------------------
# The grading definitions (config/grading/*.json) and example config live
# alongside this installer, NOT inside the wheel. The tool reads them relative
# to the current working directory, so prep a workspace to run from.
WORKSPACE=""
echo ""
if [ -t 0 ]; then
    read -r -p "Prepare a workspace directory for running the tool? [y/N] " PREP_WS
else
    PREP_WS="n"
    echo "Non-interactive shell detected; skipping workspace prep."
fi

if [[ "$PREP_WS" =~ ^[Yy] ]]; then
    echo "NOTE: If you plan to run this as a systemd service, do NOT place the"
    echo "      workspace under /home or /root — the hardened unit sets"
    echo "      ProtectHome=yes, which hides those paths from the service."
    echo "      Use /opt, /srv, or /var/lib instead (e.g. /opt/falcon-policy-audit)."
    read -r -p "Full path to use as the workspace: " WORKSPACE
    # Expand a leading ~ to the user's home directory
    WORKSPACE="${WORKSPACE/#\~/$HOME}"

    if [ -z "$WORKSPACE" ]; then
        echo "No path provided; skipping workspace prep."
    else
        echo "Preparing workspace at: $WORKSPACE"
        mkdir -p "$WORKSPACE"
        mkdir -p "$WORKSPACE/data"
        mkdir -p "$WORKSPACE/logs"
        manifest workspace "$WORKSPACE" "workspace root"
        manifest data "$WORKSPACE/data" "workspace data dir"
        manifest logs "$WORKSPACE/logs" "workspace logs dir"

        # Copy grading configs so 'config/grading/*.json' resolves at runtime
        if [ -d "$SCRIPT_DIR/config" ]; then
            cp -R "$SCRIPT_DIR/config" "$WORKSPACE/config"
            manifest config-dir "$WORKSPACE/config" "grading definitions"
        else
            echo "WARNING: bundled config/ not found next to installer; gradings unavailable."
        fi

        # Seed a config.yaml from the example if one isn't already present.
        # It holds API credentials, so lock it to owner-only (0600).
        if [ -f "$SCRIPT_DIR/config/example.config.yaml" ]; then
            if [ -f "$WORKSPACE/config.yaml" ]; then
                echo "Existing $WORKSPACE/config.yaml left untouched."
            else
                cp "$SCRIPT_DIR/config/example.config.yaml" "$WORKSPACE/config.yaml"
                chmod 600 "$WORKSPACE/config.yaml"
                # Pin the sqlite DB to an absolute path in the workspace data dir.
                set_sqlite_path "$WORKSPACE/config.yaml" "$WORKSPACE/data"
                manifest config "$WORKSPACE/config.yaml" "seeded from example, chmod 600"
            fi
        fi

        echo ""
        echo "Workspace ready:"
        echo "  $WORKSPACE/config.yaml     (edit with your settings, mode 0600)"
        echo "  $WORKSPACE/config/grading/ (grading definitions)"
        echo "  $WORKSPACE/data/           (sqlite database, default datastore)"
        echo "  $WORKSPACE/logs/           (logs)"
        echo ""
        echo "Run the tool from the workspace so relative paths resolve:"
        echo "  cd $WORKSPACE && policy-audit -c config.yaml fetch"
    fi
fi

# --- Optional systemd service install --------------------------------------
# Install the daemon as a sandboxed systemd service on a hardened RHEL9 host.
# Renders the bundled falcon-policy-audit.service template with concrete paths.
UNIT_TEMPLATE="$SCRIPT_DIR/falcon-policy-audit.service"
echo ""
if [ -t 0 ] && [ -f "$UNIT_TEMPLATE" ] && command -v systemctl &>/dev/null; then
    read -r -p "Install the daemon as a systemd service? [y/N] " INSTALL_SVC
else
    INSTALL_SVC="n"
    if [ ! -f "$UNIT_TEMPLATE" ]; then
        :
    elif ! command -v systemctl &>/dev/null; then
        echo "systemctl not found; skipping service install."
    fi
fi

if [[ "$INSTALL_SVC" =~ ^[Yy] ]]; then
    if [ "$IS_ROOT" != "yes" ]; then
        echo "Service install requires root. Re-run install.sh with sudo, or install"
        echo "the unit by hand from: $UNIT_TEMPLATE"
    else
        # Resolve the CLI path if we didn't already capture it.
        [ -z "$CLI_PATH" ] && CLI_PATH="$(command -v policy-audit 2>/dev/null || echo /usr/local/bin/policy-audit)"

        echo "Choose a layout for the service:"
        echo "  1) FHS  - /etc/falcon-policy-audit, /var/lib/..., /var/log/..."
        echo "  2) Workspace - use a single directory"
        read -r -p "Layout [1/2]: " LAYOUT

        if [ "$LAYOUT" = "2" ]; then
            if [ -z "$WORKSPACE" ]; then
                echo "NOTE: Do NOT use a path under /home or /root for a service"
                echo "      workspace — the unit sets ProtectHome=yes. Use /opt,"
                echo "      /srv, or /var/lib (e.g. /opt/falcon-policy-audit)."
                read -r -p "Full path to the workspace directory: " WORKSPACE
                WORKSPACE="${WORKSPACE/#\~/$HOME}"
            fi
            SVC_CONFIG="$WORKSPACE/config.yaml"
            SVC_DATA="$WORKSPACE/data"
            SVC_OUTPUT="$WORKSPACE/output"
            SVC_LOGS="$WORKSPACE/logs"
        else
            SVC_CONFIG="/etc/falcon-policy-audit/config.yaml"
            SVC_DATA="/var/lib/falcon-policy-audit"
            SVC_OUTPUT="/var/lib/falcon-policy-audit/output"
            SVC_LOGS="/var/log/falcon-policy-audit"
        fi

        SVC_USER="policyaudit"
        SVC_GROUP="policyaudit"

        # Create the service account if it doesn't exist.
        if ! id "$SVC_USER" &>/dev/null; then
            useradd -r -s /sbin/nologin -c "Falcon Policy Audit" "$SVC_USER"
            manifest user "$SVC_USER" "created system account"
            echo "Created system user: $SVC_USER"
        else
            manifest user "$SVC_USER" "pre-existing (not created)"
        fi

        # Create dirs and seed config.
        mkdir -p "$(dirname "$SVC_CONFIG")" "$SVC_DATA" "$SVC_OUTPUT" "$SVC_LOGS"
        manifest data "$SVC_DATA" "service data dir"
        manifest output "$SVC_OUTPUT" "service output dir"
        manifest logs "$SVC_LOGS" "service logs dir"

        if [ ! -f "$SVC_CONFIG" ]; then
            if [ -f "$SCRIPT_DIR/config/example.config.yaml" ]; then
                cp "$SCRIPT_DIR/config/example.config.yaml" "$SVC_CONFIG"
            fi
            chmod 600 "$SVC_CONFIG" 2>/dev/null || true
            # Pin the sqlite DB to an absolute path in the writable data dir so
            # the daemon can open it under the ProtectSystem/ReadWritePaths sandbox.
            set_sqlite_path "$SVC_CONFIG" "$SVC_DATA"
            manifest config "$SVC_CONFIG" "seeded from example, chmod 600"
        fi
        # Grading definitions next to the config for FHS layout.
        if [ "$LAYOUT" != "2" ] && [ -d "$SCRIPT_DIR/config/grading" ]; then
            cp -R "$SCRIPT_DIR/config/grading" "$(dirname "$SVC_CONFIG")/grading"
            manifest config-dir "$(dirname "$SVC_CONFIG")/grading" "grading definitions"
        fi

        chown -R "$SVC_USER:$SVC_GROUP" "$SVC_DATA" "$SVC_OUTPUT" "$SVC_LOGS"
        chown "$SVC_USER:$SVC_GROUP" "$SVC_CONFIG" 2>/dev/null || true

        # Render the unit template.
        UNIT_DEST="/etc/systemd/system/falcon-policy-audit.service"
        sed -e "s|@EXEC@|$CLI_PATH|g" \
            -e "s|@CONFIG@|$SVC_CONFIG|g" \
            -e "s|@OUTPUT@|$SVC_OUTPUT|g" \
            -e "s|@DATA@|$SVC_DATA|g" \
            -e "s|@LOGS@|$SVC_LOGS|g" \
            -e "s|@USER@|$SVC_USER|g" \
            -e "s|@GROUP@|$SVC_GROUP|g" \
            "$UNIT_TEMPLATE" > "$UNIT_DEST"
        chmod 644 "$UNIT_DEST"
        manifest systemd-unit "$UNIT_DEST" "rendered from template"

        systemctl daemon-reload
        echo ""
        echo "Service installed: $UNIT_DEST"
        echo ""
        echo "=== IMPORTANT: validate by hand BEFORE enabling the daemon ==="
        echo ""
        echo "1. Edit credentials and settings in:"
        echo "     $SVC_CONFIG"
        echo ""
        echo "2. Do a one-shot fetch AS THE SERVICE USER ($SVC_USER) so it exercises"
        echo "   the same config and proves API keys, DNS, and read/write access work."
        echo "   Running it as the service user (not root) is critical: a root-run"
        echo "   fetch would create root-owned files in $SVC_DATA that the daemon"
        echo "   (running as $SVC_USER) could not later update."
        echo ""
        echo "     sudo -u $SVC_USER $CLI_PATH -c $SVC_CONFIG fetch"
        echo ""
        echo "   Confirm it completes without auth/DNS/permission errors and that"
        echo "   the sqlite DB and output were written under $SVC_DATA."
        echo ""
        echo "3. If step 2 succeeded, re-assert ownership (in case anything was"
        echo "   created by another user) and enable the service:"
        echo ""
        echo "     sudo chown -R $SVC_USER:$SVC_GROUP $SVC_DATA $SVC_OUTPUT $SVC_LOGS"
        echo "     sudo systemctl enable --now falcon-policy-audit"
        echo ""
        echo "4. Verify health and sandboxing:"
        echo "     systemctl status falcon-policy-audit"
        echo "     journalctl -u falcon-policy-audit -f"
        echo "     systemd-analyze security falcon-policy-audit"
    fi
elif [ -f "$UNIT_TEMPLATE" ]; then
    echo "systemd unit template available at: $UNIT_TEMPLATE"
    echo "Render its @PLACEHOLDER@ tokens and copy to /etc/systemd/system/ to run as a service."
fi

echo ""
echo "Install manifest written to: $MANIFEST"
echo "To remove later: ./uninstall.sh  (add --purge to also delete config/data)"
INSTALL_EOF
    chmod +x "$BUNDLE_DIR/install.sh"

    # Create uninstall script
    cat > "$BUNDLE_DIR/uninstall.sh" << 'UNINSTALL_EOF'
#!/bin/bash
# falcon-policy-scoring airgap uninstaller
#
# Default: removes the Python package, CLI wrapper, systemd unit, and the
#          service account (if this bundle's installer created it). Leaves
#          config, data, and logs intact.
# --purge: additionally deletes config files, data dir, and output dir, leaving
#          only uninstall.sh and uninstall.log behind.
# --yes:   don't prompt for confirmation.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$SCRIPT_DIR/install.log"
UNINSTALL_LOG="$SCRIPT_DIR/uninstall.log"

PURGE="no"
ASSUME_YES="no"
for arg in "$@"; do
    case "$arg" in
        --purge) PURGE="yes" ;;
        --yes|-y) ASSUME_YES="yes" ;;
        --help|-h)
            echo "Usage: $0 [--purge] [--yes]"
            echo "  --purge  also delete config, data, and output"
            echo "  --yes    skip confirmation prompt"
            exit 0
            ;;
        *) echo "Unknown option: $arg"; exit 1 ;;
    esac
done

log() {
    # $1=action  $2=path/value  $3=result
    printf '%s | %s | %s | %s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" "${3:-}" >> "$UNINSTALL_LOG"
}

{
    echo "# falcon-policy-scoring uninstall log"
    echo "# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by uninstall.sh (purge=$PURGE)"
    echo "# Columns: timestamp | action | path/value | result"
} >> "$UNINSTALL_LOG"

echo "=== falcon-policy-scoring Uninstaller ==="
if [ -f "$MANIFEST" ]; then
    echo "Reading install manifest: $MANIFEST"
else
    echo "No install.log found; falling back to pip uninstall + known defaults."
fi
echo ""

# Pull values out of the manifest (last occurrence wins).
manifest_val() {
    # $1=category -> prints the path/value column of the last matching line
    [ -f "$MANIFEST" ] || return 0
    awk -F' \\| ' -v cat="$1" '$2==cat {v=$3} END {if (v) print v}' "$MANIFEST"
}
manifest_note() {
    [ -f "$MANIFEST" ] || return 0
    awk -F' \\| ' -v cat="$1" '$2==cat {v=$4} END {if (v) print v}' "$MANIFEST"
}

SVC_UNIT="$(manifest_val systemd-unit)"
SVC_USER="$(manifest_val user)"
SVC_USER_NOTE="$(manifest_note user)"
CLI_PATH="$(manifest_val cli)"
MAN_PATH="$(manifest_val man)"
PKG_PATH="$(manifest_val package)"
CONFIG_FILE="$(manifest_val config)"
CONFIG_DIRS="$(awk -F' \\| ' '$2=="config-dir" {print $3}' "$MANIFEST" 2>/dev/null || true)"
DATA_DIRS="$(awk -F' \\| ' '$2=="data" {print $3}' "$MANIFEST" 2>/dev/null || true)"
OUTPUT_DIRS="$(awk -F' \\| ' '$2=="output" {print $3}' "$MANIFEST" 2>/dev/null || true)"
LOG_DIRS="$(awk -F' \\| ' '$2=="logs" {print $3}' "$MANIFEST" 2>/dev/null || true)"

echo "Will remove:"
[ -n "$SVC_UNIT" ] && echo "  systemd unit : $SVC_UNIT"
[ -n "$CLI_PATH" ]  && echo "  CLI wrapper  : $CLI_PATH"
[ -n "$MAN_PATH" ]  && echo "  man page     : $MAN_PATH"
echo "  Python package (pip uninstall or $PKG_PATH)"
if [ "$SVC_USER_NOTE" = "created system account" ] && [ -n "$SVC_USER" ]; then
    echo "  service user : $SVC_USER"
fi
if [ "$PURGE" = "yes" ]; then
    echo "Will PURGE (delete):"
    [ -n "$CONFIG_FILE" ] && echo "  config file  : $CONFIG_FILE"
    [ -n "$CONFIG_DIRS" ] && echo "  config dirs  : $CONFIG_DIRS"
    [ -n "$DATA_DIRS" ]   && echo "  data dirs    : $DATA_DIRS"
    [ -n "$OUTPUT_DIRS" ] && echo "  output dirs  : $OUTPUT_DIRS"
    echo "  (config/data/output removed; uninstall.sh + uninstall.log kept)"
else
    echo "Config, data, and logs will be LEFT IN PLACE (use --purge to delete)."
fi
echo ""

if [ "$ASSUME_YES" != "yes" ]; then
    if [ -t 0 ]; then
        read -r -p "Proceed? [y/N] " CONFIRM
        [[ "$CONFIRM" =~ ^[Yy] ]] || { echo "Aborted."; exit 0; }
    else
        echo "Non-interactive and --yes not given; aborting."
        exit 1
    fi
fi

# Detect python for pip uninstall.
PYTHON=""
for candidate in python3.12 python3.11 python3.9 python3; do
    command -v "$candidate" &>/dev/null && { PYTHON="$candidate"; break; }
done

# 1. Stop + remove systemd unit.
if [ -n "$SVC_UNIT" ] && command -v systemctl &>/dev/null; then
    systemctl disable --now falcon-policy-audit 2>/dev/null || true
    if rm -f "$SVC_UNIT" 2>/dev/null; then
        systemctl daemon-reload 2>/dev/null || true
        echo "Removed systemd unit: $SVC_UNIT"
        log remove-unit "$SVC_UNIT" "ok"
    else
        log remove-unit "$SVC_UNIT" "failed-or-missing"
    fi
fi

# 2. Uninstall Python package.
if [ -n "$PYTHON" ] && $PYTHON -m pip show falcon-policy-scoring &>/dev/null; then
    $PYTHON -m pip uninstall -y falcon-policy-scoring 2>/dev/null \
        && log remove-package "pip" "uninstalled" \
        || log remove-package "pip" "failed"
    echo "Uninstalled Python package via pip."
elif [ -n "$PKG_PATH" ] && [ -d "$PKG_PATH" ]; then
    # Manual extraction mode: remove only our package tree, not all of site-packages.
    rm -rf "$PKG_PATH/falcon_policy_scoring" 2>/dev/null || true
    echo "Removed extracted package: $PKG_PATH/falcon_policy_scoring"
    log remove-package "$PKG_PATH/falcon_policy_scoring" "removed"
fi

# 3. Remove CLI wrapper.
if [ -n "$CLI_PATH" ] && [ -f "$CLI_PATH" ]; then
    rm -f "$CLI_PATH" 2>/dev/null \
        && { echo "Removed CLI wrapper: $CLI_PATH"; log remove-cli "$CLI_PATH" "ok"; } \
        || log remove-cli "$CLI_PATH" "failed"
fi

# 3b. Remove man page.
if [ -n "$MAN_PATH" ] && [ -f "$MAN_PATH" ]; then
    rm -f "$MAN_PATH" 2>/dev/null \
        && { echo "Removed man page: $MAN_PATH"; log remove-man "$MAN_PATH" "ok"; } \
        || log remove-man "$MAN_PATH" "failed"
fi

# 4. Remove the service account only if this bundle created it.
if [ "$SVC_USER_NOTE" = "created system account" ] && [ -n "$SVC_USER" ]; then
    if id "$SVC_USER" &>/dev/null && command -v userdel &>/dev/null; then
        userdel "$SVC_USER" 2>/dev/null \
            && { echo "Removed service user: $SVC_USER"; log remove-user "$SVC_USER" "ok"; } \
            || log remove-user "$SVC_USER" "failed (may need root)"
    fi
fi

# 5. Purge config/data/output if requested.
if [ "$PURGE" = "yes" ]; then
    purge_path() {
        [ -z "$1" ] && return 0
        if [ -e "$1" ]; then
            rm -rf "$1" 2>/dev/null \
                && { echo "Purged: $1"; log purge "$1" "deleted"; } \
                || log purge "$1" "failed"
        fi
    }
    purge_path "$CONFIG_FILE"
    for d in $CONFIG_DIRS; do purge_path "$d"; done
    for d in $DATA_DIRS;   do purge_path "$d"; done
    for d in $OUTPUT_DIRS; do purge_path "$d"; done
    echo ""
    echo "Purge complete. Only uninstall.sh and uninstall.log remain of the deployment."
else
    echo ""
    echo "Uninstall complete. Config, data, and logs were left in place."
fi

echo "Uninstall log written to: $UNINSTALL_LOG"
UNINSTALL_EOF
    chmod +x "$BUNDLE_DIR/uninstall.sh"

    # Generate CycloneDX SBOM from the bundled wheels
    echo "Generating SBOM (CycloneDX)..."
    python3 -c "
import json, zipfile, email.parser, os, datetime

wheels_dir = '$BUNDLE_DIR/wheels'
components = []
for fname in sorted(os.listdir(wheels_dir)):
    if not fname.endswith('.whl'):
        continue
    whl_path = os.path.join(wheels_dir, fname)
    with zipfile.ZipFile(whl_path) as zf:
        metadata_files = [n for n in zf.namelist() if n.endswith('/METADATA')]
        if not metadata_files:
            continue
        with zf.open(metadata_files[0]) as mf:
            meta = email.parser.BytesParser().parsebytes(mf.read())
    name = meta.get('Name', '')
    version = meta.get('Version', '')
    purl = f'pkg:pypi/{name.lower().replace(\"-\", \"-\")}@{version}'
    component = {
        'type': 'library',
        'name': name,
        'version': version,
        'purl': purl,
        'bom-ref': purl,
    }
    license_val = meta.get('License-Expression') or ''
    if not license_val or len(license_val) > 80:
        # Fallback: try Classifier for SPDX-style short identifiers
        classifiers = meta.get_all('Classifier') or []
        for c in classifiers:
            if c.startswith('License :: OSI Approved ::'):
                license_val = c.split('::')[-1].strip()
                break
    if not license_val:
        license_val = meta.get('License', '')
    if license_val and license_val.strip() and license_val.strip() != 'UNKNOWN':
        # Truncate full license texts to just the first line (likely the name)
        short = license_val.strip().split('\\n')[0].strip()
        if len(short) <= 80:
            component['licenses'] = [{'expression': short}]
        else:
            component['licenses'] = [{'license': {'name': short[:200]}}]
    author = meta.get('Author') or meta.get('Author-email', '')
    if author:
        component['author'] = author
    # Add the wheel filename as evidence of what's bundled
    component['evidence'] = {'identity': {'field': 'filename', 'methods': [{'technique': 'filename', 'value': fname}]}}
    components.append(component)

sbom = {
    '\$schema': 'http://cyclonedx.org/schema/bom-1.5.schema.json',
    'bomFormat': 'CycloneDX',
    'specVersion': '1.5',
    'version': 1,
    'metadata': {
        'timestamp': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'component': {
            'type': 'application',
            'name': 'falcon-policy-scoring',
            'version': '$VERSION',
            'purl': 'pkg:pypi/falcon-policy-scoring@$VERSION',
            'bom-ref': 'pkg:pypi/falcon-policy-scoring@$VERSION',
        },
        'tools': [{'name': 'build-airgap.sh', 'version': '$VERSION'}],
    },
    'components': components,
}

with open('$BUNDLE_DIR/sbom.cdx.json', 'w') as f:
    json.dump(sbom, f, indent=2)
print(f'  {len(components)} components in sbom.cdx.json')
"

    # Create README
    cat > "$BUNDLE_DIR/README.md" << EOF
# falcon-policy-scoring v${VERSION} — Airgap Bundle

**Target:** RHEL 9 x86_64, Python ${PYVER_DOT}

## Quick Install

\`\`\`bash
chmod +x install.sh
./install.sh
\`\`\`

The installer offers to prepare a **workspace** directory. If you accept, it
creates \`<workspace>/{config,data,logs}\`, copies the grading definitions into
\`<workspace>/config/grading/\`, and seeds \`<workspace>/config.yaml\` (mode 0600)
from the example. Run the tool from that workspace so relative paths resolve:

\`\`\`bash
cd <workspace> && policy-audit -c config.yaml fetch
\`\`\`

The installer also offers to install the daemon as a **hardened systemd
service** (see \`falcon-policy-audit.service\`) and records every artifact it
creates to \`install.log\`.

## Run as a systemd service (hardened RHEL9)

\`\`\`bash
sudo ./install.sh          # answer 'y' to the systemd prompt, pick a layout
sudo systemctl enable --now falcon-policy-audit
systemd-analyze security falcon-policy-audit   # verify the sandbox
\`\`\`

## Uninstall

\`\`\`bash
./uninstall.sh             # remove package/CLI/unit/user; keep config + data
./uninstall.sh --purge     # also delete config, data, and output
\`\`\`

\`uninstall.sh\` reads \`install.log\` to know exactly what to remove and writes
\`uninstall.log\` for audit.

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

- \`install.sh\`               — installer (writes install.log)
- \`uninstall.sh\`             — uninstaller (\`--purge\` to also delete config/data)
- \`falcon-policy-audit.service\` — hardened systemd unit template
- \`policy-audit.1\`            — man page (installed by install.sh; \`man policy-audit\`)
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
