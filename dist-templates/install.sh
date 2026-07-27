#!/bin/bash
# falcon-policy-scoring airgap installer
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WHEEL_DIR="$SCRIPT_DIR/wheels"
MANIFEST="$SCRIPT_DIR/install.log"

# --- Argument parsing -------------------------------------------------------
# Behavior is driven entirely by flags. The only interactive moment is a single
# confirmation before installing the systemd service, which -y/--yes skips.
ASSUME_YES="no"          # -y/--yes: auto-confirm the service install
TYPE="SYSTEM"            # deployment layout: SYSTEM (FHS dirs) | WORKSPACE (a dir)
TYPE_SET="no"            # was --type given explicitly?
WORKSPACE_PATH=""        # -w/--workspace-path; defaults to ./ when TYPE=WORKSPACE
WANT_SERVICE="no"        # --service: install the hardened systemd service
SVC_USER="policyaudit"   # --service-user: account to run the service as

usage() {
    cat << USAGE
falcon-policy-scoring airgap installer

Usage: ./install.sh [OPTIONS]

Installs the tool from the bundled offline wheels, then optionally prepares a
run location and/or installs a hardened systemd service. Everything is driven
by flags — the only prompt is a confirmation before the service install, which
-y skips.

Options:
  -h, --help              Show this help and exit.

      --type TYPE         Deployment layout (default: SYSTEM):
                            SYSTEM     - system-wide paths:
                                         /etc/falcon-policy-audit (config),
                                         /var/lib/falcon-policy-audit (data),
                                         /var/log/falcon-policy-audit (logs).
                                         Requires root.
                            WORKSPACE  - a single self-contained directory
                                         (see --workspace-path).

  -w, --workspace-path PATH
                          Directory to prepare and run from (implies
                          --type WORKSPACE). Created with 'mkdir -p'; gets
                          config/, data/, logs/ and a seeded config.yaml
                          (mode 0600) with an absolute sqlite path. Defaults to
                          ./ when --type WORKSPACE is used without this flag.
                          Example:
                            --workspace-path /opt/crowdstrike-oss/falcon-policy-auditor

      --service           Install the hardened systemd service (requires root).
      --service-user NAME Service account to run as (default: policyaudit).

  -y, --yes               Auto-confirm the service install (no prompt).

Steps performed:
  1. Install wheels offline (pip --require-hashes against requirements.lock,
     or manual extraction if pip is unavailable).
  2. Install the man page (best effort).
  3. Prepare a WORKSPACE run directory (only when --type WORKSPACE or -w given).
  4. Install a hardened systemd service (only when --service given).
  5. Record every created artifact to install.log for audit and cleanup.

Examples:
  ./install.sh                                        # just install the package
  ./install.sh --workspace-path /opt/crowdstrike-oss/falcon-policy-auditor
  sudo ./install.sh --service -y                      # SYSTEM service (FHS paths)
  sudo ./install.sh --type WORKSPACE -w /opt/fpa --service -y

Uninstall with ./uninstall.sh (add --purge to also remove config/data).
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --type)
            if [ $# -lt 2 ]; then echo "Error: --type requires SYSTEM|WORKSPACE" >&2; exit 2; fi
            case "$2" in
                SYSTEM|WORKSPACE) TYPE="$2"; TYPE_SET="yes" ;;
                system|workspace) TYPE="$(echo "$2" | tr '[:lower:]' '[:upper:]')"; TYPE_SET="yes" ;;
                *) echo "Error: --type must be SYSTEM or WORKSPACE (got '$2')" >&2; exit 2 ;;
            esac
            shift 2 ;;
        -w|--workspace-path)
            if [ $# -lt 2 ]; then echo "Error: $1 requires a PATH argument" >&2; exit 2; fi
            WORKSPACE_PATH="$2"; shift 2 ;;
        --service) WANT_SERVICE="yes"; shift ;;
        --service-user)
            if [ $# -lt 2 ]; then echo "Error: --service-user requires a NAME" >&2; exit 2; fi
            SVC_USER="$2"; shift 2 ;;
        -y|--yes) ASSUME_YES="yes"; shift ;;
        *) echo "Unknown option: $1" >&2; echo "Try './install.sh --help'." >&2; exit 2 ;;
    esac
done

# Providing a workspace path implies the WORKSPACE type.
if [ -n "$WORKSPACE_PATH" ]; then
    if [ "$TYPE_SET" = "yes" ] && [ "$TYPE" = "SYSTEM" ]; then
        echo "NOTE: --workspace-path given; overriding --type SYSTEM with WORKSPACE."
    fi
    TYPE="WORKSPACE"
fi

# WORKSPACE type defaults its path to the current directory.
if [ "$TYPE" = "WORKSPACE" ] && [ -z "$WORKSPACE_PATH" ]; then
    WORKSPACE_PATH="./"
fi

# Expand a leading ~ and resolve to an absolute path (once the dir exists it is
# re-resolved; this handles the leading ~ and relative ./ up front).
if [ -n "$WORKSPACE_PATH" ]; then
    WORKSPACE_PATH="${WORKSPACE_PATH/#\~/$HOME}"
fi

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

    # Resolve the console-script path. `command -v` only works if the script dir
    # is on PATH — which is frequently NOT the case for /usr/local/bin under a
    # bare root shell. Fall back to the interpreter's script directory so we
    # always capture the real path for the manifest (and later CLI_PATH use).
    CLI_PATH=$(command -v policy-audit 2>/dev/null || true)
    if [ -z "$CLI_PATH" ]; then
        local bindir
        bindir=$($PYTHON -c 'import sysconfig; print(sysconfig.get_path("scripts") or "")' 2>/dev/null || true)
        if [ -n "$bindir" ] && [ -x "$bindir/policy-audit" ]; then
            CLI_PATH="$bindir/policy-audit"
            echo "NOTE: policy-audit installed to $bindir (not on PATH)."
            echo "      Add it to PATH:  export PATH=\"$bindir:\$PATH\""
        fi
    fi
    if [ -n "$CLI_PATH" ]; then
        manifest cli "$CLI_PATH" "pip console script"
    fi
    # Explicit success: this is the last function statement, and under `set -e`
    # a falsy final command would abort the whole installer.
    return 0
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

# --- Workspace preparation (TYPE=WORKSPACE) --------------------------------
# Prepare a single self-contained directory to run from. The grading
# definitions and example config live alongside this installer, NOT inside the
# wheel. Grading is resolved at runtime as '<dir-of-config.yaml>/grading', so we
# place config.yaml and grading/ side by side in the workspace root.
WORKSPACE=""
echo ""
if [ "$TYPE" = "WORKSPACE" ]; then
    WORKSPACE="$WORKSPACE_PATH"
    echo "Preparing workspace at: $WORKSPACE"
    mkdir -p "$WORKSPACE" "$WORKSPACE/data" "$WORKSPACE/logs"
    # Resolve to an absolute path now that it exists (so ./ and relative paths
    # become concrete in the manifest and in config.yaml's sqlite path).
    WORKSPACE="$(cd "$WORKSPACE" && pwd)"
    manifest workspace "$WORKSPACE" "workspace root"
    manifest data "$WORKSPACE/data" "workspace data dir"
    manifest logs "$WORKSPACE/logs" "workspace logs dir"

    # Copy grading definitions to <workspace>/grading (sibling of config.yaml),
    # matching how the app resolves them at runtime.
    if [ -d "$SCRIPT_DIR/config/grading" ]; then
        cp -R "$SCRIPT_DIR/config/grading" "$WORKSPACE/grading"
        manifest config-dir "$WORKSPACE/grading" "grading definitions"
    else
        echo "WARNING: bundled config/grading not found next to installer; grading unavailable."
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
    echo "  $WORKSPACE/config.yaml   (edit with your settings, mode 0600)"
    echo "  $WORKSPACE/grading/      (grading definitions)"
    echo "  $WORKSPACE/data/         (sqlite database, default datastore)"
    echo "  $WORKSPACE/logs/         (logs)"
    echo ""
    echo "Grading resolves next to config.yaml, so you can run from anywhere:"
    echo "  policy-audit -c $WORKSPACE/config.yaml fetch"
fi

# --- Optional systemd service install --------------------------------------
# Install the daemon as a sandboxed systemd service on a hardened RHEL9 host.
# Renders the bundled falcon-policy-audit.service template with concrete paths.
# Runs only when --service was given.
UNIT_TEMPLATE="$SCRIPT_DIR/falcon-policy-audit.service"
echo ""
INSTALL_SVC="n"
if [ "$WANT_SERVICE" != "yes" ]; then
    :
elif [ ! -f "$UNIT_TEMPLATE" ]; then
    echo "--service given but unit template not found next to installer; skipping."
elif ! command -v systemctl &>/dev/null; then
    echo "--service given but systemctl not found; skipping service install."
elif [ "$IS_ROOT" != "yes" ]; then
    echo "--service requires root. Re-run with sudo, or render the unit by hand:"
    echo "  $UNIT_TEMPLATE"
elif [ "$ASSUME_YES" = "yes" ]; then
    INSTALL_SVC="y"
elif [ -t 0 ]; then
    read -r -p "Install the hardened systemd service (--type $TYPE)? [y/N] " CONFIRM
    [[ "$CONFIRM" =~ ^[Yy] ]] && INSTALL_SVC="y"
else
    echo "--service given without a TTY; re-run with -y to confirm. Skipping."
fi

if [ "$INSTALL_SVC" = "y" ]; then
    # Resolve the CLI path if we didn't already capture it. Use an `if`
    # (not `test && cmd`) so a non-empty CLI_PATH doesn't make this the
    # last, falsy command under `set -e`.
    if [ -z "$CLI_PATH" ]; then
        CLI_PATH="$(command -v policy-audit 2>/dev/null || echo /usr/local/bin/policy-audit)"
    fi

    # Service paths follow the deployment --type. WORKSPACE was already prepared
    # above (its path is resolved to absolute); SYSTEM uses FHS locations.
    if [ "$TYPE" = "WORKSPACE" ]; then
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

    SVC_GROUP="$SVC_USER"

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
        # Grading definitions next to the config for SYSTEM layout (WORKSPACE
        # already placed them at <workspace>/grading via the workspace prep above).
        # Either way this resolves to '<dir-of-config.yaml>/grading', matching the app.
        if [ "$TYPE" = "SYSTEM" ] && [ -d "$SCRIPT_DIR/config/grading" ]; then
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

echo ""
echo "Install manifest written to: $MANIFEST"
echo "To remove later: ./uninstall.sh  (add --purge to also delete config/data)"
