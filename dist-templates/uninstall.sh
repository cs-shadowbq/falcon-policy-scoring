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
