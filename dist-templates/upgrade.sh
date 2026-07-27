#!/bin/bash
# falcon-policy-scoring airgap upgrader
#
# Upgrades an existing airgap install to the version in THIS bundle. It reuses
# the layout recorded in the state manifest (<app>.manifest) written by
# install.sh, so paths are not re-guessed.
#
#   Package  : pip --upgrade from the bundled wheels (hash-verified). Replaced.
#   Runtime  : data/, logs/, output/, the sqlite DB are NEVER touched.
#   Grading  : 3-way reconcile (on-disk vs manifest baseline vs new bundle):
#              - unchanged locally      -> updated in place when upstream changed
#              - customized locally     -> kept; new version written as <file>.new
#              - brand-new grader       -> installed
#              After any update/add/replace the manifest baseline hash is
#              advanced, so the NEXT upgrade compares correctly.
#   config   : never overwritten. A merged candidate (config.yaml.upgraded) is
#              produced via ruamel (keeps your values + comments, adds new keys),
#              plus example.config.yaml is refreshed as the reference.
#
# State (paths, baseline hashes) is read from and written to <app>.manifest.
# Human-readable activity is appended to the shared <app>-installation.log.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WHEEL_DIR="$SCRIPT_DIR/wheels"
APP_NAME="falcon-policy-audit"
# Manifest schema this script understands. It compares MAJOR against the
# manifest's 'manifest-schema' entry and refuses on mismatch (a 1.8.1-era or
# future 2.x manifest has a different shape).
MANIFEST_SCHEMA="1.0.0"
MANIFEST=""   # resolved after arg parsing
LOGFILE=""

ASSUME_YES="no"
DRY_RUN="no"
FORCE_CONFIG="no"
FORCE_GRADING="no"
STATE_DIR_ARG=""
CHECK_ONLY="no"

usage() {
    cat << USAGE
falcon-policy-scoring airgap upgrader

Usage: ./upgrade.sh [OPTIONS]

Upgrades an existing install to this bundle's version. Reads the state manifest
($APP_NAME.manifest) to reuse the original layout. Never touches your data,
logs, or database.

Options:
  -h, --help          Show this help and exit.
      --check-install Print the current install state (version, layout, paths,
                      service, grading status) and the version this bundle would
                      upgrade to, then exit WITHOUT changing anything.
  -y, --yes           Confirm the upgrade non-interactively (required to apply
                      changes without a TTY). Also auto-resolves grading
                      conflicts by keeping your file and writing <file>.new.
      --dry-run       Show every action/diff but change nothing (no confirm).
      --force-grading Replace grading files with this bundle's versions,
                      backing up any customized file as <file>.bak.
      --force-config  Adopt the merged config candidate as the live config.yaml,
                      backing up the current one as config.yaml.bak.
      --state-dir DIR Directory holding $APP_NAME.manifest (else searched:
                      /var/log/$APP_NAME, then ~/.config/$APP_NAME, then here).
                      --log-dir is accepted as an alias.

Before applying, upgrade.sh shows the current install state and the version
transition (e.g. 1.9.0 -> 2.3.0) and asks to confirm (skip the prompt with -y).

Grading conflicts (interactive) prompt per file: keep / replace / write .new.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --check-install) CHECK_ONLY="yes"; shift ;;
        -y|--yes) ASSUME_YES="yes"; shift ;;
        --dry-run) DRY_RUN="yes"; shift ;;
        --force-grading) FORCE_GRADING="yes"; shift ;;
        --force-config) FORCE_CONFIG="yes"; shift ;;
        --state-dir|--log-dir)
            if [ $# -lt 2 ]; then echo "Error: $1 requires a DIR" >&2; exit 2; fi
            STATE_DIR_ARG="$2"; shift 2 ;;
        --state-dir=*|--log-dir=*) STATE_DIR_ARG="${1#*=}"; shift ;;
        *) echo "Unknown option: $1" >&2; echo "Try './upgrade.sh --help'." >&2; exit 2 ;;
    esac
done
[ -n "$STATE_DIR_ARG" ] && STATE_DIR_ARG="${STATE_DIR_ARG/#\~/$HOME}"

echo "=== falcon-policy-scoring Airgap Upgrader ==="
echo ""

# --- Locate the state manifest ----------------------------------------------
# Search order: explicit --state-dir, then the SYSTEM state dir, then the
# per-user XDG dir, then next to this script (back-compat).
STATE_DIR=""
for d in \
    "${STATE_DIR_ARG:-}" \
    "/var/log/$APP_NAME" \
    "${XDG_CONFIG_HOME:-$HOME/.config}/$APP_NAME" \
    "$SCRIPT_DIR"; do
    [ -n "$d" ] || continue
    if [ -f "$d/$APP_NAME.manifest" ]; then
        STATE_DIR="$d"
        MANIFEST="$d/$APP_NAME.manifest"
        break
    fi
done

if [ -z "$MANIFEST" ]; then
    echo "ERROR: no $APP_NAME.manifest found (searched --state-dir, /var/log/$APP_NAME," >&2
    echo "       ~/.config/$APP_NAME, and this script's dir). upgrade.sh needs the state" >&2
    echo "       manifest written by install.sh. If this is a fresh host, run" >&2
    echo "       ./install.sh instead, or pass --state-dir DIR." >&2
    exit 1
fi
LOGFILE="$STATE_DIR/$APP_NAME-installation.log"
echo "Using state manifest: $MANIFEST"

# --- Append-only activity log (syslog-style, tagged, never rewritten) -------
LOG_HOST="${HOSTNAME:-$(uname -n 2>/dev/null || echo localhost)}"
logline() {
    printf '%s %s %s/upgrade.sh[%s]: %s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$LOG_HOST" "$APP_NAME" "$$" "$1" >> "$LOGFILE"
}

sha256_of() {
    if command -v sha256sum &>/dev/null; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# Manifest state accessors: CATEGORY | KEY | VALUE.
mval() {
    # $1=category -> KEY column of the last matching line (path-keyed entries)
    awk -F' \\| ' -v c="$1" '$1==c {v=$2} END {if (v) print v}' "$MANIFEST"
}
mvalue() {
    # $1=category -> VALUE column of the last matching line (singleton entries
    # stored as 'category | - | value', e.g. type / version / mode).
    awk -F' \\| ' -v c="$1" '$1==c {v=$3} END {if (v) print v}' "$MANIFEST"
}
recorded_hash() {
    # $1=category  $2=key -> VALUE column for that (category,key)
    awk -F' \\| ' -v c="$1" -v k="$2" '$1==c && $2==k {v=$3} END {if (v) print v}' "$MANIFEST"
}
# Upsert a (category,key)=value into the manifest (advances baselines etc.).
mset() {
    local cat="$1" key="$2" val="${3:-}"
    awk -F' \\| ' -v c="$cat" -v k="$key" '!($1==c && $2==k)' "$MANIFEST" \
        > "$MANIFEST.tmp" && mv "$MANIFEST.tmp" "$MANIFEST"
    printf '%s | %s | %s\n' "$cat" "$key" "$val" >> "$MANIFEST"
}

# --- Manifest schema compatibility ------------------------------------------
# Refuse to operate on a manifest whose MAJOR schema differs from what this
# script understands (e.g. a 1.8.1-era or future 2.x layout) rather than
# misparsing it. A missing entry means a pre-schema 1.0 manifest -> compatible.
FOUND_SCHEMA="$(mvalue manifest-schema)"
[ -z "$FOUND_SCHEMA" ] && FOUND_SCHEMA="1.0.0"
if [ "${FOUND_SCHEMA%%.*}" != "${MANIFEST_SCHEMA%%.*}" ]; then
    echo "ERROR: manifest schema $FOUND_SCHEMA is incompatible with this upgrader" >&2
    echo "       (understands ${MANIFEST_SCHEMA%%.*}.x). Use the upgrade.sh from a" >&2
    echo "       bundle matching the installed major version." >&2
    logline "aborted: incompatible manifest schema $FOUND_SCHEMA (want ${MANIFEST_SCHEMA%%.*}.x)"
    exit 4
fi

# --- Detect Python (same probe order as install.sh) ------------------------
PYTHON=""
for candidate in python3.12 python3.11 python3.9 python3; do
    command -v "$candidate" &>/dev/null && { PYTHON="$candidate"; break; }
done
[ -z "$PYTHON" ] && { echo "ERROR: no python3 found in PATH" >&2; exit 1; }

# --- Discover the existing install from the manifest ------------------------
CONFIG_FILE="$(mval config)"
GRADING_DIR="$(mval grading-dir)"
# Fall back to the app's resolution rule if grading-dir wasn't recorded.
if [ -z "$GRADING_DIR" ] && [ -n "$CONFIG_FILE" ]; then
    GRADING_DIR="$(dirname "$CONFIG_FILE")/grading"
fi
SVC_UNIT="$(mval systemd-unit)"
SVC_USER="$(mval user)"
INSTALL_TYPE="$(mvalue type)"
CLI_PATH="$(mval cli)"
MAN_PATH="$(mval man)"
PKG_PATH="$(mval package)"
MANIFEST_VER="$(mvalue version)"

# --- Version resolution -----------------------------------------------------
# CUR_VER is the AUTHORITATIVE installed version (pip), which may differ from
# the manifest's record — e.g. running a 2.3 bundle's --check-install on top of
# a 1.9 install. NEW_VER is what THIS bundle would install.
NEW_WHEEL="$(find "$WHEEL_DIR" -maxdepth 1 -name 'falcon_policy_scoring-*.whl' -print 2>/dev/null | head -1)"
NEW_VER="unknown"
if [ -n "$NEW_WHEEL" ]; then
    NEW_VER="$(basename "$NEW_WHEEL" | awk -F- '{print $2}')"
fi
CUR_VER="$($PYTHON -m pip show falcon-policy-scoring 2>/dev/null | awk -F': ' '/^Version:/ {print $2}')"

# Count grading files and how many are locally customized (on-disk hash differs
# from the manifest baseline). Purely informational for the state summary.
grading_stats() {
    GRADING_TOTAL=0
    GRADING_CUSTOM=0
    [ -n "$GRADING_DIR" ] && [ -d "$GRADING_DIR" ] || return 0
    local f base cur inst
    for f in "$GRADING_DIR"/*.json; do
        [ -f "$f" ] || continue
        GRADING_TOTAL=$((GRADING_TOTAL + 1))
        cur="$(sha256_of "$f")"
        inst="$(recorded_hash grading-hash "$f")"
        if [ -n "$inst" ] && [ "$cur" != "$inst" ]; then
            GRADING_CUSTOM=$((GRADING_CUSTOM + 1))
        fi
    done
}

# Human-readable summary of the CURRENT install, derived from the manifest +
# live pip/systemd state. Safe to call read-only (used by --check-install too).
print_install_state() {
    grading_stats
    echo "Current install (from manifest: $MANIFEST):"
    # Show the manifest-recorded version only when it DIFFERS from pip's answer
    # (a drift signal); pip is authoritative for what is actually installed.
    local ver_note=""
    if [ -n "$MANIFEST_VER" ] && [ "$MANIFEST_VER" != "$CUR_VER" ]; then
        ver_note="   (manifest recorded: $MANIFEST_VER)"
    fi
    echo "  installed version : ${CUR_VER:-<not installed>}${ver_note}"
    echo "  deployment type   : ${INSTALL_TYPE:-<unknown>}"
    echo "  config            : ${CONFIG_FILE:-<unknown>}"
    if [ -n "$GRADING_DIR" ]; then
        echo "  grading dir       : $GRADING_DIR ($GRADING_TOTAL file(s), $GRADING_CUSTOM locally customized)"
    else
        echo "  grading dir       : <unknown>"
    fi
    [ -n "$CLI_PATH" ] && echo "  CLI               : $CLI_PATH"
    [ -n "$MAN_PATH" ] && echo "  man page          : $MAN_PATH"
    [ -n "$PKG_PATH" ] && echo "  package           : $PKG_PATH"
    if [ -n "$SVC_UNIT" ]; then
        local act="unknown" ena="unknown"
        if command -v systemctl &>/dev/null; then
            act="$(systemctl is-active falcon-policy-audit 2>/dev/null || echo inactive)"
            ena="$(systemctl is-enabled falcon-policy-audit 2>/dev/null || echo disabled)"
        fi
        echo "  systemd service   : $SVC_UNIT (user=${SVC_USER:-?}, active=$act, enabled=$ena)"
    fi
    echo "  state dir         : $STATE_DIR"
    echo "  manifest schema   : ${FOUND_SCHEMA:-1.0.0}"
    echo ""
    echo "This bundle would upgrade:  ${CUR_VER:-<none>}  ->  ${NEW_VER}"
    if [ -z "$CUR_VER" ]; then
        echo "NOTE: package not currently installed; upgrade would install it fresh."
    fi
}

print_install_state
echo ""

# --check-install: report state and exit without changing anything.
if [ "$CHECK_ONLY" = "yes" ]; then
    logline "check-install: installed=${CUR_VER:-none} bundle=${NEW_VER} type=${INSTALL_TYPE:-unknown}"
    echo "(--check-install) No changes made."
    exit 0
fi

logline "upgrade invoked (${CUR_VER:-none} -> ${NEW_VER}, dry_run=$DRY_RUN, manifest=$MANIFEST)"

# --- Confirmation gate ------------------------------------------------------
# A real upgrade changes the installed package (and possibly grading). Require
# explicit confirmation of the version transition. --dry-run is read-only so it
# skips the gate; -y confirms non-interactively.
if [ "$DRY_RUN" = "yes" ]; then
    echo "[dry-run] No changes will be made."
    echo ""
elif [ "$ASSUME_YES" = "yes" ]; then
    echo "Proceeding with upgrade ${CUR_VER:-<none>} -> ${NEW_VER} (-y given)."
    logline "upgrade confirmed via -y"
    echo ""
elif [ -t 0 ]; then
    read -r -p "Proceed with upgrade ${CUR_VER:-<none>} -> ${NEW_VER}? [y/N] " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy] ]]; then
        echo "Aborted. (Use --check-install to inspect, or --dry-run to preview.)"
        logline "upgrade aborted at confirmation prompt"
        exit 0
    fi
    logline "upgrade confirmed interactively"
    echo ""
else
    echo "ERROR: refusing to upgrade non-interactively without -y." >&2
    echo "       Re-run with -y to confirm, --dry-run to preview, or" >&2
    echo "       --check-install to just inspect the current install." >&2
    logline "upgrade aborted (non-interactive, no -y)"
    exit 2
fi

# --- ruamel is a hard requirement (config merge) ----------------------------
if ! $PYTHON -c "import ruamel.yaml" &>/dev/null; then
    # It may be bundled but not yet installed; the pip step below installs it.
    # Only fatal if it is also absent from the wheels.
    if ! ls "$WHEEL_DIR"/ruamel*.whl &>/dev/null; then
        echo "ERROR: ruamel.yaml is required for the config merge but is neither" >&2
        echo "       installed nor present in $WHEEL_DIR." >&2
        logline "ERROR: ruamel.yaml unavailable; aborting"
        exit 3
    fi
fi

# --- 1. Stop the service if it is active (SYSTEM/service installs) ----------
SVC_WAS_ACTIVE="no"
if [ -n "$SVC_UNIT" ] && command -v systemctl &>/dev/null; then
    if systemctl is-active --quiet falcon-policy-audit 2>/dev/null; then
        SVC_WAS_ACTIVE="yes"
        if [ "$DRY_RUN" = "yes" ]; then
            echo "[dry-run] would stop service falcon-policy-audit"
        else
            echo "Stopping service falcon-policy-audit ..."
            systemctl stop falcon-policy-audit || true
            logline "stopped service falcon-policy-audit for upgrade"
        fi
    fi
fi

# --- 2. Upgrade the Python package (hash-verified, offline) -----------------
if [ "$DRY_RUN" = "yes" ]; then
    echo "[dry-run] would: pip install --upgrade --no-index --find-links=wheels --require-hashes -r requirements.lock"
else
    echo "Upgrading Python package (offline, hash-verified)..."
    if [ -f "$SCRIPT_DIR/requirements.lock" ]; then
        $PYTHON -m pip install --upgrade --no-index --find-links="$WHEEL_DIR" \
            --require-hashes -r "$SCRIPT_DIR/requirements.lock"
    else
        $PYTHON -m pip install --upgrade --no-index --find-links="$WHEEL_DIR" falcon-policy-scoring
    fi
    logline "package upgraded ${CUR_VER:-none} -> ${NEW_VER}"
    mset version - "$NEW_VER"
fi
echo ""

# --- 3. Man page (best effort, idempotent) ----------------------------------
if [ -f "$SCRIPT_DIR/policy-audit.1" ]; then
    MAN_TARGET="$(mval man)"
    if [ -n "$MAN_TARGET" ]; then
        if [ "$DRY_RUN" = "yes" ]; then
            echo "[dry-run] would refresh man page at $MAN_TARGET"
        else
            if cp "$SCRIPT_DIR/policy-audit.1" "$MAN_TARGET" 2>/dev/null; then
                echo "Refreshed man page: $MAN_TARGET"
                logline "refreshed man page $MAN_TARGET"
            fi
        fi
    fi
fi
echo ""

# --- 4. Grading reconcile (3-way) -------------------------------------------
CHANGED_GRADING="no"
if [ -n "$GRADING_DIR" ] && [ -d "$SCRIPT_DIR/config/grading" ]; then
    echo "Reconciling grading definitions in $GRADING_DIR ..."
    for newf in "$SCRIPT_DIR/config/grading"/*.json; do
        [ -f "$newf" ] || continue
        base="$(basename "$newf")"
        dst="$GRADING_DIR/$base"
        new_hash="$(sha256_of "$newf")"

        # Brand-new grader: not present on disk -> install it.
        if [ ! -f "$dst" ]; then
            if [ "$DRY_RUN" = "yes" ]; then
                echo "  [dry-run] ADD  $base (new grader)"
            else
                cp "$newf" "$dst"
                mset grading-hash "$dst" "$new_hash"   # record baseline
                logline "added new grader $dst"
                echo "  ADD  $base"
                CHANGED_GRADING="yes"
            fi
            continue
        fi

        cur_hash="$(sha256_of "$dst")"
        inst_hash="$(recorded_hash grading-hash "$dst")"

        # Identical to the new version already -> nothing to do, but make sure
        # the baseline reflects reality (older installs may lack the hash).
        if [ "$cur_hash" = "$new_hash" ]; then
            if [ "$DRY_RUN" != "yes" ] && [ "$inst_hash" != "$new_hash" ]; then
                mset grading-hash "$dst" "$new_hash"
            fi
            continue
        fi

        # Force mode: take the new file, backing up the current one.
        if [ "$FORCE_GRADING" = "yes" ]; then
            if [ "$DRY_RUN" = "yes" ]; then
                echo "  [dry-run] REPLACE $base (--force-grading; backup .bak)"
            else
                cp "$dst" "$dst.bak"
                cp "$newf" "$dst"
                mset grading-hash "$dst" "$new_hash"   # advance baseline
                logline "replaced grader $dst (--force-grading; backup $dst.bak)"
                echo "  REPLACE $base (backed up to $base.bak)"
                CHANGED_GRADING="yes"
            fi
            continue
        fi

        if [ -n "$inst_hash" ] && [ "$cur_hash" = "$inst_hash" ]; then
            # Unchanged locally since install, but upstream differs -> update.
            if [ "$DRY_RUN" = "yes" ]; then
                echo "  [dry-run] UPDATE $base (unchanged locally; upstream changed)"
            else
                cp "$newf" "$dst"
                mset grading-hash "$dst" "$new_hash"   # advance baseline (fixes stale-baseline)
                logline "updated grader $dst in place"
                echo "  UPDATE $base"
                CHANGED_GRADING="yes"
            fi
            continue
        fi

        # Customized locally AND differs from the new version -> conflict.
        if [ "$ASSUME_YES" = "yes" ] || [ ! -t 0 ]; then
            choice="n"   # default: keep user's, write .new
        else
            echo ""
            echo "  CONFLICT: $base was customized locally and also changed upstream."
            if command -v diff &>/dev/null; then
                echo "  --- diff (your file -> new version) ---"
                diff "$dst" "$newf" || true
                echo "  ---------------------------------------"
            fi
            read -r -p "  [k]eep yours / [r]eplace with new / write .[n]ew (default n): " choice
        fi
        case "$choice" in
            r|R)
                if [ "$DRY_RUN" = "yes" ]; then
                    echo "  [dry-run] REPLACE $base (backup .bak)"
                else
                    cp "$dst" "$dst.bak"; cp "$newf" "$dst"
                    mset grading-hash "$dst" "$new_hash"   # advance baseline
                    logline "replaced grader $dst on conflict (backup $dst.bak)"
                    echo "  REPLACE $base (backed up to $base.bak)"
                    CHANGED_GRADING="yes"
                fi ;;
            k|K)
                echo "  KEEP $base (no new version written)"
                logline "kept user grader $dst on conflict" ;;
            *)
                if [ "$DRY_RUN" = "yes" ]; then
                    echo "  [dry-run] WRITE $base.new (keep yours)"
                else
                    cp "$newf" "$dst.new"
                    logline "wrote $dst.new; kept user grader $dst"
                    echo "  KEEP $base; new version at $base.new"
                fi ;;
        esac
    done
else
    echo "No grading directory recorded; skipping grading reconcile."
fi
echo ""

# --- 5. Config merge candidate (never overwrite live config) ----------------
NEW_EXAMPLE="$SCRIPT_DIR/config/example.config.yaml"
if [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ] && [ -f "$NEW_EXAMPLE" ]; then
    CONFIG_DIR="$(dirname "$CONFIG_FILE")"
    CANDIDATE="$CONFIG_DIR/config.yaml.upgraded"
    echo "Building merged config candidate (your values + new keys, comments kept)..."
    if [ "$DRY_RUN" = "yes" ]; then
        # Merge into a temp so we can show the added keys without writing to the dir.
        tmp="$(mktemp)"
        ADDED="$($PYTHON "$SCRIPT_DIR/merge_config.py" "$CONFIG_FILE" "$NEW_EXAMPLE" "$tmp" || true)"
        rm -f "$tmp"
        if [ -n "$ADDED" ]; then
            echo "  [dry-run] keys that would be added:"; echo "$ADDED" | sed 's/^/    + /'
        else
            echo "  [dry-run] no new config keys."
        fi
    else
        ADDED="$($PYTHON "$SCRIPT_DIR/merge_config.py" "$CONFIG_FILE" "$NEW_EXAMPLE" "$CANDIDATE")"
        chmod 600 "$CANDIDATE" 2>/dev/null || true
        # Refresh the reference example alongside the config.
        cp "$NEW_EXAMPLE" "$CONFIG_DIR/example.config.yaml"
        logline "wrote merged config candidate $CANDIDATE"
        if [ -n "$ADDED" ]; then
            echo "  New config keys in $NEW_VER:"; echo "$ADDED" | sed 's/^/    + /'
        else
            echo "  No new config keys."
        fi

        if [ "$FORCE_CONFIG" = "yes" ]; then
            cp "$CONFIG_FILE" "$CONFIG_FILE.bak"
            mv "$CANDIDATE" "$CONFIG_FILE"
            chmod 600 "$CONFIG_FILE" 2>/dev/null || true
            mset config-hash "$CONFIG_FILE" "$(sha256_of "$CONFIG_FILE")"   # advance baseline
            logline "adopted merged config $CONFIG_FILE (--force-config; backup $CONFIG_FILE.bak)"
            echo "  Adopted merged config (previous saved as $(basename "$CONFIG_FILE").bak)."
        else
            echo "  Review and adopt with:"
            echo "    diff $CONFIG_FILE $CANDIDATE"
            echo "    mv $CANDIDATE $CONFIG_FILE   # when satisfied"
        fi
    fi
else
    echo "No live config recorded/found; skipping config merge."
fi
echo ""

# --- 6. Restart the service if we stopped it --------------------------------
if [ "$SVC_WAS_ACTIVE" = "yes" ]; then
    if [ "$DRY_RUN" = "yes" ]; then
        echo "[dry-run] would restart service falcon-policy-audit"
    else
        echo "Restarting service falcon-policy-audit ..."
        systemctl start falcon-policy-audit || true
        logline "restarted service falcon-policy-audit"
    fi
fi

# --- 7. Post-upgrade guidance ----------------------------------------------
echo ""
echo "=== Upgrade complete (${CUR_VER:-none} -> ${NEW_VER}) ==="
if [ "$CHANGED_GRADING" = "yes" ] || [ "$FORCE_CONFIG" = "yes" ]; then
    echo "Grading and/or config changed. Validate before relying on results:"
    if [ -n "$SVC_UNIT" ] && [ -n "$SVC_USER" ]; then
        echo "  sudo -u $SVC_USER policy-audit -c $CONFIG_FILE fetch"
    else
        echo "  policy-audit -c ${CONFIG_FILE:-config.yaml} fetch"
    fi
fi
logline "upgrade complete (${CUR_VER:-none} -> ${NEW_VER})"
echo "State manifest: $MANIFEST"
echo "Activity log:   $LOGFILE"
