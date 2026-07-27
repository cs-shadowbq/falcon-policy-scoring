# Installation

## Standard Install (from GitHub release)

Download the wheel from the
[GitHub Releases](https://github.com/cs-shadowbq/falcon-policy-scoring/releases)
page:

```bash
pip install falcon_policy_scoring-1.8.0-py3-none-any.whl
```

Or install directly from the repository:

```bash
pip install git+https://github.com/cs-shadowbq/falcon-policy-scoring.git@v1.8.0
```

## Development Install

```bash
git clone https://github.com/cs-shadowbq/falcon-policy-scoring.git
cd falcon-policy-scoring
pip install -e ".[dev,test]"
```

## Airgapped Install (RHEL 9 x86_64)

For disconnected/air-gapped environments without internet access on the target host.

> [!IMPORTANT]
> The airgap `install.sh` is **not** the same as `pip install` or a `git clone`
> editable install. It is a self-contained **offline lifecycle**:
>
> - **`git clone` + `pip install -e .`** (development): the grading files live in
>   the repo tree (`config/grading/`), used via the default `config/config.yaml`.
> - **`pip install <wheel>`** (connected host): the package goes to site-packages;
>   you provide your own `config.yaml` with a `grading/` directory beside it.
> - **`./install.sh`** (airgap): installs wheels **offline** (hash-verified against
>   `requirements.lock`), **prepares a SYSTEM or WORKSPACE layout** with the grading
>   files (they are **not** in the wheel), can install a **hardened systemd
>   service**, writes an **`install.log`** manifest, and ships a matching
>   **`uninstall.sh`**.
>
> In every case grading definitions are resolved as `<dir-of-config.yaml>/grading/`,
> so the tool works from any working directory once `-c` points at the config.

### Download the Bundle

From the [GitHub Releases](https://github.com/cs-shadowbq/falcon-policy-scoring/releases)
page, download the appropriate airgap bundle:

| Bundle | Target |
| ------ | ------ |
| `falcon-policy-scoring-*-airgap-rhel9-cp39-x86_64.tar.gz` | Python 3.9 (RHEL 9.0-9.3 default) |
| `falcon-policy-scoring-*-airgap-rhel9-cp311-x86_64.tar.gz` | Python 3.11 |
| `falcon-policy-scoring-*-airgap-rhel9-cp312-x86_64.tar.gz` | Python 3.12 (RHEL 9.4+ AppStream) |

### Install on Target

Transfer the tarball to the airgapped host:

```bash
tar xzf falcon-policy-scoring-*-airgap-rhel9-*.tar.gz
cd falcon-policy-scoring-*-airgap-*/
./install.sh
```

`install.sh` will, in order:

1. Install the wheels **offline** — using pip with `--require-hashes` against
   `requirements.lock` when pip is available, or falling back to manual wheel
   extraction if not.
2. Optionally **prepare a workspace** (`grading/`, `config.yaml` at mode `0600`,
   `data/`, `logs/`). Grading definitions are resolved next to `config.yaml`, so
   you can run the tool from any directory:
   `policy-audit -c <workspace>/config.yaml fetch`.
3. Optionally install a **hardened systemd service** (see below).
4. Record every artifact it created to `install.log` for audit and cleanup.

To remove everything later, use the bundled `./uninstall.sh` (see
[Uninstall](#uninstalling-the-airgap-bundle)).

### Manual Install (no pip, no root)

If you need full control over where packages land:

```bash
mkdir -p ~/pylibs
for whl in wheels/*.whl; do unzip -q -o "$whl" -d ~/pylibs/; done
export PYTHONPATH=~/pylibs:$PYTHONPATH
python3 -m falcon_policy_scoring --help
```

Add the `PYTHONPATH` export to your `~/.bashrc` to make it persistent.

### Building the Airgap Bundle Yourself

On a machine with internet access:

```bash
# Build wheel + both Python 3.9 and 3.11 bundles
make airgap

# Or target a specific Python version
make airgap AIRGAP_PYTHON=39

# The script can also be run standalone
./scripts/build-airgap.sh --python 39,311
```

Outputs land in `dist/`:

```text
dist/
├── falcon_policy_scoring-1.8.0-py3-none-any.whl
├── falcon-policy-scoring-1.8.0.tar.gz
├── falcon-policy-scoring-1.8.0-airgap-rhel9-cp39-x86_64.tar.gz
├── falcon-policy-scoring-1.8.0-airgap-rhel9-cp311-x86_64.tar.gz
└── falcon-policy-scoring-1.8.0-airgap-rhel9-cp312-x86_64.tar.gz
```

Each airgap bundle contains:

- `wheels/` — all runtime dependency wheels pre-compiled for the target
- `requirements.lock` — hash-pinned lockfile; `install.sh` verifies wheels against it
- `install.sh` — auto-installer (uses pip if available, falls back to unzip); writes `install.log`
- `uninstall.sh` — uninstaller (`--purge` also removes config/data); writes `uninstall.log`
- `falcon-policy-audit.service` — hardened systemd unit template
- `sbom.cdx.json` — CycloneDX 1.5 SBOM listing all bundled components and versions
- `README.md` — quick-start instructions

### Which datastore / run mode? (hardened deployments)

For a disconnected, hardened RHEL9 host, use **SQLite as the datastore** and run
the tool as a **daemon under the systemd service**. This is the default the
installer configures.

**Datastore — use SQLite (the default).** The example config already ships with
`db.type: sqlite`. Of the available adapters (`sqlite`, `tiny_db`, `dynalite`,
`dynamodb`, `foundry_collections`), SQLite is the only one that is both fully
offline and crash-safe:

| Datastore | Airgap-safe | Concurrency / crash safety |
|-----------|-------------|----------------------------|
| **sqlite** (recommended) | ✅ stdlib, no network | Transactions + file locking; survives ungraceful shutdown |
| tiny_db | ✅ | JSON rewritten wholesale per write — no locking; a crash mid-write can corrupt the whole store |
| dynalite / dynamodb | ❌ needs `boto3` + a running endpoint | n/a offline |
| foundry_collections | ❌ needs the Falcon platform | n/a offline |

The installer pins `sqlite.path` to an **absolute** path in the writable data dir
(e.g. `/var/lib/falcon-policy-audit/db.sqlite`). Keep it absolute — a relative
`./data/...` resolves against the process working directory and can fall outside
the systemd sandbox's writable paths, causing the daemon to fail to open its DB.

**Run mode — use the daemon service, not cron.** Daemon mode gives you a single
supervised writer (no overlapping runs corrupting SQLite), continuous rate-limit
backoff state across cycles, `Restart=on-failure`, boot persistence, and the
`/health` `/ready` `/metrics` endpoints plus SIGHUP config reload. A cron one-shot
has none of these and can start a second overlapping process. If systemd is truly
unavailable, wrap a cron job in `flock` to prevent overlap, but treat that as a
degraded fallback:

```bash
flock -n /run/lock/policy-audit.lock policy-audit -c /path/config.yaml fetch
```

### Running as a hardened systemd service

`install.sh` (run as root on the target) offers to install the daemon as a
sandboxed systemd service, choosing either FHS paths (`/etc/`, `/var/lib/`,
`/var/log/`) or a single workspace directory. It seeds `config.yaml` at mode
`0600`, pins an absolute `sqlite.path`, creates a `policyaudit` service account,
renders the unit, and records everything to `install.log`.

> [!WARNING]
> The hardened unit sets `ProtectHome=yes`, which makes `/home` and `/root`
> **invisible** to the service. Do **not** put a service workspace (or config,
> data, logs) under a home directory — use `/opt`, `/srv`, or `/var/lib`
> (e.g. `/opt/falcon-policy-audit`). A home-directory workspace is fine for
> interactive `policy-audit fetch`, but not as a service root.

> [!IMPORTANT]
> **Validate with a hand run before enabling the daemon.** Do a one-shot fetch
> **as the service user** so it uses the exact same config and proves API keys,
> DNS/network egress, and read/write file locations all work. Running the
> validation as the service user (not root) matters: a root-run fetch creates
> root-owned files in the data dir that the daemon — running as `policyaudit` —
> could not later update.

```bash
sudo ./install.sh                     # install + render unit (does NOT enable it)

# 1. Edit credentials/settings:
sudo vi /etc/falcon-policy-audit/config.yaml

# 2. Hand-run as the service user to validate config, API, DNS, and file access:
sudo -u policyaudit policy-audit -c /etc/falcon-policy-audit/config.yaml fetch

# 3. If that succeeded, re-assert ownership and enable the daemon:
sudo chown -R policyaudit:policyaudit /var/lib/falcon-policy-audit /var/log/falcon-policy-audit
sudo systemctl enable --now falcon-policy-audit

# 4. Verify health and sandboxing:
systemctl status falcon-policy-audit
journalctl -u falcon-policy-audit -f
systemd-analyze security falcon-policy-audit
```

To remove: `./uninstall.sh` (keeps config/data) or `./uninstall.sh --purge`
(also deletes config, data, and output). See the unit's hardening rationale and
FIPS notes in [STIG_HARDENING.md](STIG_HARDENING.md).

### Uninstalling the Airgap Bundle

Every airgap bundle ships an `uninstall.sh` that reads the `install.log` manifest
to know exactly what to remove (package, CLI wrapper, systemd unit, and the
`policyaudit` service account if the installer created it):

```bash
./uninstall.sh            # remove package/CLI/unit/user; KEEP config, data, logs
./uninstall.sh --purge    # also delete config, data, and output
./uninstall.sh --yes      # skip the confirmation prompt (for automation)
```

`--purge` leaves only `uninstall.sh` and its own `uninstall.log` behind. The
uninstaller is idempotent — re-running it will not error on already-removed items.

### Verifying integrity (airgap)

```bash
# Checksums
sha256sum -c SHA256SUMS
# Authenticity, if the release was signed (SHA256SUMS.asc present):
gpg --verify SHA256SUMS.asc SHA256SUMS
```

## Creating a GitHub Release

Build everything and push to GitHub in one step (requires `gh` CLI):

```bash
make release
```

This runs `dist` + `airgap` then uses `gh release create` to publish:

- The `.whl` (universal wheel)
- The `.tar.gz` (sdist)
- The airgap bundles (one per targeted Python version)
- `SHA256SUMS` (and `SHA256SUMS.asc` if a GPG signing key was available)

### Prerequisites

- [GitHub CLI](https://cli.github.com/) installed and authenticated (`gh auth login`)
- Git tag matching the version in `pyproject.toml` (e.g., `git tag v1.8.0 && git push --tags`)

### Manual Release Workflow

```bash
# 1. Bump version in pyproject.toml
# 2. Commit and tag
git add pyproject.toml
git commit -m "Release v1.8.0"
git tag v1.8.0
git push && git push --tags

# 3. Build and release
make release
```
