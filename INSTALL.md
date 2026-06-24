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

The installer auto-detects whether `pip` is available and falls back to manual
wheel extraction if not.

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
- `install.sh` — auto-installer (uses pip if available, falls back to unzip)
- `sbom.cdx.json` — CycloneDX 1.5 SBOM listing all bundled components and versions
- `README.md` — quick-start instructions

## Creating a GitHub Release

Build everything and push to GitHub in one step (requires `gh` CLI):

```bash
make release
```

This runs `dist` + `airgap` then uses `gh release create` to publish:

- The `.whl` (universal wheel)
- The `.tar.gz` (sdist)
- Both airgap bundles

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
