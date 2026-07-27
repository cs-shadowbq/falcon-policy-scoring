# Security Policy

## Community Supported Versions

Security fixes are applied to the most recent minor release. Older minor
releases are not maintained — upgrade to the latest `1.8.x` for security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.8.x   | :white_check_mark: |
| 1.7.x   | :x:                |
| < 1.7   | :x:                |

## Supported platforms

falcon-policy-scoring is a pure-Python application requiring **Python >= 3.8**.

Air-gapped / disconnected deployment is supported on **RHEL 9 (x86_64)** via
prebuilt offline bundles targeting the Python interpreters shipped with RHEL 9:

| Airgap bundle | Target |
| ------------- | ------ |
| `*-airgap-rhel9-cp39-x86_64`  | Python 3.9 (RHEL 9.0–9.3 default) |
| `*-airgap-rhel9-cp311-x86_64` | Python 3.11 |
| `*-airgap-rhel9-cp312-x86_64` | Python 3.12 (RHEL 9.4+ AppStream) |

Each airgap bundle ships a hash-pinned dependency lockfile, a CycloneDX SBOM, and
a hardened systemd unit template. Release checksums are published as `SHA256SUMS`
(with an optional detached `SHA256SUMS.asc` signature). The application is
FIPS-compatible and runs unmodified on a FIPS-enabled RHEL 9 host. See
[INSTALL.md](INSTALL.md) and [STIG_HARDENING.md](STIG_HARDENING.md) for airgap,
hardening, and FIPS details.

## Supported CrowdStrike regions

falcon-policy-scoring is tested for functionality across all CrowdStrike regions, including US-GOV-2

| Region |
| :--- |
| US-1 |
| US-2 |
| EU-1 |
| US-GOV-1 |
| US-GOV-2 |

## Supported FalconPy versions

When falconpy release an update, we release security vulnerability patches for the most recent release at an accelerated cadence.  

## Reporting a potential security vulnerability

Issues may be reported [here](https://github.com/cs-shadowbq/falcon-policy-scoring/issues/new)

## Support Escalation

Falcon Policy Scoring is a community-driven, open source project, not a CrowdStrike
product. As such, it carries no formal support, expressed or implied. For issue
reporting guidance (MCVE format), questions, and confidentiality considerations,
see [SUPPORT.md](SUPPORT.md).
