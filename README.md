# Falcon Policy Audit

> Continuous security policy compliance monitoring for CrowdStrike Falcon environments

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE.md)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Container](https://img.shields.io/badge/container-UBI9-red.svg)](https://catalog.redhat.com/software/containers/ubi9/python-312/657b08d023df896ebfacf402)
[![Tests](https://github.com/cs-shadowbq/falcon-policy-scoring/actions/workflows/test.yml/badge.svg)](https://github.com/cs-shadowbq/falcon-policy-scoring/actions/workflows/test.yml)

**Falcon Policy Audit** automatically evaluates your CrowdStrike security policies against best practices, identifies configuration drift, and provides actionable compliance reports. Run it as a CLI tool for ad-hoc audits or deploy as a daemon for continuous monitoring in Docker/Kubernetes.

---

## Key Capabilities

Falcon Policy Audit evaluates your CrowdStrike security policies across six critical areas: Prevention, Sensor Update, Content Update, Firewall, Device Control, and IT Automation. It compares your configurations against customizable security standards, identifies which hosts are affected by policy gaps, and provides detailed compliance reports.

Run it interactively for ad-hoc audits or deploy as a daemon for scheduled monitoring with configurable intervals. The daemon mode includes enterprise features like intelligent API rate limiting, health check endpoints, Prometheus metrics, and graceful shutdown handling.

---

## Quick Start

### CLI Mode (Interactive)

```bash
# Initialize Environment - Set Autoloaded ENVs
export CLIENT_ID="your_client_id"
export CLIENT_SECRET="your_client_secret"
export BASE_URL="your_base_url"  # e.g. "US1", "US2", "EU1", "USGOV1", "USGOV2"

# Alternative: Use .env file (automatically loaded)
# Create a .env file in the project root:
# CLIENT_ID=your_client_id
# CLIENT_SECRET=your_client_secret
# BASE_URL=US1

# Install
pip install -e .

# Configure 
cp config/example.config.yaml config/config.yaml
vi config/config.yaml

# Fetch and grade policies using ENV credentials or Configured Credentials
policy-audit fetch

# Explicit ENV Mapping (alternative to auto-loading)
# policy-audit --client-id=$CLIENT_ID --client-secret=$CLIENT_SECRET --base-url=$BASE_URL fetch

# Limit fetching to specific policy types, host groups, and last-seen
# policy-audit fetch --host-groups "MY-GROUP" -t "it-automation" --last-seen day

# View results
## Simply run policy-audit hosts or policy-audit policies without any arguments, and it will automatically use the most recent cached data.
policy-audit policies --details
policy-audit hosts --status any-failed
```

### Daemon Mode (Continuous Monitoring)

**Docker Compose:**

```bash
# Configure credentials
vi config/config.yaml

# Start daemon
docker-compose up -d

# Check health
curl http://localhost:8088/health

# View timestamped reports
ls -la output/
```

**Kubernetes:**

```bash
# Configure secrets
vi k8s/secret.yaml

# Deploy
kubectl apply -f k8s/

# Monitor
kubectl logs -n endpoint-readiness-audit -l app=falcon-policy-audit -f
```

---

## Features

### CLI Mode

- Rich colored tables with status indicators
- Filter by last-seen, policy type, platform, and compliance status
- Sort by score, name, or platform
- Host-level and policy-level reports
- Local caching to minimize API calls

### Daemon Mode

- Cron-like scheduling (e.g., every 15 minutes, hourly, daily)
- Intelligent API rate limiting with exponential backoff for 100k+ hosts
- Timestamped JSON output files for audit trails
- Kubernetes-ready health checks (`/health`, `/ready`, `/metrics`)
- Prometheus-compatible metrics export
- Configuration reload via SIGHUP (no restart needed)
- Non-root container with STIG-hardened base image (UBI9)

---

## Documentation

> [!TIP]
> Start with [Understanding the Tool](docs/understanding-the-tool.md) to learn what it does and why you need it, then move to the [Interactive Mode Guide](docs/policy-audit-interactive-mode.md) or [Daemon Mode Guide](docs/policy-audit-daemon-mode.md) depending on your use case.

| Document | Description |
|----------|-------------|
| **[Understanding the Tool](docs/understanding-the-tool.md)** | What it does, why you need it, how grading works |
| **[Policy Grading System](docs/policy-grading-system.md)** | Grading architecture, scoring, and customization |
| **[Interactive Mode Guide](docs/policy-audit-interactive-mode.md)** | CLI commands, filtering, sorting, examples |
| **[Daemon Mode Guide](docs/policy-audit-daemon-mode.md)** | Continuous monitoring, scheduling, deployment |
| **[JSON Output Format](docs/json-output.md)** | Output schema and file structure |
| **[Kubernetes Deployment](k8s/README.md)** | K8s manifests, RBAC, resource limits |
| **[STIG Hardening Guide](STIG_HARDENING.md)** | Container security and compliance |

### Policy-Specific Documentation

- [Prevention Policies](docs/prevention-policies.md) - Threat blocking and protection levels
- [Sensor Update Policies](docs/sensor-update-policies.md) - Agent version management
- [Content Update Policies](docs/content-update-policies.md) - Threat intelligence updates
- [Firewall Policies](docs/firewall-policies.md) - Network connection rules
- [Device Control Policies](docs/device-control-policies.md) - USB/peripheral restrictions
- [IT Automation Policies](docs/it-automation-policies.md) - Remote access controls

---

## Configuration

> [!IMPORTANT]
> Policies are graded against standards defined in `config/grading/*.json`. Customize these files to match your organization's security requirements.

```text
config/
├── config.yaml                              # API credentials, schedules, rate limits
└── grading/
    ├── prevention_policies_grading.json     # Prevention policy standards
    ├── sensor_update_policies_grading.json  # Sensor update standards
    ├── firewall_policies_grading.json       # Firewall standards
    └── ...                                  # Other policy types
```

**Example Schedule (config.yaml):**

```yaml
daemon:
  schedules:
    fetch_and_grade: "0 */2 * * *"  # Every 2 hours
  rate_limit:
    requests_per_second: 10.0
    burst_size: 20
```

---

## Sample Output

### Policy Table (CLI)

```
╭──────────────────────────────────────────────────────────────╮
│ Prevention Policies                                          │
├────┬─────────────────────────┬──────────┬─────────┬─────────┤
│ ✓  │ Corporate Standard      │ Windows  │ 0/15    │ 100.0%  │
│ ✗  │ Legacy Workstations     │ Windows  │ 3/15    │  82.5%  │
│ ✓  │ Mac Standard            │ Mac      │ 0/12    │ 100.0%  │
╰────┴─────────────────────────┴──────────┴─────────┴─────────╯
```

### JSON Output (Daemon)

```
output/
├── 2025-12-08_14-30-00_policy-audit.json
├── 2025-12-08_14-30-00_host-summary.json
└── 2025-12-08_14-30-00_metrics.json
```

---

## Deployment

> [!TIP]
> Use the provided Makefile for Docker operations and k8s-deploy.sh for Kubernetes monitoring.

### Docker Build & Push

```bash
# Build image
make docker-build TAG=v1.0.0

# Push to registry
export REGISTRY=docker.io/myuser
make docker-push TAG=v1.0.0
```

### Kubernetes Deployment

```bash
# Quick deploy
kubectl apply -f k8s/

# Monitor with helper script
./k8s-deploy.sh check        # Status
./k8s-deploy.sh logs         # Tail logs
./k8s-deploy.sh port-forward # Access health endpoint
```

See [Daemon Mode Guide](docs/policy-audit-daemon-mode.md) for detailed deployment instructions.

---

## Use Cases

| Scenario | How Falcon Policy Audit Helps |
|----------|-------------------------------|
| **Compliance Audits** | Generate timestamped reports showing policy compliance over time |
| **Configuration Drift** | Detect when policies deviate from approved security standards |
| **Change Management** | Verify policy changes meet requirements before deployment |
| **Security Posture** | Continuous monitoring of security configuration across 100k+ hosts |
| **Incident Response** | Quickly identify hosts with weak security settings |

---

## Security

> [!IMPORTANT]
> This tool requires CrowdStrike API credentials with read access to policy and host data. Store credentials securely using Kubernetes Secrets or environment variables, never commit them to version control.

- **Non-root Container**: Runs as UID 1001
- **STIG-Hardened Base**: Red Hat UBI9 (A-rated)
- **Secret Management**: API credentials via Kubernetes Secrets or environment variables
- **RBAC**: Minimal permissions in Kubernetes deployments
- **Network Policies**: Egress-only to CrowdStrike API

See [STIG_HARDENING.md](STIG_HARDENING.md) for container security hardening guidelines details. The out-of-the-box container configuration does not enforce STIG compliance on the container, and leaves it to the deployer to ensure compliance based on their environment and requirements.

---

## Scaling

Designed to handle large environments efficiently:

| Environment Size | Resource Recommendations |
|------------------|--------------------------|
| **<10k hosts** | 1 CPU / 2GB RAM |
| **10k-100k hosts** | 2-4 CPU / 4-8GB RAM |
| **100k+ hosts** | 4+ CPU / 8+ GB RAM |

Rate limiting automatically adjusts for scale. See [Daemon Mode Guide](docs/policy-audit-daemon-mode.md#api-rate-limiting) for tuning guidance.

---

## Contributing

We welcome contributions! Please see [SUPPORT.md](SUPPORT.md) for guidelines.

### Development Setup

```bash
# Clone and install
git clone <repository-url>
cd TornadoVortex
pip install -e ".[dev,test]"

# Run tests
pytest

# Run locally
python bin/policy-audit daemon --verbose
```

---

## License

MIT License - see [LICENSE.md](LICENSE.md) for details.

---

## Support

This is a community-driven open source project, not a CrowdStrike product. For issues and questions:

- [Report Issues](https://github.com/CrowdStrike/xxxx/issues)
- [Read Documentation](docs/)
- [Support Guidelines](SUPPORT.md)

---

Made with **❤❤❤** by the CrowdStrike Community
