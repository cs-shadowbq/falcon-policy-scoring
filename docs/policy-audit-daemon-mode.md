# Policy Audit Tool - Daemon Mode - Continuous Policy Auditing Service

The Falcon Policy Audit Daemon provides continuous, automated policy auditing for CrowdStrike Falcon environments. It runs as a long-lived service in containers (Docker/Kubernetes) and periodically fetches, grades, and reports on security policies.

## Overview

### Key Features

- **Continuous Operation**: Runs indefinitely with configurable schedules
- **Cron-like Scheduling**: Flexible task scheduling using cron expressions
- **API Rate Limiting**: Built-in rate limiting with exponential backoff for 100k+ hosts
- **Timestamped JSON Output**: Reports written to dated JSON files for easy analysis
- **Health Checks**: Kubernetes-ready liveness/readiness probes
- **Metrics Export**: Prometheus-compatible metrics endpoint
- **Graceful Shutdown**: Handles SIGTERM/SIGINT for clean container stops
- **Non-root Execution**: Runs as unprivileged user for security

## Quick Start

Policy Audit Daemon can be run in various environments. Below are instructions for local testing, Docker, and Kubernetes deployment.

```bash
./bin/policy-audit daemon \
  --config config/config.yaml \
  --output-dir ./output \
  --health-port 8088 \
  --verbose
```

## Configuration

### Daemon Section in config.yaml

```yaml
daemon:
  # Task Scheduling (cron format)
  schedules:
    fetch_and_grade: "0 */2 * * *"  # Every 2 hours
    cleanup: "0 2 * * *"              # Daily at 2 AM
    metrics: "*/30 * * * *"            # Every 30 minutes
  
  # Check interval (seconds between schedule checks)
  check_interval: 60
  
  # Policy types to audit
  policy_types:
    - prevention
    - sensor-update
    - content-update
    - firewall
    - device-control
    - it-automation
  
  # Host filtering (empty = default, ['all'] = all types)
  product_types: []
  
  # API Rate Limiting
  rate_limit:
    requests_per_second: 10.0    # Max requests/sec
    requests_per_minute: 500     # Max requests/min
    burst_size: 20               # Burst capacity
    retry_attempts: 5            # Max retries
  
  # Output Configuration
  output:
    compress: false              # Gzip compression
    max_age_days: 30            # Retention period
    max_files_per_type: 100     # Max files per type
  
  # Health Check
  health_check:
    port: 8088
```

### Cron Expression Format

```
* * * * *
│ │ │ │ │
│ │ │ │ └─── Day of week (0-6, Sunday=0)
│ │ │ └───── Month (1-12)
│ │ └─────── Day of month (1-31)
│ └───────── Hour (0-23)
└─────────── Minute (0-59)
```

**Examples:**

- `*/5 * * * *` - Every 5 minutes
- `0 * * * *` - Every hour
- `0 */6 * * *` - Every 6 hours
- `0 2 * * *` - Daily at 2 AM
- `0 0 * * 0` - Weekly on Sunday at midnight

## API Rate Limiting

The daemon includes sophisticated rate limiting to handle large environments (100k+ hosts) while respecting CrowdStrike API limits.

### Rate Limit Strategy

1. **Token Bucket Algorithm**
   - Allows configurable requests/second
   - Supports burst traffic up to `burst_size`
   - Tokens refill at steady rate

2. **Sliding Window**
   - Tracks requests/minute
   - Prevents minute-boundary issues

3. **Exponential Backoff**
   - Automatic retry on 429 errors
   - Backoff: 2^attempt seconds (capped at 5 minutes)
   - Resets after successful request

### Tuning for Scale

**Small Environments (<1,000 hosts)**

```yaml
rate_limit:
  requests_per_second: 10.0
  requests_per_minute: 500
  burst_size: 20
```

**Medium Environments (1,000-10,000 hosts)**

```yaml
rate_limit:
  requests_per_second: 15.0
  requests_per_minute: 750
  burst_size: 30
```

**Large Environments (10,000-100,000 hosts)**

```yaml
rate_limit:
  requests_per_second: 20.0
  requests_per_minute: 1000
  burst_size: 50
```

**Very Large Environments (100,000+ hosts)**

```yaml
rate_limit:
  requests_per_second: 25.0
  requests_per_minute: 1200
  burst_size: 75
```

## File Output

The daemon writes timestamped JSON reports to the specified output directory.

See [JSON Output Documentation](json-output.md) for full schema details.

## Health Checks

The daemon exposes three HTTP endpoints for monitoring:

### 1. Liveness Probe - `/health`

Checks if the daemon is alive and responding.

```bash
curl http://localhost:8088/health
```

**Response (200 OK):**

```json
{
  "status": "alive",
  "timestamp": "2025-12-07T14:30:00",
  "uptime_seconds": 3600
}
```

**Use Case:** Kubernetes liveness probe

### 2. Readiness Probe - `/ready`

Checks if the daemon is ready to process work.

```bash
curl http://localhost:8088/ready
```

**Response (200 OK = ready, 503 = not ready):**

```json
{
  "status": "healthy",  // or "degraded", "unhealthy"
  "timestamp": "2025-12-07T14:30:00",
  "last_successful_run": "2025-12-07T14:15:00",
  "next_scheduled_run": "2025-12-07T14:30:00",
  "consecutive_failures": 0
}
```

**Use Case:** Kubernetes readiness probe

### 3. Metrics Endpoint - `/metrics`

Returns operational metrics.

```bash
curl http://localhost:8088/metrics
```

**Response (200 OK):**

```json
{
  "timestamp": "2025-12-07T14:30:00",
  "uptime_seconds": 3600,
  "total_runs": 24,
  "successful_runs": 24,
  "failed_runs": 0,
  "success_rate": 1.0,
  "total_hosts_processed": 24000,
  "total_policies_graded": 1200,
  "rate_limiter": {
    "total_requests": 500,
    "throttled_requests": 10,
    "failed_requests": 0
  }
}
```

**Use Case:** Prometheus scraping, monitoring dashboards

### Using Makefile to Assist with Docker and Kubernetes

```bash

# Build Docker image
make docker-build                    # Builds falcon-policy-audit:latest
make docker-build TAG=v1.0.0        # Builds falcon-policy-audit:v1.0.0

# Test Docker image locally
make docker-test

# Push to registry (set REGISTRY as environment variable or inline)
export REGISTRY=docker.io/myuser
make docker-push                     # Pushes :latest tag

# Or inline
REGISTRY=docker.io/myuser TAG=v1.0.0 make docker-push

# Deploy to Kubernetes
make k8s-deploy

# Remove Kubernetes deployment
make k8s-delete
```

**Environment Variables:**

- `REGISTRY` - Docker registry URL (required for push). Examples:
  - `docker.io/username` (Docker Hub)
  - `ghcr.io/organization` (GitHub Container Registry)
  - `your-registry.com/project` (Private registry)
- `TAG` - Image tag (default: `latest`)

**Setting Environment Variables:**

```bash
# Option 1: Export for session
export REGISTRY=docker.io/myuser
export TAG=v1.0.0
make docker-push

# Option 2: Inline for single command
REGISTRY=docker.io/myuser TAG=v1.0.0 make docker-push

# Option 3: Set in your shell profile (~/.bashrc, ~/.zshrc)
echo 'export REGISTRY=docker.io/myuser' >> ~/.bashrc
```

### Using k8s-deploy.sh (Kubernetes Management Tool)

The `k8s-deploy.sh` script provides Kubernetes-specific deployment management:

```bash
# Deploy to Kubernetes
./k8s-deploy.sh deploy

# Monitor deployment
./k8s-deploy.sh check        # View status
./k8s-deploy.sh logs         # Tail logs
./k8s-deploy.sh port-forward # Access locally (port 8088)

# Clean up
./k8s-deploy.sh delete
```

**Note**: Docker operations (build, test, push) are handled by the Makefile. The k8s-deploy.sh script focuses on Kubernetes deployment and monitoring.

**When to use which:**

- **Makefile**: All Docker operations plus K8s deployment shortcuts
- **k8s-deploy.sh**: Advanced K8s monitoring (checking status, logs, port forwarding)

### Local Testing with Docker Compose

```bash
# 1. Update config with your API credentials
vi config/config.yaml

# 2. Build and run
docker-compose up -d

# 3. Check logs
docker-compose logs -f

# 4. Check health
curl http://localhost:8088/health

# 5. View reports
ls -la output/
```

### Kubernetes Deployment

```bash
# 1. Configure API credentials
vi k8s/secret.yaml

# 2. Deploy
kubectl apply -f k8s/

# 3. Monitor
kubectl logs -n security -l app=falcon-policy-audit -f
```

## Advanced: Signal Handling

The daemon handles multiple signals for operational control:

### Graceful Shutdown (SIGTERM/SIGINT)

The daemon handles shutdown signals gracefully:

1. **SIGTERM/SIGINT received**
2. Stop accepting new tasks
3. Complete current task (if running)
4. Flush buffers and write checkpoint
5. Close database connections
6. Stop health check server
7. Exit cleanly

```bash
# Docker
docker stop falcon-policy-audit-daemon

# Kubernetes
kubectl delete pod -n security <pod-name>

# Local process
kill -TERM <pid>

# Or press Ctrl+C for interactive sessions
```

### Configuration Reload (SIGHUP)

The daemon supports configuration reload without restart via SIGHUP:

```bash
# Send SIGHUP to reload configuration
kill -HUP <pid>

# Or in Docker
docker kill -s HUP falcon-policy-audit-daemon

# Or in Kubernetes
kubectl exec -n security <pod-name> -- kill -HUP 1
```

**What gets reloaded:**

- Rate limiting settings (`requests_per_second`, `burst_size`, etc.)
- Output compression settings
- Scheduled task timing (cron expressions)
- Health check configuration (port, enabled/disabled)

**What requires restart:**

- Database configuration changes
- Falcon API credentials
- Policy types or product types filters

**Use Case:** Update rate limits, adjust schedules, or enable/disable features without downtime.

## Monitoring and Observability

### Prometheus Integration

The daemon exports metrics in Prometheus format at `/metrics`:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'falcon-policy-audit'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
            - security
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
```

### Key Metrics

- `uptime_seconds` - Daemon uptime
- `total_runs` - Total audit runs
- `successful_runs` - Successful runs
- `failed_runs` - Failed runs
- `total_hosts_processed` - Total hosts audited
- `total_policies_graded` - Total policies graded
- `api_calls` - Total API calls made
- `api_errors` - API errors encountered
- `throttled_requests` - Rate-limited requests

### Log Aggregation

Logs are written to stdout in JSON format for easy aggregation:

```json
{
  "timestamp": "2025-12-07T14:30:00",
  "level": "INFO",
  "message": "Fetch and grade run completed successfully",
  "hosts_processed": 1000,
  "policies_graded": 50,
  "duration_seconds": 120.5
}
```

## Troubleshooting

### Common Issues

#### 1. Daemon Won't Start

**Symptoms:** Pod crashes immediately

**Checks:**

```bash
# Check logs
docker logs falcon-policy-audit-daemon

# Check config
cat config/config.yaml

# Verify API credentials
echo $FALCON_CLIENT_ID
```

#### 2. API Rate Limiting

**Symptoms:** Many 429 errors in logs

**Solution:** Adjust rate limits or schedule frequency

```yaml
rate_limit:
  requests_per_second: 5.0  # Reduce
  requests_per_minute: 250   # Reduce

schedules:
  fetch_and_grade: "*/30 * * * *"  # Less frequent
```

#### 3. High Memory Usage

**Symptoms:** OOMKilled pods, high memory metrics

**Solution:** Increase resources or reduce batch size

```yaml
# Kubernetes
resources:
  limits:
    memory: 4Gi  # Increase

# Config
host_fetching:
  batch_size: 50  # Reduce from 100
```

#### 4. Health Check Failures

**Symptoms:** Pod marked as unhealthy

**Checks:**

```bash
# Test endpoint directly
curl http://localhost:8088/health

# Check recent errors
kubectl logs -n security <pod> --tail=100

# Inspect health state
curl http://localhost:8088/ready | jq
```

### Debug Mode

Enable verbose logging:

```bash
# Docker
docker run -e LOG_LEVEL=DEBUG ...

# Kubernetes
# Edit deployment.yaml, add to args:
args:
  - "--verbose"

# Local
python bin/policy-audit daemon --verbose
```

## Performance Optimization

### For 100k+ Hosts

1. **Increase Resources**

   ```yaml
   resources:
     limits:
       cpu: 4000m
       memory: 8Gi
   ```

## Quick Reference

### Deployment Tools Comparison

| Task | Makefile | k8s-deploy.sh |
|------|----------|---------------|
| Build image | `make docker-build` | *(use Makefile)* |
| Test locally | `make docker-test` | *(use Makefile)* |
| Push to registry | `make docker-push REGISTRY=...` | *(use Makefile)* |
| Deploy to K8s | `make k8s-deploy` | `./k8s-deploy.sh deploy` |
| Check status | *(not available)* | `./k8s-deploy.sh check` |
| View logs | *(not available)* | `./k8s-deploy.sh logs` |
| Port forward | *(not available)* | `./k8s-deploy.sh port-forward` |
| Remove deployment | `make k8s-delete` | `./k8s-deploy.sh delete` |

**Division of Responsibilities:**

- **Makefile**: All Docker operations (build, test, push) + basic K8s deployment
- **k8s-deploy.sh**: Advanced Kubernetes monitoring and management

**Recommendation**: Use Makefile for building and deploying. Use k8s-deploy.sh for monitoring and troubleshooting running deployments.

3. **Enable Compression**

   ```yaml
   output:
     compress: true  # Reduce storage
   ```

4. **Adjust Retention**

   ```yaml
   output:
     max_age_days: 7  # Keep 1 week
     max_files_per_type: 50
   ```

## Best Practices

1. **Monitor Health Endpoints**: Set up alerts on readiness failures
2. **Watch Rate Limits**: Monitor `/metrics` for throttling
3. **Regular Cleanup**: Ensure cleanup task runs successfully
4. **Resource Sizing**: Start conservative, scale based on metrics
5. **Backup Reports**: Consider external backup of output directory
6. **API Credentials**: Rotate regularly, use Kubernetes Secrets
7. **Log Aggregation**: Ship logs to central logging system
8. **Alerting**: Alert on consecutive failures or degraded status

## Security Considerations

1. **API Credentials**: Never commit to git, use Secrets
2. **Non-root User**: Container runs as UID 1001
3. **Read-only Root**: Consider enabling for enhanced security
4. **Network Policies**: Restrict egress to CrowdStrike API only
5. **RBAC**: Minimal permissions in Kubernetes
6. **Pod Security**: Apply restricted Pod Security Standards
7. **Image Scanning**: Scan container images for vulnerabilities

## Support and Troubleshooting

For issues:

1. Check logs: `docker logs` or `kubectl logs`
2. Verify health: `curl http://localhost:8088/health`
3. Review metrics: `curl http://localhost:8088/metrics`
4. Check configuration: Validate YAML syntax
5. Test API credentials: Run `policy-audit fetch` manually
