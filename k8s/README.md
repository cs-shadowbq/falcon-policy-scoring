# Kubernetes Deployment Guide for Falcon Policy Audit Daemon

This directory contains Kubernetes manifests for deploying the Falcon Policy Audit Daemon.

The manifest files are provided as a reference implementation for deploying the Falcon Policy Audit Daemon in a Kubernetes environment. You should customize these manifests to fit your specific deployment needs.

The files are organized as follows:

- `namespace.yaml`: Defines the Namespace for the Falcon Policy Audit Daemon.
- `deployment.yaml`: Defines the Deployment for the Falcon Policy Audit Daemon.
- `service.yaml`: Defines the Service to expose the Daemon's health and metrics endpoints.
- `configmap.yaml`: Contains configuration settings for the Daemon.
- `secret.yaml`: Stores CrowdStrike API credentials securely.
- `persistent-volume-claim.yaml`: Defines PersistentVolumeClaims for data, output, and logs.
- `rbac.yaml`: Defines RBAC roles and bindings for the Daemon.

## Prerequisites

- Kubernetes cluster (v1.20+)
- kubectl configured to access your cluster
- CrowdStrike API credentials (Client ID and Secret)
- Storage provisioner for PersistentVolumeClaims

## Quick Start

### 1. Create Namespace

```bash
kubectl apply -f k8s/namespace.yaml
```

### 2. Configure API Credentials

Edit `secret.yaml` and replace the placeholder values with your actual CrowdStrike API credentials:

```bash
kubectl apply -f k8s/secret.yaml
```

### 3. Deploy Application

```bash
kubectl apply -f k8s/
```

### 4. Verify Deployment

```bash
# Check pod status
kubectl get pods -n endpoint-readiness-audit

# Check logs
kubectl logs -n endpoint-readiness-audit -l app=falcon-policy-audit -f

# Check health
kubectl port-forward -n endpoint-readiness-audit svc/falcon-policy-audit 8088:8088
curl http://localhost:8088/health
```

## Configuration

### Adjusting Resources

For larger deployments (100k+ hosts), adjust resource limits in `deployment.yaml`:

```yaml
resources:
  requests:
    cpu: 1000m
    memory: 2Gi
  limits:
    cpu: 4000m
    memory: 8Gi
```

### Modifying Schedule

Edit the `configmap.yaml` to adjust task schedules:

```yaml
daemon:
  schedules:
    fetch_and_grade: "*/30 * * * *"  # Every 30 minutes
    cleanup: "0 3 * * *"              # Daily at 3 AM
```

### Storage Configuration

Adjust PVC sizes in `persistent-volume-claim.yaml` based on your needs:

- `falcon-policy-audit-data`: Database storage (10Gi default)
- `falcon-policy-audit-output`: JSON reports storage (50Gi default)
- `falcon-policy-audit-logs`: Log files storage (5Gi default)

## Monitoring

### Health Checks

The daemon exposes health check endpoints:

- `/health` - Liveness probe (is the service running?)
- `/ready` - Readiness probe (is the service ready?)
- `/metrics` - Metrics endpoint (Prometheus format)

### Prometheus Integration

The deployment is annotated for Prometheus scraping:

```yaml
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "8088"
  prometheus.io/path: "/metrics"
```

## Accessing Reports

Reports are written to the persistent volume mounted at `/app/output`. Access them:

### Option 1: Port Forward and API

```bash
# Port forward to the pod
kubectl port-forward -n endpoint-readiness-audit $(kubectl get pod -n endpoint-readiness-audit -l app=falcon-policy-audit -o name) 8088:8088

# Access metrics
curl http://localhost:8088/metrics
```

### Option 2: Exec into Pod

```bash
kubectl exec -it -n endpoint-readiness-audit $(kubectl get pod -n endpoint-readiness-audit -l app=falcon-policy-audit -o name) -- ls /app/output
```

### Option 3: Mount PVC to Debug Pod

```bash
kubectl run -it --rm debug --image=busybox --restart=Never -n endpoint-readiness-audit -- sh
# Then mount the PVC in the debug pod spec
```

## Scaling Considerations

### For 100k+ Hosts

1. **Increase Resources**:
   - CPU: 2-4 cores
   - Memory: 4-8 GB
   - Storage: Scale based on retention policy

2. **Adjust Rate Limits**: Edit configmap.yaml:

   ```yaml
   rate_limit:
     requests_per_second: 15.0
     requests_per_minute: 750
   ```

3. **Optimize Schedule**: Reduce frequency for large environments:

   ```yaml
   schedules:
     fetch_and_grade: "*/30 * * * *"  # Every 30 minutes
   ```

## Troubleshooting

### Pod Not Starting

```bash
# Check pod events
kubectl describe pod -n endpoint-readiness-audit -l app=falcon-policy-audit

# Check logs
kubectl logs -n endpoint-readiness-audit -l app=falcon-policy-audit
```

### API Connection Issues

```bash
# Verify secret is configured
kubectl get secret falcon-api-credentials -n endpoint-readiness-audit -o yaml

# Check environment variables in pod
kubectl exec -n endpoint-readiness-audit $(kubectl get pod -n endpoint-readiness-audit -l app=falcon-policy-audit -o name) -- env | grep FALCON
```

### Storage Issues

```bash
# Check PVC status
kubectl get pvc -n endpoint-readiness-audit

# Check PV binding
kubectl get pv
```

### Health Check Failures

```bash
# Test health endpoint directly
kubectl port-forward -n endpoint-readiness-audit svc/falcon-policy-audit 8088:8088
curl http://localhost:8088/health
curl http://localhost:8088/ready
```

## Cleanup

```bash
# Delete all resources
kubectl delete -f k8s/

# Delete namespace (removes everything)
kubectl delete namespace endpoint-readiness-audit
```

## Security Notes

1. **API Credentials**: Store in Kubernetes Secrets, never in code
2. **Non-Root**: Container runs as non-root user (UID 1001)
3. **Read-Only Root**: Consider enabling read-only root filesystem
4. **Network Policies**: Add NetworkPolicy to restrict egress/ingress
5. **Pod Security**: Apply Pod Security Standards (restricted profile)

## Support

For issues or questions:

- Check logs: `kubectl logs -n endpoint-readiness-audit -l app=falcon-policy-audit`
- Review metrics: Access `/metrics` endpoint
- Check health: Access `/health` and `/ready` endpoints
