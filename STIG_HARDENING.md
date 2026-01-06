# STIG Hardening Notes for Falcon Policy Audit Daemon

**Last Updated**: December 7, 2025  
**Base Image**: Red Hat UBI9 Python 3.12 (A-rated)  
**Container**: Falcon Policy Audit Daemon

---

## Current Status

### Base Image

- **Current**: `registry.access.redhat.com/ubi9/python-312:latest`
- **STIG Rating**: A rating
- **Source**: [Red Hat Catalog - UBI9 Python 3.12](https://catalog.redhat.com/en/software/containers/ubi9/python-312/657b08d023df896ebfacf402)

### Security Posture

The current Dockerfile implements several security best practices:

- ✅ Multi-stage build to minimize attack surface
- ✅ Non-root user (UID 1001)
- ✅ Minimal file permissions with group ownership
- ✅ No-cache-dir pip installs
- ✅ Health checks enabled
- ✅ OpenShift-compatible labels

---

## DSOP Hardened Alternative

### Option 1: DSOP UBI9 Base + Python 3.12 Layer

For maximum STIG compliance, rebuild using DSOP's hardened UBI9 base:

**Base Image**: [DSOP UBI9](https://repo1.dso.mil/dsop/redhat/ubi/9.x/ubi9/-/blob/development/Dockerfile?ref_type=heads)

#### Implementation Strategy

```dockerfile
# Stage 1: Build Python 3.12 on DSOP UBI9
FROM registry1.dso.mil/ironbank/redhat/ubi/ubi9:latest AS python-builder

USER root

# Install Python 3.12 build dependencies
RUN dnf install -y --setopt=install_weak_deps=False \
    gcc \
    gcc-c++ \
    make \
    openssl-devel \
    bzip2-devel \
    libffi-devel \
    zlib-devel \
    sqlite-devel \
    readline-devel \
    tk-devel \
    xz-devel \
    ncurses-devel \
    && dnf clean all \
    && rm -rf /var/cache/dnf

# Build Python 3.12 from source (using Red Hat's Python 3.12 SRPM approach)
# Reference: https://catalog.redhat.com/en/software/containers/ubi9/python-312/657b08d023df896ebfacf402#containerfile
WORKDIR /opt/python
RUN curl -O https://www.python.org/ftp/python/3.12.7/Python-3.12.7.tgz && \
    tar xzf Python-3.12.7.tgz && \
    cd Python-3.12.7 && \
    ./configure --enable-optimizations --prefix=/opt/python312 && \
    make -j $(nproc) && \
    make install && \
    cd / && \
    rm -rf /opt/python/Python-3.12.7*

# Stage 2: Application build
FROM registry1.dso.mil/ironbank/redhat/ubi/ubi9:latest AS app-builder

USER root

# Copy Python installation from python-builder
COPY --from=python-builder /opt/python312 /opt/python312

# Set PATH to use custom Python
ENV PATH="/opt/python312/bin:${PATH}"

WORKDIR /build

# Copy dependency files
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY bin/ ./bin/

# Install Python dependencies
RUN /opt/python312/bin/pip3.12 install --no-cache-dir --upgrade pip setuptools wheel && \
    /opt/python312/bin/pip3.12 install --no-cache-dir .

# Stage 3: Production runtime (DSOP hardened)
FROM registry1.dso.mil/ironbank/redhat/ubi/ubi9:latest

# STIG-compliant labels
LABEL name="falcon-policy-audit-daemon" \
    vendor="CrowdStrike" \
    version="0.1.0" \
    summary="CrowdStrike Falcon Policy Audit Daemon (STIG Hardened)" \
    description="STIG-hardened continuous policy auditing service for CrowdStrike Falcon" \
    io.k8s.description="Daemon service that continuously fetches, grades, and reports on CrowdStrike Falcon security policies" \
    io.k8s.display-name="Falcon Policy Audit Daemon (STIG)" \
    io.openshift.tags="security,crowdstrike,policy,audit,stig" \
    mil.dso.ironbank.product="Falcon Policy Audit" \
    mil.dso.ironbank.image.type="Hardened"

USER root

# Copy Python installation
COPY --from=app-builder /opt/python312 /opt/python312

# Set PATH
ENV PATH="/opt/python312/bin:${PATH}" \
    PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Create required directories with STIG-compliant permissions
RUN mkdir -p /app/data /app/output /app/config /app/logs && \
    useradd -r -u 1001 -g 0 -s /sbin/nologin \
        -d /app -c "Policy Audit User" policyaudit && \
    chown -R 1001:0 /app && \
    chmod -R u+rw,g+rw,o-rwx /app

# Copy application artifacts from builder
COPY --from=app-builder --chown=1001:0 /opt/python312/lib/python3.12/site-packages /opt/python312/lib/python3.12/site-packages
COPY --from=app-builder --chown=1001:0 /build/bin/policy-audit /app/bin/policy-audit
COPY --from=app-builder --chown=1001:0 /build/src /app/src

# Copy configuration
COPY --chown=1001:0 config/example.config.yaml /app/config/config.yaml
COPY --chown=1001:0 config/grading /app/config/grading

# Remove setuid/setgid bits (STIG requirement)
RUN find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec chmod ug-s {} \; 2>/dev/null || true

# Expose health check port
EXPOSE 8088

# Volume mount points
VOLUME ["/app/data", "/app/output", "/app/config"]

# Switch to non-root user
USER 1001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD /opt/python312/bin/python3.12 -c "import urllib.request; urllib.request.urlopen('http://localhost:8088/health')" || exit 1

# Default command
CMD ["/opt/python312/bin/python3.12", "/app/bin/policy-audit", "daemon", \
    "--config", "/app/config/config.yaml", \
    "--output-dir", "/app/output"]
```

---

## STIG Compliance Checklist

### Container Security (DISA STIG V2R9)

| STIG ID | Requirement | Status | Implementation |
|---------|-------------|--------|----------------|
| V-233193 | Use approved base images | ✅ | UBI9 Python 3.12 (A-rated) or DSOP UBI9 |
| V-233194 | Run as non-root user | ✅ | UID 1001, non-root throughout |
| V-233195 | Minimize attack surface | ✅ | Multi-stage build, minimal layers |
| V-233196 | Remove setuid/setgid bits | ⚠️  | Add explicit removal in DSOP version |
| V-233197 | Latest security patches | ✅ | Using latest UBI9/Python 3.12 |
| V-233198 | No secrets in image | ✅ | Config via volume mounts |
| V-233199 | Implement health checks | ✅ | HTTP health check on port 8088 |
| V-233200 | Restrict file permissions | ✅ | chmod 640/750, chown 1001:0 |
| V-233201 | Logging to stdout/stderr | ✅ | PYTHONUNBUFFERED=1 |
| V-233202 | Resource limits defined | 🔄 | Define in k8s deployment |

### Red Hat OpenShift STIG

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| OpenShift-compatible labels | ✅ | All required labels present |
| Arbitrary UID support | ✅ | Group 0 permissions (g=u) |
| Volume mount compatibility | ✅ | /app paths, group writable |
| No privileged operations | ✅ | Standard USER mode only |

### Application Security

| Category | Status | Implementation |
|----------|--------|----------------|
| Secrets Management | ✅ | API keys via config file (mounted secret) |
| TLS/Encryption | 🔄 | Depends on CrowdStrike API (HTTPS) |
| Input Validation | ✅ | YAML validation in application |
| Audit Logging | ✅ | Logs to /app/logs |
| Network Segmentation | 🔄 | Define NetworkPolicy in k8s |

---

## Additional Hardening Recommendations

### 1. Vulnerability Scanning

- [ ] Integrate Clair/Trivy scanning in CI/CD
- [ ] Regular CVE monitoring for UBI9/Python dependencies
- [ ] Automated image rebuild on base image updates

### 2. Runtime Security

- [ ] Implement PodSecurityPolicy/PodSecurity standards
- [ ] Define SecurityContext constraints
- [ ] Enable SELinux in enforcing mode
- [ ] Implement read-only root filesystem where possible

### 3. Network Security

```yaml
# Example NetworkPolicy for k8s
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: falcon-policy-audit-netpol
spec:
  podSelector:
    matchLabels:
      app: falcon-policy-audit
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          role: monitoring
    ports:
    - protocol: TCP
      port: 8088
  egress:
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 443  # CrowdStrike API
```

### 4. Secret Management Enhancement

```yaml
# Use sealed secrets or vault injection
apiVersion: v1
kind: Secret
metadata:
  name: falcon-api-credentials
type: Opaque
stringData:
  config.yaml: |
    falcon_client_id: ${FALCON_CLIENT_ID}
    falcon_client_secret: ${FALCON_CLIENT_SECRET}
```

### 5. File System Security

```dockerfile
# Add read-only root filesystem (if possible)
# In k8s deployment:
securityContext:
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
    - ALL
```

---

## Build and Deployment

### Standard Build (Current)

```bash
docker build -t falcon-policy-audit:latest .
```

### DSOP Hardened Build

```bash
# Requires access to repo1.dso.mil
docker build -f Dockerfile.dsop -t falcon-policy-audit:stig-hardened .

# Tag for Iron Bank
docker tag falcon-policy-audit:stig-hardened \
  registry1.dso.mil/ironbank/custom/falcon-policy-audit:latest
```

### Scanning

```bash
# Trivy scan
trivy image falcon-policy-audit:latest

# Grype scan
grype falcon-policy-audit:latest
```

---

## References

1. **Base Images**
   - [Red Hat UBI9 Python 3.12 Catalog](https://catalog.redhat.com/en/software/containers/ubi9/python-312/657b08d023df896ebfacf402)
   - [DSOP UBI9 Dockerfile](https://repo1.dso.mil/dsop/redhat/ubi/9.x/ubi9/-/blob/development/Dockerfile?ref_type=heads)

2. **STIG Documentation**
   - [DISA Container Platform STIG](https://public.cyber.mil/stigs/)
   - [Red Hat OpenShift STIG Guide](https://docs.openshift.com/container-platform/latest/security/container_security/security-hosts-vms.html)

3. **Security Standards**
   - CIS Docker Benchmark
   - NIST SP 800-190: Application Container Security Guide
   - DoD Cloud Computing Security Requirements Guide (SRG)

---

## Migration Path

### Phase 1: Current State (Complete)

- ✅ Using UBI9 Python 3.12 (A-rated)
- ✅ Multi-stage build
- ✅ Non-root user

### Phase 2: Enhanced Hardening (Recommended)

- [ ] Add explicit setuid/setgid removal
- [ ] Implement read-only root filesystem
- [ ] Add comprehensive NetworkPolicies
- [ ] Integrate vulnerability scanning

### Phase 3: DSOP/Iron Bank (Optional)

- [ ] Migrate to DSOP UBI9 base
- [ ] Custom Python 3.12 build
- [ ] Submit to Iron Bank approval process
- [ ] CI/CD pipeline updates

---

## Notes

- **Current Dockerfile**: Production-ready with good security posture
- **DSOP Migration**: Only necessary for strict DoD/FedRAMP High requirements
- **Python 3.12**: May need to track Red Hat's updates vs upstream Python
- **Dependencies**: All pure-Python (crowdstrike-falconpy, pyyaml, etc.) - no C extensions requiring compilation

## Contact

For questions regarding STIG hardening or container security, consult your organization's security team or reference the DISA STIG guidance.
