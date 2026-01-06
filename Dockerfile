# Multi-stage Dockerfile for CrowdStrike Falcon Policy Audit Daemon
# Base: Red Hat Universal Base Image (UBI) 9
#
# Version is dynamically set from pyproject.toml via build arg:
#   docker build --build-arg VERSION=$(python -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])") .
# Or simply use: make docker-build (which does this automatically)

# ============================================================================
# Stage 1: Build stage
# ============================================================================
FROM registry.access.redhat.com/ubi9/python-312:latest AS builder

USER root

# Set working directory
WORKDIR /build

# Copy dependency files
COPY pyproject.toml ./
COPY README.md ./

# Copy source code
COPY src/ ./src/
COPY bin/ ./bin/

# Install Python dependencies (no compilation needed for these pure-Python packages)
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir .

# ============================================================================
# Stage 2: Production runtime stage
# ============================================================================
FROM registry.access.redhat.com/ubi9/python-312:latest

# Build argument for version (can be passed at build time, or use a default)
ARG VERSION

# Labels for container metadata
LABEL name="falcon-policy-audit-daemon" \
    vendor="CrowdStrike" \
    version="${VERSION:-unknown}" \
    summary="CrowdStrike Falcon Policy Audit Daemon" \
    description="Continuous policy auditing service for CrowdStrike Falcon" \
    io.k8s.description="Daemon service that continuously fetches, grades, and reports on CrowdStrike Falcon security policies" \
    io.k8s.display-name="Falcon Policy Audit Daemon" \
    io.openshift.tags="security,crowdstrike,policy,audit"

# Create non-root user (UBI images already have default user 1001, just use it)
USER root

# Set working directory
WORKDIR /app

# Create directories for data, output, and config
RUN mkdir -p /app/data /app/output /app/config /app/logs && \
    chown -R 1001:0 /app && \
    chmod -R g=u /app

# Copy Python packages from builder
COPY --from=builder --chown=1001:0 /opt/app-root/lib/python3.12/site-packages /opt/app-root/lib/python3.11/site-packages

# Copy console script from builder
COPY --from=builder --chown=1001:0 /opt/app-root/bin/policy-audit /opt/app-root/bin/policy-audit

# Copy application files (for direct access if needed)
COPY --from=builder --chown=1001:0 /build/bin/policy-audit /app/bin/policy-audit
COPY --from=builder --chown=1001:0 /build/src /app/src

# Copy example config as default (can be overridden by volume mount)
COPY --chown=1001:0 config/example.config.yaml /app/config/config.yaml

# Copy grading configs
COPY --chown=1001:0 config/grading /app/config/grading

# Set Python path
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

# Expose health check port
EXPOSE 8088

# Volume mount points
VOLUME ["/app/data", "/app/output", "/app/config"]

# Switch to non-root user
USER 1001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8088/health || exit 1

# Default command: run daemon
CMD ["policy-audit", "daemon", \
    "--config", "/app/config/config.yaml", \
    "--output-dir", "/app/output"]
