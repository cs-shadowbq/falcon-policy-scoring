#!/bin/bash
# Kubernetes deployment script for Falcon Policy Audit Daemon

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Variables
NAMESPACE="${NAMESPACE:-endpoint-readiness-audit}"

# Functions
print_header() {
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${GREEN}========================================${NC}\n"
}

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Deploy to Kubernetes
deploy_k8s() {
    print_header "Deploying to Kubernetes"
    
    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl not found. Please install kubectl."
        exit 1
    fi
    
    # Create namespace if it doesn't exist
    print_info "Ensuring namespace '$NAMESPACE' exists..."
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Apply manifests
    print_info "Applying Kubernetes manifests..."
    kubectl apply -f k8s/rbac.yaml
    kubectl apply -f k8s/persistent-volume-claim.yaml
    kubectl apply -f k8s/configmap.yaml
    kubectl apply -f k8s/secret.yaml
    kubectl apply -f k8s/service.yaml
    kubectl apply -f k8s/deployment.yaml
    
    print_info "Waiting for deployment to be ready..."
    kubectl wait --for=condition=available --timeout=300s \
        deployment/falcon-policy-audit-daemon -n "$NAMESPACE" || true
    
    # Show status
    print_info "Deployment status:"
    kubectl get pods -n "$NAMESPACE" -l app=falcon-policy-audit
    
    print_info "Deployment complete!"
}

# Check Kubernetes deployment status
check_k8s() {
    print_header "Checking Kubernetes Deployment"
    
    print_info "Pods:"
    kubectl get pods -n "$NAMESPACE" -l app=falcon-policy-audit
    
    print_info "\nServices:"
    kubectl get svc -n "$NAMESPACE" -l app=falcon-policy-audit
    
    print_info "\nPersistent Volume Claims:"
    kubectl get pvc -n "$NAMESPACE" -l app=falcon-policy-audit
    
    print_info "\nRecent logs:"
    kubectl logs -n "$NAMESPACE" -l app=falcon-policy-audit --tail=20
}

# Tail logs from Kubernetes
logs_k8s() {
    print_header "Tailing Kubernetes Logs"
    kubectl logs -n "$NAMESPACE" -l app=falcon-policy-audit -f
}

# Port forward for local access
port_forward() {
    print_header "Port Forwarding"
    print_info "Forwarding port 8088 to localhost..."
    print_info "Health check: http://localhost:8088/health"
    print_info "Metrics: http://localhost:8088/metrics"
    print_info "Press Ctrl+C to stop"
    
    kubectl port-forward -n "$NAMESPACE" svc/falcon-policy-audit 8088:8088
}

# Delete Kubernetes deployment
delete_k8s() {
    print_header "Deleting Kubernetes Deployment"
    
    read -p "Are you sure you want to delete the deployment? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Cancelled."
        exit 0
    fi
    
    print_info "Deleting resources..."
    kubectl delete -f k8s/ -n "$NAMESPACE" || true
    
    print_info "Deletion complete!"
}

# Show usage
usage() {
    cat << EOF
Usage: $0 <command> [options]

Commands:
    deploy          Deploy to Kubernetes
    check           Check Kubernetes deployment status
    logs            Tail Kubernetes logs
    port-forward    Forward port 8088 for local access
    delete          Delete Kubernetes deployment

Environment Variables:
    NAMESPACE       Kubernetes namespace (default: endpoint-readiness-audit)

Examples:
    # Deploy to Kubernetes
    $0 deploy

    # Check deployment status
    $0 check

    # View logs
    $0 logs

    # Access locally via port forward
    $0 port-forward
    curl http://localhost:8088/health

    # Remove deployment
    $0 delete

Note:
    For Docker operations (build, test, push), use the Makefile:
        make docker-build
        make docker-test
        make docker-push REGISTRY=your-registry.com

EOF
}

# Main script
main() {
    case "${1:-}" in
        deploy)
            deploy_k8s
            ;;
        check)
            check_k8s
            ;;
        logs)
            logs_k8s
            ;;
        port-forward)
            port_forward
            ;;
        delete)
            delete_k8s
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
