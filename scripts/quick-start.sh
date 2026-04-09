#!/bin/bash
# Quick Start Script for Advanced SFTP Exporter Phase 5
# Usage: ./scripts/quick-start.sh [docker|k8s|helm]

set -e

DEPLOYMENT_TYPE="${1:-docker}"
NAMESPACE="sftp-exporter"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}➜${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    case $DEPLOYMENT_TYPE in
        docker)
            print_info "Checking Docker prerequisites..."
            if ! command -v docker &> /dev/null; then
                print_error "Docker not found. Please install Docker."
                exit 1
            fi
            if ! command -v docker-compose &> /dev/null; then
                print_error "Docker Compose not found. Please install Docker Compose."
                exit 1
            fi
            docker --version
            docker-compose --version
            print_success "Docker prerequisites verified"
            ;;
        k8s|helm)
            print_info "Checking Kubernetes prerequisites..."
            if ! command -v kubectl &> /dev/null; then
                print_error "kubectl not found. Please install kubectl."
                exit 1
            fi
            if [ "$DEPLOYMENT_TYPE" = "helm" ] && ! command -v helm &> /dev/null; then
                print_error "Helm not found. Please install Helm."
                exit 1
            fi
            kubectl cluster-info
            print_success "Kubernetes prerequisites verified"
            ;;
    esac
}

# Docker deployment
deploy_docker() {
    print_info "Starting Docker deployment..."
    
    cd "$PROJECT_ROOT"
    
    # Build image
    print_info "Building Docker image..."
    docker-compose build sftp-exporter
    print_success "Image built"
    
    # Start services
    print_info "Starting services..."
    docker-compose up -d
    
    # Wait for services
    print_info "Waiting for services to be ready..."
    sleep 10
    
    # Verify
    docker-compose ps
    
    # Display URLs
    cat << EOF

${GREEN}Docker Deployment Complete!${NC}

${BLUE}Service URLs:${NC}
  • Prometheus: http://localhost:9090
  • Grafana: http://localhost:3000 (admin/admin)
  • SFTP Exporter: http://localhost:1210/metrics
  • AlertManager: http://localhost:9093

${BLUE}Quick Commands:${NC}
  • View logs: docker-compose logs -f sftp-exporter
  • Stop services: docker-compose down
  • Health check: curl http://localhost:1210/health

EOF
}

# Kubernetes deployment
deploy_k8s() {
    print_info "Starting Kubernetes deployment..."
    
    # Create namespace
    print_info "Creating namespace..."
    kubectl create namespace $NAMESPACE || true
    print_success "Namespace ready"
    
    # Apply manifests
    print_info "Applying Kubernetes manifests..."
    kubectl apply -f "$PROJECT_ROOT/k8s/"
    print_success "Manifests applied"
    
    # Wait for deployment
    print_info "Waiting for deployment..."
    kubectl rollout status deployment/sftp-exporter -n $NAMESPACE --timeout=300s
    print_success "Deployment ready"
    
    # Display instructions
    cat << EOF

${GREEN}Kubernetes Deployment Complete!${NC}

${BLUE}Current Status:${NC}
EOF
    kubectl get all -n $NAMESPACE
    
    cat << EOF

${BLUE}Quick Commands:${NC}
  • Port forward: kubectl port-forward -n $NAMESPACE svc/sftp-exporter 1210:1210
  • View logs: kubectl logs -n $NAMESPACE -l app=advanced-sftp-exporter -f
  • Check pods: kubectl get pods -n $NAMESPACE -w
  • Scale replicas: kubectl scale deployment sftp-exporter -n $NAMESPACE --replicas=5

EOF
}

# Helm deployment
deploy_helm() {
    print_info "Starting Helm deployment..."
    
    # Validate chart
    print_info "Validating Helm chart..."
    helm lint "$PROJECT_ROOT/helm/advanced-sftp-exporter/"
    print_success "Chart valid"
    
    # Create namespace
    print_info "Creating namespace..."
    kubectl create namespace $NAMESPACE || true
    
    # Install release
    print_info "Installing Helm release..."
    helm install sftp-exporter "$PROJECT_ROOT/helm/advanced-sftp-exporter/" \
        --namespace $NAMESPACE \
        --create-namespace
    
    print_success "Helm release installed"
    
    # Wait for deployment
    print_info "Waiting for pods to start..."
    kubectl rollout status deployment/sftp-exporter -n $NAMESPACE --timeout=300s
    print_success "Deployment ready"
    
    # Display status
    cat << EOF

${GREEN}Helm Deployment Complete!${NC}

${BLUE}Release Status:${NC}
EOF
    helm status sftp-exporter -n $NAMESPACE
    
    cat << EOF

${BLUE}Quick Commands:${NC}
  • Upgrade release: helm upgrade sftp-exporter ./helm/advanced-sftp-exporter -n $NAMESPACE
  • Rollback: helm rollback sftp-exporter -n $NAMESPACE
  • Uninstall: helm uninstall sftp-exporter -n $NAMESPACE
  • Get values: helm get values sftp-exporter -n $NAMESPACE

EOF
}

# Main execution
main() {
    print_info "Advanced SFTP Exporter Phase 5 - Quick Start"
    print_info "Deployment Type: $DEPLOYMENT_TYPE"
    
    check_prerequisites
    
    case $DEPLOYMENT_TYPE in
        docker)
            deploy_docker
            ;;
        k8s)
            deploy_k8s
            ;;
        helm)
            deploy_helm
            ;;
        *)
            print_error "Unknown deployment type: $DEPLOYMENT_TYPE"
            echo "Usage: $0 [docker|k8s|helm]"
            exit 1
            ;;
    esac
    
    print_success "Deployment completed successfully!"
}

main "$@"
