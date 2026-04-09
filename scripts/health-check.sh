#!/bin/bash
# Health Check Script for Advanced SFTP Exporter
# Usage: ./scripts/health-check.sh [docker|k8s] [interval]

DEPLOYMENT_TYPE="${1:-docker}"
CHECK_INTERVAL="${2:-30}"
NAMESPACE="sftp-exporter"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_docker_health() {
    echo "=== Docker Health Check ==="
    
    # Check if services running
    echo -e "\n${YELLOW}Service Status:${NC}"
    docker-compose ps
    
    # Check metrics endpoint
    echo -e "\n${YELLOW}Metrics Endpoint:${NC}"
    if curl -s http://localhost:1210/metrics > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Metrics endpoint responding"
        METRIC_COUNT=$(curl -s http://localhost:1210/metrics | grep -c "^#")
        echo "  Metric families: $METRIC_COUNT"
    else
        echo -e "${RED}✗${NC} Metrics endpoint not responding"
    fi
    
    # Check health endpoint
    echo -e "\n${YELLOW}Health Endpoint:${NC}"
    if curl -s http://localhost:1210/health > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Health endpoint responding"
        HEALTH=$(curl -s http://localhost:1210/health)
        echo "  $HEALTH" | jq .
    else
        echo -e "${RED}✗${NC} Health endpoint not responding"
    fi
    
    # Check container logs for errors
    echo -e "\n${YELLOW}Recent Errors:${NC}"
    ERROR_COUNT=$(docker-compose logs sftp-exporter | grep -i error | wc -l)
    if [ $ERROR_COUNT -eq 0 ]; then
        echo -e "${GREEN}✓${NC} No errors found"
    else
        echo -e "${YELLOW}⚠${NC} Found $ERROR_COUNT errors"
        docker-compose logs sftp-exporter | grep -i error | tail -5
    fi
}

check_k8s_health() {
    echo "=== Kubernetes Health Check ==="
    
    # Check pod status
    echo -e "\n${YELLOW}Pod Status:${NC}"
    kubectl get pods -n $NAMESPACE
    
    # Check pod readiness
    echo -e "\n${YELLOW}Pod Readiness:${NC}"
    kubectl get pods -n $NAMESPACE -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}'
    
    # Check metrics endpoint
    echo -e "\n${YELLOW}Metrics Collection:${NC}"
    POD=$(kubectl get pod -n $NAMESPACE -o jsonpath='{.items[0].metadata.name}')
    if kubectl exec -n $NAMESPACE $POD -- wget -q -O - http://localhost:1210/metrics > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Metrics endpoint responding"
        METRIC_COUNT=$(kubectl exec -n $NAMESPACE $POD -- wget -q -O - http://localhost:1210/metrics 2>/dev/null | grep -c "^#" || echo "0")
        echo "  Metric families: $METRIC_COUNT"
    else
        echo -e "${RED}✗${NC} Metrics endpoint not responding"
    fi
    
    # Check resource usage
    echo -e "\n${YELLOW}Resource Usage:${NC}"
    kubectl top pods -n $NAMESPACE
    
    # Check recent events
    echo -e "\n${YELLOW}Recent Events:${NC}"
    kubectl get events -n $NAMESPACE --sort-by='.lastTimestamp' | tail -10
}

continuous_check() {
    echo "Starting continuous health checks (interval: ${CHECK_INTERVAL}s)"
    echo "Press Ctrl+C to stop"
    
    while true; do
        clear
        echo "=== Health Check - $(date) ==="
        
        case $DEPLOYMENT_TYPE in
            docker)
                check_docker_health
                ;;
            k8s)
                check_k8s_health
                ;;
        esac
        
        echo -e "\nNext check in ${CHECK_INTERVAL} seconds..."
        sleep $CHECK_INTERVAL
    done
}

# Main
case $DEPLOYMENT_TYPE in
    docker)
        continuous_check
        ;;
    k8s)
        continuous_check
        ;;
    *)
        echo "Usage: $0 [docker|k8s] [interval]"
        exit 1
        ;;
esac
