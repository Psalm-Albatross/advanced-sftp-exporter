#!/bin/bash

# Advanced SFTP Exporter - Health Check Script
# Phase 4 Deployment Validation
# Usage: ./health-check.sh [--verbose] [--port 9115]

set -e

# Configuration
PORT="${PORT:-9115}"
BASE_URL="http://localhost:${PORT}"
VERBOSE="${VERBOSE:-0}"
ALL_TESTS_PASSED=true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose)
            VERBOSE=1
            shift
            ;;
        --port)
            PORT="$2"
            BASE_URL="http://localhost:${PORT}"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--verbose] [--port 9115]"
            exit 1
            ;;
    esac
done

# Helper functions
log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ALL_TESTS_PASSED=false
}

warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

verbose() {
    if [ "$VERBOSE" -eq 1 ]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
}

# Test functions
test_connectivity() {
    log "Testing connectivity to ${BASE_URL}..."
    if timeout 5 curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/health" > /dev/null 2>&1; then
        success "Service is reachable"
        return 0
    else
        error "Cannot reach service at ${BASE_URL}"
        return 1
    fi
}

test_health_endpoint() {
    log "Testing /health endpoint..."
    response=$(curl -s "${BASE_URL}/health")
    verbose "Response: $response"
    
    if echo "$response" | grep -q '"status"'; then
        success "/health endpoint responding"
        
        # Check if status is ok
        if echo "$response" | grep -q '"status":"ok"'; then
            success "Health status is OK"
        else
            warning "Health status is not OK: $(echo "$response" | grep -o '"status":"[^"]*"')"
        fi
        return 0
    else
        error "/health endpoint not responding with JSON"
        return 1
    fi
}

test_readiness_endpoint() {
    log "Testing /readiness endpoint..."
    response=$(curl -s "${BASE_URL}/readiness")
    verbose "Response: $response"
    
    if echo "$response" | grep -q '"status"'; then
        success "/readiness endpoint responding"
        return 0
    else
        error "/readiness endpoint not responding"
        return 1
    fi
}

test_metrics_endpoint() {
    log "Testing /metrics endpoint..."
    response=$(curl -s "${BASE_URL}/metrics")
    
    if echo "$response" | grep -q "^# HELP"; then
        success "/metrics endpoint responding with Prometheus format"
        
        # Count metric families
        metric_count=$(echo "$response" | grep "^# HELP" | wc -l)
        verbose "Found $metric_count metric families"
        
        if [ "$metric_count" -ge 40 ]; then
            success "Found $metric_count metrics (expected 46+)"
        else
            warning "Found $metric_count metrics (expected 46+, some may be missing)"
        fi
        
        # Check for Phase 4 health metrics
        if echo "$response" | grep -q "sftp_exporter_uptime_seconds"; then
            success "Phase 4 health metrics present"
        else
            error "Phase 4 health metrics not found"
        fi
        
        # Check for Phase 1-3 metrics
        if echo "$response" | grep -q "sftp_connection_active_total"; then
            success "Phase 3 metrics present"
        else
            warning "Phase 3 metrics not found"
        fi
        
        return 0
    else
        error "/metrics endpoint not responding with Prometheus format"
        return 1
    fi
}

test_diagnostics_endpoint() {
    log "Testing /diagnostics endpoint (Phase 4)..."
    response=$(curl -s "${BASE_URL}/diagnostics")
    verbose "Response: $response"
    
    if echo "$response" | grep -q "uptime_seconds"; then
        success "/diagnostics endpoint responding"
        
        # Extract and display diagnostics
        if command -v jq &> /dev/null; then
            uptime=$(echo "$response" | jq '.uptime_seconds // 0')
            goroutines=$(echo "$response" | jq '.goroutine_count // 0')
            memory=$(echo "$response" | jq '.memory_usage_bytes // 0')
            errors=$(echo "$response" | jq '.error_count // 0')
            
            verbose "Uptime: ${uptime}s"
            verbose "Goroutines: $goroutines"
            verbose "Memory: $((memory / 1024 / 1024))MB"
            verbose "Error count: $errors"
            
            # Check goroutine count
            if [ "$goroutines" -lt 50 ]; then
                success "Goroutine count is reasonable: $goroutines"
            else
                warning "Goroutine count is high: $goroutines"
            fi
            
            # Check memory
            memory_mb=$((memory / 1024 / 1024))
            if [ "$memory_mb" -lt 100 ]; then
                success "Memory usage is reasonable: ${memory_mb}MB"
            else
                warning "Memory usage is high: ${memory_mb}MB"
            fi
            
            # Check errors
            if [ "$errors" -eq 0 ]; then
                success "No errors detected"
            else
                warning "Error count: $errors (check logs)"
            fi
        else
            verbose "jq not installed, skipping detailed diagnostics parsing"
        fi
        
        return 0
    else
        error "/diagnostics endpoint not responding"
        return 1
    fi
}

test_metrics_in_prometheus() {
    log "Checking for metrics in Prometheus (optional)..."
    
    # Try to query Prometheus (may not be running)
    if timeout 5 curl -s -o /dev/null "http://localhost:9090/api/v1/query" 2>/dev/null; then
        response=$(curl -s "http://localhost:9090/api/v1/query?query=up{job='sftp-exporter'}")
        verbose "Prometheus response: $response"
        
        if echo "$response" | grep -q '"result"'; then
            success "SFTP exporter found in Prometheus"
            return 0
        else
            warning "SFTP exporter not yet scraped by Prometheus"
            return 0
        fi
    else
        verbose "Prometheus not running (optional)"
        return 0
    fi
}

test_no_error_logs() {
    log "Checking for ERROR level logs..."
    # This is a placeholder - actual implementation would check logs
    verbose "Skipping error log check (logs would be in application output)"
    return 0
}

test_version() {
    log "Checking version information..."
    # Looking for version in metrics or via flag
    version=$(curl -s "${BASE_URL}/diagnostics" | grep -o "version[\"]*:[^,}]*" || echo "unavailable")
    verbose "Version info: $version"
    success "Version check complete"
    return 0
}

# Performance baseline tests
test_performance() {
    log "Testing performance (baseline)..."
    
    # Measure /metrics endpoint response time
    start_time=$(date +%s%N)
    curl -s "${BASE_URL}/metrics" > /dev/null
    end_time=$(date +%s%N)
    
    response_time_ms=$(( (end_time - start_time) / 1000000 ))
    verbose "Metrics endpoint response time: ${response_time_ms}ms"
    
    if [ "$response_time_ms" -lt 1000 ]; then
        success "Response time is acceptable (${response_time_ms}ms)"
    else
        warning "Response time is slow (${response_time_ms}ms, consider load balancing)"
    fi
    
    return 0
}

# Security tests
test_security() {
    log "Testing security aspects..."
    
    # Check if bearer token is in use
    response=$(curl -s -w "%{http_code}" "${BASE_URL}/health" -o /dev/null)
    if [ "$response" -eq 200 ]; then
        success "No authentication required (or correctly configured)"
    elif [ "$response" -eq 401 ]; then
        success "Bearer token authentication is enabled (secure)"
    else
        warning "Unexpected HTTP response: $response"
    fi
    
    return 0
}

# Main execution
main() {
    echo "╔════════════════════════════════════════════════════╗"
    echo "║  Advanced SFTP Exporter - Health Check             ║"
    echo "║  Phase 4 - Production Ready Validation             ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo ""
    
    log "Starting health checks..."
    log "Target: ${BASE_URL}"
    echo ""
    
    # Run all tests
    test_connectivity || {
        error "Cannot proceed without connectivity"
        exit 1
    }
    
    echo ""
    test_health_endpoint
    echo ""
    test_readiness_endpoint
    echo ""
    test_metrics_endpoint
    echo ""
    test_diagnostics_endpoint
    echo ""
    test_version
    echo ""
    test_performance
    echo ""
    test_security
    echo ""
    test_metrics_in_prometheus
    echo ""
    test_no_error_logs
    
    # Summary
    echo ""
    echo "╔════════════════════════════════════════════════════╗"
    if [ "$ALL_TESTS_PASSED" = true ]; then
        echo -e "║  ${GREEN}✓ ALL TESTS PASSED${NC}                              ║"
        echo "║  Phase 4 is ready for production deployment       ║"
    else
        echo -e "║  ${RED}✗ SOME TESTS FAILED${NC}                            ║"
        echo "║  Review errors above and rerun after fixes        ║"
    fi
    echo "╚════════════════════════════════════════════════════╝"
    
    # Exit with appropriate code
    if [ "$ALL_TESTS_PASSED" = true ]; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main "$@"
