# Phase 4 Deployment Guide

**Target**: Local Testing on macOS  
**Version**: 1.4.0-phase4  
**Date**: April 9, 2026

---

## Quick Start (5 minutes)

### Step 1: Locate Your Binary
```bash
cd /Users/sandeshrajbhopa/Documents/Projects/advanced-sftp-exporter
ls -lh bin/advanced-sftp-exporter-v1.4.0-2-gdf0df49.darwin-arm64
```

Expected output:
```
-rwxr-xr-x  12M  advanced-sftp-exporter-v1.4.0-2-gdf0df49.darwin-arm64
```

### Step 2: Verify Binary Works
```bash
# Check version
./bin/advanced-sftp-exporter-v1.4.0-2-gdf0df49.darwin-arm64 -version

# Expected output:
# Version: 1.4.0-phase4
# Build Date: 2026-04-08T19:25:49Z
# Hash: 2b43863
```

### Step 3: Run with Defaults
```bash
# In one terminal, start the exporter
./bin/advanced-sftp-exporter-v1.4.0-2-gdf0df49.darwin-arm64

# Expected startup:
# time=2026-04-09T10:30:00Z level=INFO msg="Starting Advanced SFTP Exporter" version=1.4.0-phase4
# time=2026-04-09T10:30:00Z level=INFO msg="Web service listening" addr=:9115
```

### Step 4: Test Health Endpoints
```bash
# In another terminal, verify it's running
curl -s http://localhost:9115/health | jq .
curl -s http://localhost:9115/readiness | jq .

# Expected response:
{
  "status": "ok",
  "uptime_seconds": 2.34,
  "monitors_healthy": true,
  "error_count": 0
}
```

### Step 5: View Metrics
```bash
# Get all 46+ metrics
curl -s http://localhost:9115/metrics | head -50

# Sample output:
# # HELP sftp_exporter_goroutine_count Current number of goroutines
# # TYPE sftp_exporter_goroutine_count gauge
# sftp_exporter_goroutine_count 12
#
# # HELP sftp_exporter_memory_usage_bytes Memory usage in bytes
# # TYPE sftp_exporter_memory_usage_bytes gauge
# sftp_exporter_memory_usage_bytes 5242880
```

---

## Configuration

### Finding Your SFTP Log

On macOS, SFTP logs typically come from:

```bash
# Option 1: SSH daemon (common)
tail -f /var/log/system.log | grep sftp

# Option 2: If SFTP is custom-configured
grep -r "sftp" /etc/ssh/

# Option 3: Check sshd config
cat /etc/ssh/sshd_config | grep -i sftp

# Option 4: macOS system log (newer versions)
log stream --predicate 'eventMessage contains[c] "sftp"' --info
```

### Using Configuration Template

Create a config file (see next section), then run:

```bash
./bin/advanced-sftp-exporter-v1.4.0-2-gdf0df49.darwin-arm64 \
  -config /path/to/exporter-config.yaml
```

### Environment Variables

Alternatively, use environment variables:

```bash
export SFTP_EXPORTER_AUTH_LOG="/var/log/system.log"
export SFTP_EXPORTER_HOME_BASE="/Users"
export SFTP_EXPORTER_LOG_LEVEL="INFO"
export SFTP_EXPORTER_WEB_PORT="9115"
export SFTP_EXPORTER_WEB_BEARER_TOKEN="your-secret-token"

./bin/advanced-sftp-exporter-v1.4.0-2-gdf0df49.darwin-arm64
```

---

## Verify All Components

### 1. Metrics Endpoint
```bash
curl -s http://localhost:9115/metrics | wc -l
# Should show 100+ lines of metrics

# Search for Phase 4 health metrics
curl -s http://localhost:9115/metrics | grep "sftp_exporter"
```

### 2. Diagnostics Endpoint
```bash
curl -s http://localhost:9115/diagnostics | jq .

# Expected response includes:
# - uptime_seconds
# - goroutine_count
# - memory_usage_bytes
# - scrape_count
# - error_count
# - active_monitors
# - error_history
```

### 3. All 46+ Metrics Are Present
```bash
# Count unique metric families
curl -s http://localhost:9115/metrics | grep "^# HELP" | wc -l
# Should be: 46 or more
```

### 4. No Errors or Warnings
```bash
# Check logs for errors
# If running in foreground, watch terminal output
# Should see only INFO level logs

# If running in background, check logs:
# Already shown in terminal output
```

---

## Prometheus Integration

### Step 1: Install/Run Prometheus Locally

```bash
# Using Homebrew
brew install prometheus

# Or download from: https://prometheus.io/download/
cd ~/prometheus
./prometheus --config.file=prometheus.yml
```

### Step 2: Create Prometheus Config

Create `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'sftp-exporter'
    static_configs:
      - targets: ['localhost:9115']
    metrics_path: '/metrics'
    scrape_interval: 30s
    scrape_timeout: 10s
```

### Step 3: Query Metrics

Open Prometheus UI: http://localhost:9090

Try these queries:

```promql
# System health
sftp_exporter_uptime_seconds
sftp_exporter_goroutine_count
sftp_exporter_memory_usage_bytes

# Connection tracking
sftp_connection_active_total
sftp_connection_duration_seconds

# Anomaly detection
sftp_anomaly_detection_score

# Bandwidth monitoring
sftp_user_bandwidth_bytes_per_second

# Latency tracking
sftp_file_operation_latency_seconds_bucket
```

---

## Health Checks

### Startup Health Check
```bash
# Wait for service to be ready
for i in {1..10}; do
  if curl -s http://localhost:9115/readiness; then
    echo "✓ Service is ready"
    break
  fi
  echo "Waiting for service to be ready... ($i/10)"
  sleep 2
done
```

### Continuous Monitoring
```bash
# Monitor health every 5 seconds
watch -n 5 'curl -s http://localhost:9115/diagnostics | jq "."'
```

### Error Tracking
```bash
# Get error history
curl -s http://localhost:9115/diagnostics | jq '.error_history'

# Normal response (no errors):
# {
#   "error_history": [],
#   "recovery_state": "healthy"
# }
```

---

## Troubleshooting

### Issue: "Port 9115 already in use"
```bash
# Find what's using the port
lsof -i :9115

# Kill the process (if needed)
kill -9 <PID>

# Or use a different port
./bin/advanced-sftp-exporter-v1.4.0-2-gdf0df49.darwin-arm64 -web.listen-address=:9116
```

### Issue: "Cannot read SFTP log file"
```bash
# Check file permissions
ls -la /var/log/system.log

# May need to adjust permissions or run with elevated privileges
sudo ./bin/advanced-sftp-exporter-v1.4.0-2-gdf0df49.darwin-arm64

# Or check syslog stream instead
log stream --predicate 'eventMessage contains[c] "sftp"' --info
```

### Issue: "No metrics appearing"
```bash
# Verify metrics endpoint is responding
curl -v http://localhost:9115/metrics

# Check Health endpoint
curl -v http://localhost:9115/health

# If still no metrics, check logs for errors
# Look for ERROR level messages in terminal output
```

### Issue: "High goroutine count"
```bash
# Check current goroutine count
curl -s http://localhost:9115/diagnostics | jq '.goroutine_count'

# With Phase 4 optimization:
# - Idle: 8-12 goroutines
# - Active: 20-30 goroutines
# - Pooled max: 10 worker goroutines

# If exceeding 50, check for goroutine leaks
```

---

## Performance Validation

### Metrics Baseline (Phase 4)
```
Memory Usage: 5-8 MB (idle)
Goroutines: 8-12 (idle)
CPU Usage: <1% (idle)
Scrape Latency: 50-200ms
Cardinality: <5000 series
```

### Load Test (Optional)
```bash
# Generate load with Apache Bench
ab -n 1000 -c 10 http://localhost:9115/metrics

# Expected result:
# Requests per second: 100-500
# P50 latency: <50ms
# P99 latency: <200ms
```

---

## Next Steps

### 1. Connect to Grafana (Optional)
- Data source: http://localhost:9090 (Prometheus)
- Create dashboard using metric queries
- See `docs/ARCHITECTURE.md` for Grafana dashboard examples

### 2. Set Up Alerts (Optional)
- Configure alert rules in Prometheus
- See `docs/METRICS.md` for example rules
- Test with sample data

### 3. Production Deployment
- See `docs/DEPLOYMENT.md` for systemd/Kubernetes
- See `PHASE4-CICD-FINAL.md` for CI/CD integration
- See `PHASE5-PLANNING.md` for containerization

### 4. Customization
- Modify config template for your environment
- Add custom monitors (see `internal/monitor/interface.go`)
- Extend metrics as needed (see `docs/ARCHITECTURE.md`)

---

## Validation Checklist

Before considering deployment successful:

- [ ] Binary runs without errors
- [ ] Version flag shows correct version (1.4.0-phase4)
- [ ] `/health` endpoint returns `"status": "ok"`
- [ ] `/readiness` endpoint returns `"status": "ok"`
- [ ] `/metrics` endpoint shows 46+ metric families
- [ ] `/diagnostics` shows healthy status
- [ ] Goroutine count is reasonable (8-30)
- [ ] Memory usage is reasonable (5-10 MB)
- [ ] No ERROR level logs appearing
- [ ] Prometheus scrape succeeds
- [ ] Can query at least 3 different metrics in Prometheus

---

## Support

**Issue**: Check `CONTRIBUTING.md` for development setup  
**Questions**: Review `docs/ARCHITECTURE.md` for system design  
**Metrics**: See `docs/METRICS.md` for 46+ metric reference  
**Problems**: Run `/diagnostics` for detailed system information  

---

**Status**: Phase 4 Production Ready ✅  
**Last Updated**: April 9, 2026
