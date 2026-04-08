# METRICS.md - Advanced SFTP Exporter Metrics Reference

## Overview

This document provides a comprehensive reference for all metrics exported by advanced-sftp-exporter across all phases.

**Total Metrics**: 46+ families with 100+ individual series (depending on cardinality)

---

## Phase 1: Security Hardening Metrics

### User Session Metrics

#### `sftp_users_online`
- **Type**: Gauge
- **Labels**: `user`
- **Description**: Number of active SFTP sessions per user
- **Phase**: 1
- **Example**: `sftp_users_online{user="alice"} 2`

#### `sftp_user_login_type`
- **Type**: Gauge
- **Labels**: `user`, `type`
- **Description**: Login type (password, pubkey, keyboard-interactive)
- **Phase**: 1
- **Example**: `sftp_user_login_type{user="bob", type="pubkey"} 1`

#### `sftp_user_upload_bytes_total`
- **Type**: Counter
- **Labels**: `user`, `file_type`
- **Description**: Total bytes uploaded per user and file type
- **Phase**: 1

#### `sftp_user_download_bytes_total`
- **Type**: Counter
- **Labels**: `user`
- **Description**: Total bytes downloaded per user
- **Phase**: 1

#### `sftp_user_failed_login_attempts_total`
- **Type**: Counter
- **Labels**: `user`, `reason`
- **Description**: Failed login attempts per user (invalid_password, account_locked, etc.)
- **Phase**: 1

### Security Events

#### `sftp_security_anomaly_score`
- **Type**: Gauge
- **Labels**: `user`
- **Description**: Security anomaly score (0-100)
- **Phase**: 1
- **Threshold**: >70 indicates suspicious activity

#### `sftp_user_sudo_commands_total`
- **Type**: Counter
- **Labels**: `user`, `command`
- **Description**: SUDO command executions
- **Phase**: 1

#### `sftp_pam_event_total`
- **Type**: Counter
- **Labels**: `user`, `event_type`, `service`
- **Description**: PAM authentication events
- **Phase**: 1

---

## Phase 2: Performance Optimization Metrics

### Polling Performance

#### `sftp_exporter_poller_stats`
- **Type**: Gauge
- **Labels**: `stat_type`
- **Description**: Poller statistics (active_workers, queued_tasks, completed)
- **Phase**: 2

#### `sftp_exporter_poller_interval_seconds`
- **Type**: Gauge
- **Labels**: `monitor`
- **Description**: Current polling interval (adaptive)
- **Phase**: 2
- **Note**: Backoff increases during idle periods

#### `sftp_exporter_poller_errors_total`
- **Type**: Counter
- **Labels**: `monitor`
- **Description**: Polling errors per monitor
- **Phase**: 2

### Cache Performance

#### `sftp_exporter_cache_hit_rate`
- **Type**: Gauge
- **Description**: Command cache hit rate (0-1)
- **Phase**: 2
- **Expected**: >0.8 indicates good cache behavior

#### `sftp_exporter_metric_cardinality`
- **Type**: Gauge
- **Labels**: `metric_family`
- **Description**: Current cardinality per metric family
- **Phase**: 2
- **Warning**: Alert if excessive growth detected

---

## Phase 3: Rich Metrics & Enhanced Visibility

### Connection Tracking

#### `sftp_connection_active_total`
- **Type**: Gauge
- **Labels**: `user`, `remote_ip`, `session_id`, `protocol_version`
- **Description**: Active SFTP connections
- **Phase**: 3
- **Example**: `sftp_connection_active_total{user="alice", remote_ip="192.168.1.100", session_id="abc123", protocol_version="3"} 1`

#### `sftp_connection_duration_seconds`
- **Type**: Histogram
- **Labels**: `user`, `reason`
- **Description**: Session duration distribution (reason: normal, timeout, error)
- **Phase**: 3
- **Buckets**: [1s, 5s, 10s, 30s, 1m, 5m, 15m, 1h, 4h, 12h, 24h]

#### `sftp_connection_bytes_transferred`
- **Type**: Gauge
- **Labels**: `user`, `session_id`, `direction`
- **Description**: Bytes transferred per session (direction: upload, download)
- **Phase**: 3

### Protocol Intelligence

#### `sftp_protocol_version_info`
- **Type**: Gauge
- **Labels**: `user`, `version`
- **Description**: SFTP version distribution (2 or 3)
- **Phase**: 3

#### `sftp_protocol_renegotiations_total`
- **Type**: Counter
- **Labels**: `user`
- **Description**: SSH renegotiations per user
- **Phase**: 3
- **Alert**: High rate indicates potential DoS

#### `sftp_protocol_keepalive_received_total`
- **Type**: Counter
- **Labels**: `user`
- **Description**: SSH keepalive messages received
- **Phase**: 3

### Anomaly Detection

#### `sftp_anomaly_detection_score`
- **Type**: Gauge
- **Labels**: `user`, `type`
- **Description**: Anomaly scores by component (operation_rate, entropy, time_pattern, command_sequence)
- **Phase**: 3
- **Range**: 0-1 per component, 0-4 aggregate

#### `sftp_user_risk_level`
- **Type**: Gauge
- **Labels**: `user`
- **Description**: Composite risk level (0=low, 1=medium, 2=high, 3=critical)
- **Phase**: 3

### Bandwidth & Quota

#### `sftp_user_bandwidth_bytes_per_second`
- **Type**: Gauge
- **Labels**: `user`
- **Description**: Current bandwidth consumption (bytes/sec)
- **Phase**: 3

#### `sftp_user_quota_usage_percent`
- **Type**: Gauge
- **Labels**: `user`
- **Description**: Quota usage percentage (0-100)
- **Phase**: 3

#### `sftp_user_quota_exceeded_events_total`
- **Type**: Counter
- **Labels**: `user`
- **Description**: Times user exceeded quota
- **Phase**: 3

#### `sftp_bandwidth_throttle_active`
- **Type**: Gauge
- **Labels**: `user`
- **Description**: Is user throttled? (0=no, 1=yes)
- **Phase**: 3

### File Operations

#### `sftp_file_operation_latency_seconds`
- **Type**: Histogram
- **Labels**: `user`, `operation`
- **Description**: File operation latency (operation: get, put, stat, delete, mkdir, rmdir, rename)
- **Phase**: 3
- **Buckets**: [0.001s, 0.005s, 0.01s, 0.05s, 0.1s, 0.5s, 1s, 5s]

#### `sftp_file_size_distribution_bytes`
- **Type**: Histogram
- **Labels**: `user`
- **Description**: File size distribution
- **Phase**: 3
- **Buckets**: [100B, 1KB, 10KB, 100KB, 1MB, 10MB, 100MB, 1GB]

---

## Phase 4: Exporter Health & Diagnostics

### Exporter System Metrics

#### `sftp_exporter_goroutine_count`
- **Type**: Gauge
- **Description**: Current goroutine count
- **Phase**: 4
- **Warning**: Sustained growth may indicate goroutine leak

#### `sftp_exporter_memory_usage_bytes`
- **Type**: Gauge
- **Description**: Memory allocation in bytes
- **Phase**: 4
- **Unit**: Bytes (monitor for OOM)

#### `sftp_exporter_uptime_seconds`
- **Type**: Gauge
- **Description**: Time since exporter start
- **Phase**: 4

#### `sftp_exporter_scrape_count_total`
- **Type**: Counter
- **Description**: Total number of metric scrapes
- **Phase**: 4

#### `sftp_exporter_error_count_total`
- **Type**: Counter
- **Description**: Total errors encountered
- **Phase**: 4

#### `sftp_exporter_scrape_duration_seconds`
- **Type**: Histogram
- **Description**: Metric scrape latency distribution
- **Phase**: 4
- **Buckets**: [1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s]

---

## Cardinality Controls (Phase 2)

The following metric families have cardinality limits:

| Metric | Default Limit | Action |
|--------|---------------|--------|
| `sftp_users_online` | 1000 | Drop new users beyond limit |
| `sftp_user_upload_bytes_total` | 500 file types | Aggregate to "other" |
| `sftp_connection_active_total` | 50 IPs per user | Keep top N, increment overflow |

---

## Metric Query Examples

### Prometheus Queries

```promql
# Total users online
sum(sftp_users_online)

# Failed login rate
rate(sftp_user_failed_login_attempts_total[5m])

# High-risk users
sftp_user_risk_level{user=~".+"} > 2

# Session activity
sum(sftp_connection_active_total) by (protocol_version)

# Bandwidth usage
topk(5, sftp_user_bandwidth_bytes_per_second)

# Exporter health
sftp_exporter_error_count_total / sftp_exporter_scrape_count_total

# Anomaly detection
sftp_anomaly_detection_score > 0.8
```

### Grafana Dashboard Recommendations

**Dashboard 1: Overview**
- Users online (pie chart)
- Error rate (graph)
- Top file types by volume (bar chart)

**Dashboard 2: Security**
- Risk levels by user (color scale)
- Anomaly scores (heatmap)
- Failed logins (counter)

**Dashboard 3: Performance**
- Bandwidth usage (area chart)
- Operation latency (histogram/heatmap)
- Cache hit rate (gauge)

**Dashboard 4: Exporter Health**
- Uptime (gauge)
- Memory usage (graph)
- Goroutines (graph)
- Error rate (gauge)

---

## Alerting Rules

### Example Alert Rules

```yaml
groups:
  - name: sftp-exporter
    rules:
      - alert: HighUserRisk
        expr: max(sftp_user_risk_level) > 2
        for: 5m
        annotations:
          summary: "High-risk SFTP activity detected"

      - alert: QuotaViolation
        expr: rate(sftp_user_quota_exceeded_events_total[5m]) > 0
        annotations:
          summary: "User quota exceeded"

      - alert: ExporterErrors
        expr: rate(sftp_exporter_error_count_total[5m]) > 0.1
        annotations:
          summary: "Exporter error rate high"

      - alert: HighCardinalityMetric
        expr: sftp_exporter_metric_cardinality > 500
        annotations:
          summary: "Metric cardinality excessive"
```

---

## Metric Types

- **Gauge**: Current value at scrape time
- **Counter**: Monotonically increasing value (only goes up)
- **Histogram**: Distribution of values with configurable buckets
- **Info**: Metadata (label-only metrics)

---

## Documentation Locations

- Phase 1: [main.go](../main.go) security metrics
- Phase 2: [poller/manager.go](../internal/poller/manager.go), [cache/cache.go](../internal/cache/cache.go)
- Phase 3: Per-module documentation in `internal/`
- Phase 4: [monitor/health.go](../internal/monitor/health.go)

---

Last Updated: Phase 4 (2026-04-09)
