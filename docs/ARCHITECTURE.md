# ARCHITECTURE.md - Advanced SFTP Exporter Architecture

## Overview

Advanced SFTP Exporter follows a modular, layered architecture designed for extensibility, testability, and operational observability.

```
┌─────────────────────────────────────────────────────────────┐
│                   main.go (Orchestrator)                    │
├─────────────────────────────────────────────────────────────┤
│  Entry point, configuration, signal handling, lifecycle     │
└──────────────────┬──────────────────────────────────────────┘
                   │
        ┌──────────┼──────────┬──────────┐
        │          │          │          │
        ▼          ▼          ▼          ▼
    ┌────────┐ ┌──────────┐ ┌────────┐ ┌──────────┐
    │ Config │ │Logger    │ │Health  │ │Monitor   │
    │        │ │Structured│ │Metrics │ │Registry  │
    └────────┘ └──────────┘ └────────┘ └────┬─────┘
        │          │          │              │
        │          │          │         ┌────┴──────────────┐
        │          │          │         │                   │
        ▼          ▼          ▼         ▼                   ▼
    ┌────────┐ ┌──────────┐ ┌───────┐ ┌──────────┐    ┌──────────┐
    │Env Var │ │JSON/Text │ │Gauges │ │AuthLog   │    │FileXfer  │
    │Override│ │Formatting│ │Histos │ │Monitor   │    │Monitor   │
    └────────┘ └──────────┘ └───────┘ └──────────┘    └──────────┘
                                           │                   │
                                      (Pluggable monitors)
                                           │
        ┌──────────────────────────────────┼──────────────────────┐
        │                                  │                      │
        ▼                                  ▼                      ▼
    ┌─────────────┐                   ┌───────────┐          ┌──────────┐
    │Performance  │                   │Rich       │          │Security  │
    │Optimization │                   │Metrics    │          │Hardening │
    │             │                   │           │          │          │
    │ Polling     │                   │Connection │          │Command   │
    │ Cache       │                   │Protocol   │          │Validation│
    │ Cardinality │                   │Anomaly    │          │Path Safe │
    │             │                   │Quota      │          │Rate Limit│
    └─────────────┘                   │Latency    │          │TLS/Token │
                                      └───────────┘          └──────────┘

                        ┌──────────────────────────┐
                        │  Prometheus HTTP Handler │
                        ├──────────────────────────┤
                        │ /metrics                 │
                        │ /health                  │
                        │ /readiness               │
                        │ /diagnostics (Phase 4)   │
                        └──────────────────────────┘
```

---

## Module Organization

### Root Level: `main.go`

**Responsibilities**:
- CLI flag parsing
- Configuration initialization
- Component lifecycle (start/stop)
- HTTP server setup
- Signal handling (SIGTERM, SIGINT)
- Metrics registration with Prometheus

**Key Functions**:
- `main()` - Entry point
- `init()` - Metric registration
- `validateConfiguration()` - Config validation
- `monitorAuthLog()` - PII-free auth monitoring
- Various HTTP handlers

### Phase 1: `internal/security/`

**Purpose**: Secure command execution, input validation, session management

**Components**:
- `safety/exec_safe.go` - Command execution with timeouts
- `validation/validator.go` - Input validation and path safety
- `session/store.go` - Thread-safe session storage

### Phase 2: `internal/{poller,cache,cardinality}/`

**Purpose**: Performance optimization and resource efficiency

**Components**:
- `poller/manager.go` - Adaptive polling with goroutine pooling
- `cache/cache.go` - TTL-based command result caching
- `cardinality/limiter.go` - Metric cardinality controls

### Phase 3: `internal/{connection,protocol,anomaly,quota,latency}/`

**Purpose**: Rich metrics and enhanced visibility

**Components**:
- `connection/store.go` - Per-session connection tracking
- `protocol/detector.go` - SFTP version and subsystem detection
- `anomaly/scorer.go` - Behavioral anomaly detection (4 components)
- `quota/manager.go` - Bandwidth and storage quota tracking
- `latency/tracker.go` - Per-operation latency metrics

### Phase 4: `internal/{monitor,config,logger}/`

**Purpose**: Modular architecture, configuration management, structured logging

**Components**:
- `monitor/interface.go` - Monitor plugin interface
- `monitor/registry.go` - Monitor lifecycle management
- `monitor/health.go` - Exporter health metrics
- `config/config.go` - Hierarchical configuration system
- `logger/logger.go` - Structured JSON/text logging

---

## Data Flow

### Metric Collection Pipeline

```
1. Monitor Start
   └─> Goroutine spawned (with goroutine limit)
   
2. Data Collection
   └─> Auth log parsing, process inspection, etc.
   └─> Error handling and recovery
   
3. Metric Update
   └─> Thread-safe RWMutex protected updates
   └─> Cardinality checks (drop/aggregate if exceeded)
   └─> Anomaly scoring and thresholds
   
4. Metric Scrape
   └─> HTTP GET /metrics
   └─> Prometheus handler iterates collectors
   └─> Response marshaled to Prometheus text format
   
5. Prometheus Ingestion
   └─> Stored in time-series database
   └─> Available for querying and alerting
```

### Security Flow

```
User Input (CLI flags/env)
   │
   ▼
Configuration Validation
   ├─> Path traversal checks
   ├─> Regex complexity validation
   ├─> TLS certificate validation
   └─> Bearer token validation
   
   ▼
Command Execution
   ├─> Whitelist check (if configured)
   ├─> Timeout enforcement (5s default)
   ├─> Context cancellation support
   └─> Output sanitization
   
   ▼
Metric Export
   ├─> User/IP anonymization (strict mode)
   ├─> Bearer token auth check
   ├─> TLS encryption (if enabled)
   └─> Rate limiting (per IP)
```

---

## Component Interactions

### Configuration Flow

```
Defaults
   │
   ├─> CLI Flags (override)
   │
   ├─> Environment Variables (SFTP_EXPORTER_*)
   │   (override)
   │
   └─> Validation
       ├─> Type checks
       ├─> Range checks
       ├─> Path existence checks
       └─> Regex compilation
```

### Monitor Registry Pattern

```
Monitor Interface {
  Start(ctx) error
  Stop(ctx) error
  IsHealthy() bool
  Name() string
  GetMetrics() []Collector
  GetErrors() []error
}

Registry {
  Register(Monitor) error
  StartAll(ctx) error
  StopAll(ctx) error
  GetHealthStatus() map[string]bool
  GetAllCollectors() []Collector
}
```

### Error Handling Strategy

```
3 Error Rules:
1. Record first occurrence
2. Track up to 10 errors (sliding window)
3. Mark unhealthy after 3 consecutive errors

Recovery:
- Success clears error queue
- Health auto-recovers when errors clear
- Available in diagnostics endpoint
```

---

## Threading Model

### Goroutine Pooling

```
PollerManager
   │
   ├─> Worker Sem (max 10, configurable)
   │   ├─> Worker 1 ─> Auth log monitor
   │   ├─> Worker 2 ─> File transfer monitor
   │   ├─> Worker 3 ─> Resource usage monitor
   │   └─> ...
   │
   └─> Task Queue
       ├─> Adaptive backoff (1s → 60s)
       ├─> Context-based cancellation
       └─> Graceful shutdown timeout (30s)
```

### Thread Safety

- **RWMutex** on shared maps: sessionState, metrics labels
- **sync.Map** for high-contention data (if needed)
- **Atomic** operations for counters/gauges
- **Context** for cancellation propagation

---

## Configuration System

### Hierarchy

```
Config {
  Monitoring {
    auth_log_path: "/var/log/auth.log"
    home_base_path: "/home"
    strict_mode: false
    ...
  }
  
  Security {
    command_timeout_seconds: 5
    enable_path_validation: true
    ...
  }
  
  Performance {
    max_monitor_goroutines: 10
    enable_adaptive_polling: true
    cache_ttl_seconds: 3600
    ...
  }
  
  Web {
    listen_address: ":1210"
    enable_tls: false
    bearer_token: "secret"
    rate_limit_req_sec: 100
    ...
  }
  
  Logging {
    level: "INFO"
    json_mode: false
    ...
  }
}
```

### Override Precedence

1. Defaults (NewDefaultConfig)
2. CLI flags (if provided)
3. Environment variables (SFTP_EXPORTER_*)
4. Config file (future enhancement)

---

## Lifecycle Management

### Startup Sequence

```
1. Parse flags
2. Check -version flag (early exit if set)
3. Initialize logger
4. Load config from environment
5. Validate configuration
6. Initialize health metrics
7. Create monitor registry
8. Register default monitors
9. Register Prometheus metrics
10. Start goroutine monitors
11. Bind HTTP handlers
12. Listen on port
```

### Shutdown Sequence

```
1. Receive SIGTERM/SIGINT
2. Stop accepting new connections
3. Shutdown HTTP server (immediate)
4. Stop monitor registry (30s timeout)
5. Wait for in-flight operations
6. Log shutdown metrics
7. Exit gracefully (code 0)
```

---

## Extensibility Points

### Adding a New Monitor

```go
// 1. Implement Monitor interface
type MyMonitor struct {
  base *monitor.BaseMonitor
  // ... fields
}

func NewMyMonitor() *MyMonitor {
  return &MyMonitor{
    base: monitor.NewBaseMonitor("my-monitor"),
  }
}

// 2. Implement interface methods
func (m *MyMonitor) Start(ctx context.Context) error { ... }
func (m *MyMonitor) Stop(ctx context.Context) error { ... }
func (m *MyMonitor) Name() string { return m.base.GetName() }
func (m *MyMonitor) IsHealthy() bool { return m.base.GetIsHealthy() }
func (m *MyMonitor) GetMetrics() []prometheus.Collector { ... }
func (m *MyMonitor) GetErrors() []error { return m.base.GetErrorsCopy() }

// 3. Register in main.go
if err := monitorRegistry.Register(monitors.NewMyMonitor()); err != nil {
  appLogger.Error("Failed to register monitor", err, nil)
}
```

### Adding a New Metric

```go
// 1. Define metric
myMetric := prometheus.NewGaugeVec(
  prometheus.GaugeOpts{
    Name: "sftp_my_metric",
    Help: "Description",
  },
  []string{"label1", "label2"},
)

// 2. Register
prometheus.MustRegister(myMetric)

// 3. Update in monitor
myMetric.WithLabelValues("value1", "value2").Set(42)
```

---

## Performance Characteristics

### Memory Usage

- **Baseline**: ~10-20 MB (no sessions)
- **Per Session**: ~1-2 KB (cached data)
- **Estimated**: 100 sessions ≈ 30 MB

### CPU Usage

- **Idle**: <1% (adaptive polling at 60s intervals)
- **Active**: 2-5% per monitoring cycle (depends on file count)
- **Spike**: Brief spikes on log rotation (re-parse)

### Latency

- **Metric scrape**: <100ms typical
- **Operation latency**: Per-operation tracked (see METRICS.md)

---

## Testing Strategy

### Unit Tests
- Monitor interface implementations
- Configuration validation
- Cardinality limiting logic
- Anomaly scoring algorithms

### Integration Tests
- Monitor lifecycle (start/stop)
- Data flow through registry
- Configuration override chain

### Manual Testing
- Build and run: `make build && ./bin/advanced-sftp-exporter`
- Check metrics: `curl http://localhost:1210/metrics`
- Check health: `curl http://localhost:1210/health`
- Check diagnostics: `curl http://localhost:1210/diagnostics`

---

## References

- [METRICS.md](./METRICS.md) - Metric reference
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Development guidelines
- [PHASE4-DELIVERY.md](../PHASE4-DELIVERY.md) - Phase 4 specifics

---

Last Updated: Phase 4 (2026-04-09)
