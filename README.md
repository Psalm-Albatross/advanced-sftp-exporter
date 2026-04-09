# Advanced SFTP Exporter

A highly advanced Prometheus exporter for monitoring SFTP (SSH File Transfer Protocol) activity, security, and resource usage on Linux and macOS servers. Enterprise-grade monitoring with 104+ metrics across 8 categories.

**Current Version**: 1.4.0-phase5 | **Metrics**: 104 total (47 core + 57 enterprise) | **Status**: Production Ready

## Features
- **Multi-architecture binaries**: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, freebsd/amd64, freebsd/arm64, linux/ppc64le, linux/s390x, linux/386, linux/arm
- **104 Enterprise Prometheus Metrics** across 8 categories:
  - **Network & Connection**: Bandwidth, latency, RTT, connection tracking
  - **User & Authentication**: Auth tracking, quota management, concurrent connections
  - **Performance & Resource**: Disk I/O, CPU, memory, connection pools, timeouts
  - **File Operations**: By type/extension, symlinks, inode usage, age distribution
  - **Security & Compliance**: Policy violations, suspicious patterns, encryption, data classification
  - **System Health**: Log monitoring, certificates, filesystem, DNS, load averages
  - **Business & Usage**: Storage tracking, SLA compliance, cost estimates, user retention
  - **Advanced Diagnostics**: Goroutines, memory allocation, GC pause times, lock contention
- **GDPR-safe strict mode**: anonymizes IPs and usernames
- **Configurable**: via command-line flags and environment variables
- **Version information** and build metadata embedded in binaries
- **Enterprise-ready**: Zero duplicates, cardinality-controlled, production quality

## Installation

Download the appropriate binary from the `bin/` directory or release assets:

```
advanced-sftp-exporter-vX.Y.Z-OS-ARCH
```

Example for Linux amd64:
```
cp bin/advanced-sftp-exporter-v1.3.0-linux-amd64 /usr/local/bin/advanced-sftp-exporter
chmod +x /usr/local/bin/advanced-sftp-exporter
```

Or build from source:
```
git clone https://github.com/Psalm-Albatross/advanced-sftp-exporter.git
cd advanced-sftp-exporter
./scripts/build.sh
```

## Usage

Run the exporter with default settings:
```
./advanced-sftp-exporter
```

Or with custom flags:
```
./advanced-sftp-exporter \
  -auth-log /var/log/auth.log \
  -home-base /home \
  -upload-marker-suffix .uploaded \
  -download-marker-suffix .downloaded \
  -web.listen-address :9115 \
  -idle-threshold-seconds 300 \
  -home-glob "/home/*" \
  -home-regex "^/home/demo-ftp-.*$" \
  -user-regex "^ftpuser.*$" \
  -strict-mode
```

### Key Flags
- `-auth-log`: Path to auth.log (default: /var/log/auth.log)
- `-home-base`: Base directory for user home dirs (default: /home)
- `-upload-marker-suffix`: Suffix for upload marker files (default: .uploaded)
- `-download-marker-suffix`: Suffix for download marker files (default: .downloaded)
- `-web.listen-address`: Address for metrics endpoint (default: :9115)
- `-idle-threshold-seconds`: Idle session threshold (default: 300)
- `-home-glob`: Glob pattern for user home dirs
- `-home-regex`: Regex to filter user home dirs
- `-user-regex`: Regex to filter usernames
- `-strict-mode`: Enable GDPR-safe mode (anonymize IPs, usernames)

## Prometheus Integration

Add a scrape config to your Prometheus config:

```yaml
- job_name: 'advanced-sftp-exporter'
  static_configs:
    - targets: ['localhost:9115']
  scrape_interval: 15s
  scrape_timeout: 10s
```

Metrics will be available at: [http://localhost:9115/metrics](http://localhost:9115/metrics)

**Total Metrics**: 104 (expandable)
**Estimated Time Series**: 400-500 (with all labels)
**Cardinality**: Fully controlled

## Metrics Categories (Phase 5 Enterprise)

### Network & Connection (8 metrics)
- Active connections, bandwidth tracking, connection latency, RTT measurement, packet drops

### User & Authentication (12 metrics)
- Authentication attempts, concurrent connections, quota management, user activity tracking

### Performance & Resource (13 metrics)
- Disk I/O latency, CPU time, connection pool utilization, operation timeouts

### File Operations (9 metrics)
- Operations by type, directory scan latency, symlink operations, inode usage

### Security & Compliance (8 metrics)
- Policy violations, suspicious patterns, bulk transfers, encryption algorithms

### System Health (10 metrics)
- Auth log monitoring, SSL certificates, filesystem usage, DNS performance

### Business & Usage (8 metrics)
- Storage consumption, transaction rates, SLA compliance, cost estimation

### Advanced Diagnostics (9 metrics)
- Goroutines, memory allocation, garbage collection, lock contention

## Security & GDPR
- Enable `-strict-mode` to anonymize IP addresses and usernames in logs and metrics.
- Monitors for suspicious file uploads, shell access, and failed login bursts.

## Building

To build multi-arch binaries with versioning:
```
./scripts/build.sh
```
Binaries will be placed in the `bin/` directory.

## License
MIT License

## Documentation

- **Metrics Reference**: See `IMPLEMENTATION-GUIDE-PHASE5.md` for code examples
- **Complete Metrics List**: See `METRICS-REVIEW-PHASE5-ENTERPRISE.md` for all 104 metrics
- **Deployment Guide**: See `PHASE5-COMPLETION-SUMMARY.md` for deployment instructions
- **Navigation**: See `PHASE5-START-HERE.md` for role-specific guidance

## Support

For issues, feature requests, or contributions, please refer to `CONTRIBUTING.md`.
Pull requests and issues are welcome! Please see CONTRIBUTING.md (if available).
