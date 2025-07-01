# Advanced SFTP Exporter

A highly advanced Prometheus exporter for monitoring SFTP (SSH File Transfer Protocol) activity, security, and resource usage on Linux and macOS servers.

## Features
- **Multi-architecture binaries**: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64
- **Prometheus metrics** for:
  - SFTP user sessions, uploads, downloads, transfer rates
  - Open files, memory, CPU, and disk usage per user
  - Security: failed logins, sudo/PAM failures, root login attempts, SELinux/AppArmor violations, shell invocation detection
  - Large file transfer and anomaly detection
  - Idle session monitoring and session duration tracking
  - Home directory permission checks
- **GDPR-safe strict mode**: anonymizes IPs and usernames
- **Configurable**: via command-line flags (log paths, home base, thresholds, regex filters, etc.)
- **Version information** embedded in binaries

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

```
- job_name: 'advanced-sftp-exporter'
  static_configs:
    - targets: ['localhost:9115']
```

Metrics will be available at: [http://localhost:9115/metrics](http://localhost:9115/metrics)

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

## Contributing
Pull requests and issues are welcome! Please see CONTRIBUTING.md (if available).
