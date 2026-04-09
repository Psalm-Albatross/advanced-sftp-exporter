package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

// ============================================================================
// FOUNDATIONAL METRICS (Phase 1 & Phase 2 Performance Optimization)
// ============================================================================
// These metrics provide core SFTP monitoring capabilities and performance
// insights for the exporter itself. Organized by functional area.

// Phase 1: Foundational Session & Transfer Metrics
var (
	// Session & User Tracking
	sftpUp = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "sftp_up",
			Help: "SFTP availability: 1 = OK (sshd + config + running), 0 = not ready",
		})

	userLoginType = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_linux_user_login_type",
			Help: "SFTP Login method per Linux user: 1 = SSH key, 0 = Password or Unknown",
		},
		[]string{"user"},
	)

	loginTypeCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_login_type_total",
			Help: "Login method type (key/password) observed per user",
		},
		[]string{"user", "method"},
	)

	userSessions = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_user_sessions_total",
			Help: "Current active SFTP sessions per user",
		},
		[]string{"user"},
	)

	sessionDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_session_duration_seconds",
			Help:    "Duration of completed SFTP sessions per user",
			Buckets: prometheus.ExponentialBuckets(5, 1.5, 10),
		},
		[]string{"user"},
	)

	idleSessions = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_idle_sessions_total",
			Help: "Number of idle SFTP sessions per user (no activity for threshold)",
		},
		[]string{"user"},
	)

	// File Transfer Metrics
	uploadCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_upload_count",
			Help: "Number of uploaded files per user",
		},
		[]string{"user"},
	)

	uploadBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_upload_bytes_total",
			Help: "Total bytes uploaded per user",
		},
		[]string{"user"},
	)

	downloadBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_download_bytes_total",
			Help: "Total bytes downloaded per user",
		},
		[]string{"user"},
	)

	transferRate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_transfer_rate_bytes_per_second",
			Help: "Approximate transfer rate (upload/download) per user",
		},
		[]string{"user"},
	)

	// Resource & System Metrics
	openFiles = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_open_files",
			Help: "Current open files per user",
		},
		[]string{"user"},
	)

	memUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_memory_usage_bytes",
			Help: "Memory usage (RSS) of SFTP sessions per user",
		},
		[]string{"user"},
	)

	memoryUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_user_memory_usage_bytes",
			Help: "Memory usage per user",
		},
		[]string{"user"},
	)

	cpuUsage = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_cpu_usage_seconds_total",
			Help: "Cumulative CPU time of SFTP sessions per user",
		},
		[]string{"user"},
	)

	cpu_Usage = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_user_cpu_usage_seconds_total",
			Help: "Cumulative CPU time of SFTP sessions per user",
		},
		[]string{"user"},
	)

	diskUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_disk_usage_bytes",
			Help: "Disk usage of user home directories",
		},
		[]string{"user"},
	)

	// Security & Transfer Anomaly Metrics
	largeTransferDetected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_large_transfer_detected_total",
			Help: "Large file transfers detected per user (>500MB)",
		},
		[]string{"user"},
	)

	failedLogins = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_failed_logins_total",
			Help: "Failed SFTP login attempts per user",
		},
		[]string{"user"},
	)

	fileErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_file_operation_errors_total",
			Help: "Errors during file operations per user",
		},
		[]string{"user"},
	)

	transferAnomalies = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_transfer_anomaly_detected_total",
			Help: "Detected anomalies in transfer patterns per user",
		},
		[]string{"user"},
	)

	loginEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_login_events_total",
			Help: "Successful SFTP login events per user",
		},
		[]string{"user"},
	)

	// Timestamp Tracking
	lastUploadTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_last_upload_timestamp_seconds",
			Help: "Unix timestamp of last upload per user",
		},
		[]string{"user"},
	)

	lastDownloadTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_last_download_timestamp_seconds",
			Help: "Unix timestamp of last download per user",
		},
		[]string{"user"},
	)

	// Transfer Analysis Metrics
	uploadFileTypeCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_upload_file_type_count",
			Help: "Count of uploaded files by type per user",
		},
		[]string{"user", "type"},
	)

	concurrentTransfers = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_concurrent_transfers_total",
			Help: "Current concurrent transfers per user",
		},
		[]string{"user"},
	)

	lastSourceIP = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_last_source_ip_info",
			Help: "Source IP of last login per user (label only)",
		},
		[]string{"user", "ip"},
	)

	// Security & Compliance Metrics
	sudoFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_sudo_auth_failures_total",
			Help: "Total sudo authentication failures",
		},
		[]string{"user", "tty", "rhost"},
	)

	authFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_pam_auth_failures_total",
			Help: "PAM authentication failures",
		},
		[]string{"user", "service"},
	)

	rootLoginAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_root_login_attempts_total",
			Help: "Login attempts to root user",
		},
		[]string{"source_ip"},
	)

	sshdRestarts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_sshd_restarts_total",
			Help: "SSHD restart count",
		},
		[]string{"host", "reason"},
	)

	accessViolations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_access_violations_total",
			Help: "SELinux/AppArmor access denials",
		},
		[]string{"policy", "exe"},
	)

	homeDirWarnings = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_home_directory_permission_warnings_total",
			Help: "Home directories that are world/group writable (potential misconfig).",
		},
		[]string{"user"},
	)

	unexpectedFileTypes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_unexpected_file_types_total",
			Help: "Suspicious or uncommon file extensions uploaded by user (e.g. .exe, .php, .sh)",
		},
		[]string{"user", "ext"},
	)

	failedLoginBurst = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_failed_login_window_total",
			Help: "Failed login attempts by user within time window",
		},
		[]string{"user"},
	)

	shellInvocations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_user_shell_invocations_total",
			Help: "Count of bash/sh spawned by SFTP users (should be 0)",
		},
		[]string{"user"},
	)

	sessionFrequency = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_user_session_frequency_total",
			Help: "Tracks session start frequency per user",
		},
		[]string{"user"},
	)

	sessionByHour = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_user_session_hour_bucket",
			Help:    "Histogram of login frequency by hour of day (0–23)",
			Buckets: prometheus.LinearBuckets(0, 1, 24), // 0, 1, 2, ..., 23
		},
		[]string{"user"},
	)

	memoryThresholdExceeded = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_memory_threshold_exceeded",
			Help: "Memory usage over defined threshold (per user)",
		},
		[]string{"user"},
	)

	virtualMemoryUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_linux_virtual_memory_usage_bytes",
			Help: "Virtual memory (VmSize) per user in bytes",
		},
		[]string{"user"},
	)
)

// Phase 2: Performance Optimization & Exporter Health Metrics
var (
	exporterMetricCardinality = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_exporter_metric_cardinality",
			Help: "Current cardinality of metric labels (users, IPs, file types, sessions)",
		},
		[]string{"metric_type"},
	)

	exporterCacheHitRate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_exporter_cache_hit_rate",
			Help: "Cache hit rate for command caching (0-1)",
		},
		[]string{"cache_type"},
	)

	exporterPollerStats = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_exporter_poller_runs_total",
			Help: "Total number of runs for each monitor poller",
		},
		[]string{"poller_name"},
	)

	exporterPollerInterval = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_exporter_poller_interval_seconds",
			Help: "Current polling interval for each monitor (adaptive polling)",
		},
		[]string{"poller_name"},
	)

	exporterPollerErrors = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_exporter_poller_errors_total",
			Help: "Total number of errors for each monitor poller",
		},
		[]string{"poller_name"},
	)
)

// ============================================================================
// METRIC REGISTRATION (Core Metrics)
// ============================================================================

func init_core() error {
	// Phase 1: Core Session & Transfer Metrics
	prometheus.MustRegister(sftpUp)
	prometheus.MustRegister(userLoginType)
	prometheus.MustRegister(loginTypeCounter)
	prometheus.MustRegister(userSessions)
	prometheus.MustRegister(sessionDuration)
	prometheus.MustRegister(idleSessions)
	prometheus.MustRegister(uploadCount)
	prometheus.MustRegister(uploadBytes)
	prometheus.MustRegister(downloadBytes)
	prometheus.MustRegister(transferRate)
	prometheus.MustRegister(openFiles)
	prometheus.MustRegister(memUsage)
	prometheus.MustRegister(memoryUsage)
	prometheus.MustRegister(cpuUsage)
	prometheus.MustRegister(cpu_Usage)
	prometheus.MustRegister(diskUsage)
	prometheus.MustRegister(largeTransferDetected)
	prometheus.MustRegister(failedLogins)
	prometheus.MustRegister(fileErrors)
	prometheus.MustRegister(transferAnomalies)
	prometheus.MustRegister(loginEvents)
	prometheus.MustRegister(lastUploadTimestamp)
	prometheus.MustRegister(lastDownloadTimestamp)
	prometheus.MustRegister(uploadFileTypeCount)
	prometheus.MustRegister(concurrentTransfers)
	prometheus.MustRegister(lastSourceIP)
	prometheus.MustRegister(unexpectedFileTypes)
	prometheus.MustRegister(sessionByHour)
	prometheus.MustRegister(
		sudoFailures,
		authFailures,
		rootLoginAttempts,
		sshdRestarts,
		accessViolations,
	)
	prometheus.MustRegister(memoryThresholdExceeded, virtualMemoryUsage)

	// Phase 2: Performance Metrics
	prometheus.MustRegister(exporterMetricCardinality)
	prometheus.MustRegister(exporterCacheHitRate)
	prometheus.MustRegister(exporterPollerStats)
	prometheus.MustRegister(exporterPollerInterval)
	prometheus.MustRegister(exporterPollerErrors)

	return nil
}
