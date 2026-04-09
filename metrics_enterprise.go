package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

// ============================================================================
// NETWORK & CONNECTION METRICS (NEW)
// ============================================================================

// Network bandwidth metrics
var (
	// Connection metrics
	networkConnectionsActive = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_network_connections_active",
			Help: "Current active network connections (TCP established)",
		},
		[]string{"user", "protocol"},
	)

	networkConnectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_network_connections_total",
			Help: "Total network connections established since startup",
		},
		[]string{"user", "connection_type"},
	)

	networkConnectionLatencySeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_network_connection_latency_seconds",
			Help:    "Network connection establishment latency",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
		},
		[]string{"protocol"},
	)

	// Bandwidth metrics (upload/download)
	networkBandwidthUploadBytesPerSecond = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_network_bandwidth_upload_bytes_per_second",
			Help: "Real-time upload bandwidth per user in bytes per second",
		},
		[]string{"user"},
	)

	networkBandwidthDownloadBytesPerSecond = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_network_bandwidth_download_bytes_per_second",
			Help: "Real-time download bandwidth per user in bytes per second",
		},
		[]string{"user"},
	)

	networkBandwidthTotalBytesPerSecond = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_network_bandwidth_total_bytes_per_second",
			Help: "Total bandwidth (upload + download) per user in bytes per second",
		},
		[]string{"user"},
	)

	networkPacketsDropped = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_network_packets_dropped_total",
			Help: "Total network packets dropped or retransmitted",
		},
		[]string{"user", "reason"},
	)

	networkRoundTripTimeMilliseconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_network_round_trip_time_milliseconds",
			Help:    "Network RTT (round trip time) in milliseconds",
			Buckets: prometheus.LinearBuckets(1, 10, 20),
		},
		[]string{"protocol"},
	)
)

// ============================================================================
// USER & AUTHENTICATION METRICS (ENHANCED, NO DUPLICATES)
// ============================================================================

var (
	// Authentication attempt tracking (failedLogins already exists, this is failed attempts)
	authenticationAttemptsFailed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_authentication_attempts_failed_total",
			Help: "Total failed authentication attempts with reason",
		},
		[]string{"user", "reason"},
	)

	authenticationAttemptsSuccessful = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_authentication_attempts_successful_total",
			Help: "Total successful authentications by method",
		},
		[]string{"user", "method"},
	)

	authenticationAttemptsPerSecond = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_authentication_attempts_per_second",
			Help: "Real-time authentication attempt rate",
		},
		[]string{"result"},
	)

	// User session tracking (userSessions already exists for active, this is concurrent connections)
	userConcurrentConnectionsMax = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_user_concurrent_connections_max_allowed",
			Help: "Maximum concurrent connections allowed per user",
		},
		[]string{"user"},
	)

	userConcurrentConnectionsCurrent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_user_concurrent_connections_current",
			Help: "Current concurrent connections for user",
		},
		[]string{"user"},
	)

	userUniqueCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_user_unique_count",
			Help: "Number of unique users connected",
		},
		[]string{"period"},
	)

	userLastActivityUnixTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_user_last_activity_unix_timestamp",
			Help: "Unix timestamp of last activity per user",
		},
		[]string{"user"},
	)

	userInactivityDurationSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_user_inactivity_duration_seconds",
			Help: "Duration of inactivity for each user in seconds",
		},
		[]string{"user"},
	)

	userQuotaUsedBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_user_quota_used_bytes",
			Help: "Storage quota used by user in bytes",
		},
		[]string{"user"},
	)

	userQuotaTotalBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_user_quota_total_bytes",
			Help: "Total storage quota allocated to user in bytes",
		},
		[]string{"user"},
	)

	userQuotaUsedPercent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_user_quota_used_percent",
			Help: "Storage quota used percentage (0-100)",
		},
		[]string{"user"},
	)

	userQuotaExceeded = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_user_quota_exceeded_total",
			Help: "Times user exceeded storage quota",
		},
		[]string{"user"},
	)
)

// ============================================================================
// PERFORMANCE & RESOURCE METRICS (ENHANCED)
// ============================================================================

var (
	// Disk I/O metrics
	diskIOLatencyReadMilliseconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_disk_io_latency_read_milliseconds",
			Help:    "Disk read operation latency in milliseconds",
			Buckets: prometheus.LinearBuckets(1, 5, 20),
		},
		[]string{"device"},
	)

	diskIOLatencyWriteMilliseconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_disk_io_latency_write_milliseconds",
			Help:    "Disk write operation latency in milliseconds",
			Buckets: prometheus.LinearBuckets(1, 5, 20),
		},
		[]string{"device"},
	)

	diskIOOperationsReadTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_disk_io_operations_read_total",
			Help: "Total disk read operations",
		},
		[]string{"device"},
	)

	diskIOOperationsWriteTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_disk_io_operations_write_total",
			Help: "Total disk write operations",
		},
		[]string{"device"},
	)

	diskIOBytesReadTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_disk_io_bytes_read_total",
			Help: "Total bytes read from disk",
		},
		[]string{"device"},
	)

	diskIOBytesWriteTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_disk_io_bytes_write_total",
			Help: "Total bytes written to disk",
		},
		[]string{"device"},
	)

	// CPU metrics (enhanced)
	cpuTimeUserSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_cpu_time_user_seconds",
			Help: "CPU time spent in user mode",
		},
		[]string{},
	)

	cpuTimeSystemSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_cpu_time_system_seconds",
			Help: "CPU time spent in system mode",
		},
		[]string{},
	)

	cpuContextSwitchesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_cpu_context_switches_total",
			Help: "Total context switches",
		},
		[]string{},
	)

	// Connection pool metrics
	connectionPoolSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_connection_pool_size",
			Help: "Current size of connection pool",
		},
		[]string{},
	)

	connectionPoolUtilizationPercent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_connection_pool_utilization_percent",
			Help: "Connection pool utilization percentage (0-100)",
		},
		[]string{},
	)

	connectionPoolWaitTimeSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_connection_pool_wait_time_seconds",
			Help:    "Time waiting for available connection from pool",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
		},
		[]string{},
	)

	// Timeout metrics
	operationTimeoutsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_operation_timeouts_total",
			Help: "Total operation timeouts by type",
		},
		[]string{"operation_type", "user"},
	)
)

// ============================================================================
// FILE OPERATION METRICS (ENHANCED, NO DUPLICATES)
// ============================================================================

var (
	// File operations by type (uploadFileTypeCount exists but this is more detailed)
	fileOperationsByTypeTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_file_operations_by_type_total",
			Help: "File operations counted by file extension/type",
		},
		[]string{"user", "operation", "file_type"},
	)

	fileOperationsByTypeLatencySeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_file_operations_by_type_latency_seconds",
			Help:    "Latency of file operations by type",
			Buckets: prometheus.ExponentialBuckets(0.01, 2, 12),
		},
		[]string{"operation", "file_type"},
	)

	fileDirectoryScanLatencySeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_file_directory_scan_latency_seconds",
			Help:    "Latency of directory listing operations",
			Buckets: prometheus.ExponentialBuckets(0.01, 2, 12),
		},
		[]string{},
	)

	fileSymlinkOperationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_file_symlink_operations_total",
			Help: "Symbolic link operations (create, read, follow, etc)",
		},
		[]string{"user", "operation"},
	)

	filePermissionDeniedErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_file_permission_denied_errors_total",
			Help: "File access permission denied errors",
		},
		[]string{"user", "operation"},
	)

	fileAgeDistributionSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_file_age_distribution_seconds",
			Help:    "Distribution of file ages (last modified time)",
			Buckets: prometheus.ExponentialBuckets(86400, 1.5, 15), // 1 day base
		},
		[]string{},
	)

	fileInodeUsagePercent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_file_inode_usage_percent",
			Help: "Filesystem inode usage percentage (0-100)",
		},
		[]string{"filesystem"},
	)

	fileRecoveryDeletedCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_file_recovery_deleted_count",
			Help: "Count of soft-deleted files available for recovery",
		},
		[]string{"user"},
	)
)

// ============================================================================
// SECURITY & COMPLIANCE METRICS (ENHANCED)
// ============================================================================

var (
	// Policy and compliance tracking
	securityPolicyViolationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_security_policy_violations_total",
			Help: "Security policy violations detected",
		},
		[]string{"user", "policy_name", "severity"},
	)

	securitySuspiciousPatternDetections = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_security_suspicious_pattern_detections_total",
			Help: "Suspicious activity pattern detections",
		},
		[]string{"user", "pattern_type"},
	)

	securityBulkTransfersDetected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_security_bulk_transfers_detected_total",
			Help: "Bulk data transfer operations detected",
		},
		[]string{"user", "transfer_type"},
	)

	securityEncryptionAlgorithmUsed = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_security_encryption_algorithm_used",
			Help: "Encryption algorithms in use (1=active)",
		},
		[]string{"algorithm", "strength"},
	)

	securityFailedIntegrityChecksTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_security_failed_integrity_checks_total",
			Help: "File integrity check failures (checksums, hashes)",
		},
		[]string{"user", "check_type"},
	)

	securityDeletedFileRecoveryCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_security_deleted_file_recovery_count",
			Help: "Count of recoverable deleted files per user",
		},
		[]string{"user"},
	)

	securityMalwareDetectionSignaturesMatched = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_security_malware_detection_signatures_matched_total",
			Help: "Malware signature matches (if scanning enabled)",
		},
		[]string{"user", "malware_type"},
	)

	securityDataClassificationViolations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_security_data_classification_violations_total",
			Help: "Data classification policy violations",
		},
		[]string{"user", "classification_level"},
	)
)

// ============================================================================
// SYSTEM HEALTH METRICS (ENHANCED)
// ============================================================================

var (
	// Log file metrics
	systemAuthLogFileSizeBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_system_auth_log_file_size_bytes",
			Help: "Size of authentication log file in bytes",
		},
		[]string{"log_file"},
	)

	systemAuthLogRotationFailuresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_system_auth_log_rotation_failures_total",
			Help: "Failed log rotation attempts",
		},
		[]string{},
	)

	systemLoadAverage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_system_load_average",
			Help: "System load average",
		},
		[]string{"period"},
	)

	systemNetworkInterfaceErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_system_network_interface_errors_total",
			Help: "Network interface errors (collisions, underruns, etc)",
		},
		[]string{"interface", "error_type"},
	)

	systemDNSLookupLatencySeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_system_dns_lookup_latency_seconds",
			Help:    "DNS resolution latency",
			Buckets: prometheus.LinearBuckets(0.001, 0.01, 20),
		},
		[]string{},
	)

	systemSSLCertificateExpiryDays = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_system_ssl_certificate_expiry_days",
			Help: "Days until SSL/TLS certificate expiration",
		},
		[]string{"certificate_name"},
	)

	systemUptimeSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_system_uptime_seconds",
			Help: "System uptime in seconds",
		},
		[]string{},
	)

	systemFilesystemUsagePercent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_system_filesystem_usage_percent",
			Help: "Filesystem usage percentage (0-100)",
		},
		[]string{"mountpoint"},
	)

	systemMemoryUsagePercent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_system_memory_usage_percent",
			Help: "System memory usage percentage (0-100)",
		},
		[]string{"memory_type"},
	)
)

// ============================================================================
// BUSINESS & USAGE METRICS
// ============================================================================

var (
	// Storage and capacity tracking
	storageConsumedBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_storage_consumed_bytes",
			Help: "Total storage consumed by all users in bytes",
		},
		[]string{},
	)

	storageGrowthRateBytesPerDay = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_storage_growth_rate_bytes_per_day",
			Help: "Storage growth rate in bytes per day",
		},
		[]string{},
	)

	transactionsPerDayTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_transactions_per_day_total",
			Help: "Total transactions (file operations) per day",
		},
		[]string{},
	)

	peakBandwidthBytesPerSecond = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_peak_bandwidth_bytes_per_second",
			Help: "Peak bandwidth usage in bytes per second",
		},
		[]string{},
	)

	peakBandwidthHourOfDay = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_peak_bandwidth_hour_of_day",
			Help: "Hour of day with peak bandwidth (0-23)",
		},
		[]string{},
	)

	costEstimateUSD = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_cost_estimate_usd",
			Help: "Estimated monthly cost in USD based on storage and bandwidth",
		},
		[]string{"cost_component"},
	)

	slaCompliancePercent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_sla_compliance_percent",
			Help: "SLA compliance percentage (0-100)",
		},
		[]string{"sla_metric"},
	)

	userRetentionPercent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_user_retention_percent",
			Help: "User retention percentage period-over-period",
		},
		[]string{"period"},
	)
)

// ============================================================================
// ADVANCED DIAGNOSTICS & PROFILING METRICS
// ============================================================================

var (
	// Goroutine profiling
	diagnosticGoroutineDistribution = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_diagnostic_goroutine_distribution",
			Help:    "Distribution of goroutines by state",
			Buckets: prometheus.LinearBuckets(1, 10, 100),
		},
		[]string{"state"},
	)

	// Memory allocation tracking
	diagnosticMemoryAllocationRateBytesPerSecond = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_diagnostic_memory_allocation_rate_bytes_per_second",
			Help: "Memory allocation rate for leak detection",
		},
		[]string{},
	)

	diagnosticMemoryAllocationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_diagnostic_memory_allocations_total",
			Help: "Total memory allocations",
		},
		[]string{},
	)

	// GC metrics
	diagnosticGarbageCollectionDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_diagnostic_garbage_collection_duration_seconds",
			Help:    "Garbage collection pause duration",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 12),
		},
		[]string{},
	)

	diagnosticGarbageCollectionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_diagnostic_garbage_collections_total",
			Help: "Total garbage collection runs",
		},
		[]string{},
	)

	// Lock contention
	diagnosticLockContentionMicroseconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_diagnostic_lock_contention_microseconds",
			Help:    "Lock contention duration in microseconds",
			Buckets: prometheus.ExponentialBuckets(1, 2, 16),
		},
		[]string{"lock_name"},
	)

	// Request queue
	diagnosticRequestQueueDepth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_diagnostic_request_queue_depth",
			Help: "Current depth of request processing queue",
		},
		[]string{},
	)

	diagnosticRequestQueueMaxDepth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_diagnostic_request_queue_max_depth",
			Help: "Maximum request queue depth since startup",
		},
		[]string{},
	)

	// Circular dependencies
	diagnosticCircularDependencyDetections = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_diagnostic_circular_dependency_detections_total",
			Help: "Detected circular references in file structure",
		},
		[]string{},
	)
)

// RegisterNewMetrics registers all new Phase 5 metrics with Prometheus
func RegisterNewMetrics() error {
	// Network & Connection
	prometheus.MustRegister(networkConnectionsActive)
	prometheus.MustRegister(networkConnectionsTotal)
	prometheus.MustRegister(networkConnectionLatencySeconds)
	prometheus.MustRegister(networkBandwidthUploadBytesPerSecond)
	prometheus.MustRegister(networkBandwidthDownloadBytesPerSecond)
	prometheus.MustRegister(networkBandwidthTotalBytesPerSecond)
	prometheus.MustRegister(networkPacketsDropped)
	prometheus.MustRegister(networkRoundTripTimeMilliseconds)

	// Authentication
	prometheus.MustRegister(authenticationAttemptsFailed)
	prometheus.MustRegister(authenticationAttemptsSuccessful)
	prometheus.MustRegister(authenticationAttemptsPerSecond)
	prometheus.MustRegister(userConcurrentConnectionsMax)
	prometheus.MustRegister(userConcurrentConnectionsCurrent)
	prometheus.MustRegister(userUniqueCount)
	prometheus.MustRegister(userLastActivityUnixTimestamp)
	prometheus.MustRegister(userInactivityDurationSeconds)
	prometheus.MustRegister(userQuotaUsedBytes)
	prometheus.MustRegister(userQuotaTotalBytes)
	prometheus.MustRegister(userQuotaUsedPercent)
	prometheus.MustRegister(userQuotaExceeded)

	// Performance & Resource
	prometheus.MustRegister(diskIOLatencyReadMilliseconds)
	prometheus.MustRegister(diskIOLatencyWriteMilliseconds)
	prometheus.MustRegister(diskIOOperationsReadTotal)
	prometheus.MustRegister(diskIOOperationsWriteTotal)
	prometheus.MustRegister(diskIOBytesReadTotal)
	prometheus.MustRegister(diskIOBytesWriteTotal)
	prometheus.MustRegister(cpuTimeUserSeconds)
	prometheus.MustRegister(cpuTimeSystemSeconds)
	prometheus.MustRegister(cpuContextSwitchesTotal)
	prometheus.MustRegister(connectionPoolSize)
	prometheus.MustRegister(connectionPoolUtilizationPercent)
	prometheus.MustRegister(connectionPoolWaitTimeSeconds)
	prometheus.MustRegister(operationTimeoutsTotal)

	// File Operations
	prometheus.MustRegister(fileOperationsByTypeTotal)
	prometheus.MustRegister(fileOperationsByTypeLatencySeconds)
	prometheus.MustRegister(fileDirectoryScanLatencySeconds)
	prometheus.MustRegister(fileSymlinkOperationsTotal)
	prometheus.MustRegister(filePermissionDeniedErrorsTotal)
	prometheus.MustRegister(fileAgeDistributionSeconds)
	prometheus.MustRegister(fileInodeUsagePercent)
	prometheus.MustRegister(fileRecoveryDeletedCount)

	// Security & Compliance
	prometheus.MustRegister(securityPolicyViolationsTotal)
	prometheus.MustRegister(securitySuspiciousPatternDetections)
	prometheus.MustRegister(securityBulkTransfersDetected)
	prometheus.MustRegister(securityEncryptionAlgorithmUsed)
	prometheus.MustRegister(securityFailedIntegrityChecksTotal)
	prometheus.MustRegister(securityDeletedFileRecoveryCount)
	prometheus.MustRegister(securityMalwareDetectionSignaturesMatched)
	prometheus.MustRegister(securityDataClassificationViolations)

	// System Health
	prometheus.MustRegister(systemAuthLogFileSizeBytes)
	prometheus.MustRegister(systemAuthLogRotationFailuresTotal)
	prometheus.MustRegister(systemLoadAverage)
	prometheus.MustRegister(systemNetworkInterfaceErrorsTotal)
	prometheus.MustRegister(systemDNSLookupLatencySeconds)
	prometheus.MustRegister(systemSSLCertificateExpiryDays)
	prometheus.MustRegister(systemUptimeSeconds)
	prometheus.MustRegister(systemFilesystemUsagePercent)
	prometheus.MustRegister(systemMemoryUsagePercent)

	// Business & Usage
	prometheus.MustRegister(storageConsumedBytes)
	prometheus.MustRegister(storageGrowthRateBytesPerDay)
	prometheus.MustRegister(transactionsPerDayTotal)
	prometheus.MustRegister(peakBandwidthBytesPerSecond)
	prometheus.MustRegister(peakBandwidthHourOfDay)
	prometheus.MustRegister(costEstimateUSD)
	prometheus.MustRegister(slaCompliancePercent)
	prometheus.MustRegister(userRetentionPercent)

	// Advanced Diagnostics
	prometheus.MustRegister(diagnosticGoroutineDistribution)
	prometheus.MustRegister(diagnosticMemoryAllocationRateBytesPerSecond)
	prometheus.MustRegister(diagnosticMemoryAllocationsTotal)
	prometheus.MustRegister(diagnosticGarbageCollectionDurationSeconds)
	prometheus.MustRegister(diagnosticGarbageCollectionsTotal)
	prometheus.MustRegister(diagnosticLockContentionMicroseconds)
	prometheus.MustRegister(diagnosticRequestQueueDepth)
	prometheus.MustRegister(diagnosticRequestQueueMaxDepth)
	prometheus.MustRegister(diagnosticCircularDependencyDetections)

	return nil
}
