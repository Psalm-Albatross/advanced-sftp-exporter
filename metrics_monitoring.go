package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

// ============================================================================
// MONITORING & VISIBILITY METRICS (Phase 3 - Rich Metrics & Enhanced Visibility)
// ============================================================================
// These metrics provide deep observability into SFTP connections, protocol
// operations, anomalies, bandwidth usage, and file operation performance.
// Enables comprehensive monitoring of SFTP activity and behavior patterns.

// Phase 3: Rich Metrics & Enhanced Visibility

// Connection-Level Granularity Metrics
var (
	connectionActiveTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_connection_active_total",
			Help: "Current active SFTP connections",
		},
		[]string{"user", "remote_ip"},
	)

	connectionDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_connection_duration_seconds",
			Help:    "SFTP connection duration histogram",
			Buckets: prometheus.ExponentialBuckets(1, 2, 12), // 1s to ~4096s
		},
		[]string{"user", "reason"},
	)

	connectionBytesTransferred = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_connection_bytes_transferred_total",
			Help: "Total bytes transferred per connection",
		},
		[]string{"user", "direction"},
	)

	// Protocol-Level Intelligence
	protocolVersionInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_protocol_version_info",
			Help: "SFTP protocol version distribution (2 or 3)",
		},
		[]string{"version"},
	)

	protocolRenegotiationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_protocol_renegotiations_total",
			Help: "SSH renegotiation count per user",
		},
		[]string{"user"},
	)

	protocolKeepaliveReceived = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_protocol_keepalive_received_total",
			Help: "SSH keepalive frequency per user",
		},
		[]string{"user"},
	)

	// Advanced Anomaly Detection
	anomalyDetectionScore = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_anomaly_detection_score",
			Help: "User anomaly score (0-1, higher = more anomalous)",
		},
		[]string{"user", "score_type"},
	)

	userRiskLevel = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_user_risk_level",
			Help: "User risk level: 0=low, 1=medium, 2=high, 3=critical",
		},
		[]string{"user"},
	)

	// Bandwidth & Quota Tracking
	userBandwidthBps = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_user_bandwidth_bps",
			Help: "Current bandwidth usage in bits per second",
		},
		[]string{"user", "direction"},
	)

	userQuotaUsagePercent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_user_quota_usage_percent",
			Help: "User storage quota usage as percentage",
		},
		[]string{"user"},
	)

	quotaExceededEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_quota_exceeded_events_total",
			Help: "Number of times a user exceeded their quota",
		},
		[]string{"user"},
	)

	// File Operation Latency & Distribution
	fileOperationLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_file_operation_latency_seconds",
			Help:    "File operation latency histogram",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 12), // 1ms to ~4s
		},
		[]string{"user", "operation"},
	)

	fileSizeDistribution = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_file_size_distribution_bytes",
			Help:    "File size distribution in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 7), // 100B to 100GB
		},
		[]string{"user"},
	)
)

// ============================================================================
// METRIC REGISTRATION (Monitoring Metrics)
// ============================================================================

func init_monitoring() error {
	// Phase 3: Connection Tracking
	prometheus.MustRegister(connectionActiveTotal)
	prometheus.MustRegister(connectionDurationSeconds)
	prometheus.MustRegister(connectionBytesTransferred)

	// Phase 3: Protocol Intelligence
	prometheus.MustRegister(protocolVersionInfo)
	prometheus.MustRegister(protocolRenegotiationsTotal)
	prometheus.MustRegister(protocolKeepaliveReceived)

	// Phase 3: Anomaly Detection & Risk Assessment
	prometheus.MustRegister(anomalyDetectionScore)
	prometheus.MustRegister(userRiskLevel)

	// Phase 3: Bandwidth & Quota Management
	prometheus.MustRegister(userBandwidthBps)
	prometheus.MustRegister(userQuotaUsagePercent)
	prometheus.MustRegister(quotaExceededEvents)

	// Phase 3: File Operation Performance
	prometheus.MustRegister(fileOperationLatency)
	prometheus.MustRegister(fileSizeDistribution)

	return nil
}
