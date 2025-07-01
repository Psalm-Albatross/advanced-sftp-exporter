package main

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	historicalUploadBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_historical_upload_bytes_daily",
			Help: "Daily total upload bytes per user (reset every 24h)",
		},
		[]string{"user", "date"},
	)
)

func init() {
	prometheus.MustRegister(historicalUploadBytes)
}

func monitorHistoricalMetrics() {
	for {
		// This is a placeholder: in a real implementation, you would persist and aggregate metrics
		// Here, we just reset the gauge every 24h to simulate daily tracking
		time.Sleep(24 * time.Hour)
		historicalUploadBytes.Reset()
	}
}
