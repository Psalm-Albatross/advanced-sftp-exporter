package monitor

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// HealthMetrics tracks exporter health and performance
type HealthMetrics struct {
	startTime                time.Time
	totalScrapes             atomic.Int64
	totalErrors              atomic.Int64
	scrapeDurationMicroseconds atomic.Int64
	goroutineCount           prometheus.GaugeFunc
	memoryUsageBytes         prometheus.GaugeFunc
	uptimeSeconds            prometheus.GaugeFunc
	scrapeCountTotal         prometheus.Counter
	errorCountTotal          prometheus.Counter
	scrapeDurationMetric     prometheus.Histogram
	lastScrapeDuration       time.Duration
	scrapeMu                 sync.RWMutex
}

// NewHealthMetrics creates a new health metrics tracker
func NewHealthMetrics() *HealthMetrics {
	hm := &HealthMetrics{
		startTime: time.Now(),
	}

	// Goroutine count gauge
	hm.goroutineCount = prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "sftp_exporter_goroutine_count",
			Help: "Number of goroutines running in the exporter",
		},
		func() float64 {
			return float64(runtime.NumGoroutine())
		},
	)

	// Memory usage gauge
	hm.memoryUsageBytes = prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "sftp_exporter_memory_usage_bytes",
			Help: "Memory usage of the exporter in bytes",
		},
		func() float64 {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			return float64(m.Alloc)
		},
	)

	// Uptime gauge
	hm.uptimeSeconds = prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "sftp_exporter_uptime_seconds",
			Help: "Uptime of the exporter in seconds",
		},
		func() float64 {
			return time.Since(hm.startTime).Seconds()
		},
	)

	// Scrape count counter
	hm.scrapeCountTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "sftp_exporter_scrape_count_total",
			Help: "Total number of metric scrapes",
		},
	)

	// Error count counter
	hm.errorCountTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "sftp_exporter_error_count_total",
			Help: "Total number of errors encountered",
		},
	)

	// Scrape duration histogram
	hm.scrapeDurationMetric = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name: "sftp_exporter_scrape_duration_seconds",
			Help: "Duration of metric scrapes in seconds",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
	)

	return hm
}

// RecordScrapeStart returns a function that should be called when scrape completes
func (hm *HealthMetrics) RecordScrapeStart() func(error) {
	start := time.Now()
	return func(err error) {
		duration := time.Since(start)
		hm.scrapeMu.Lock()
		hm.lastScrapeDuration = duration
		hm.scrapeMu.Unlock()

		hm.scrapeDurationMetric.Observe(duration.Seconds())
		hm.totalScrapes.Add(1)
		hm.scrapeCountTotal.Add(1)

		if err != nil {
			hm.totalErrors.Add(1)
			hm.errorCountTotal.Add(1)
		}
	}
}

// RecordError records an error
func (hm *HealthMetrics) RecordError(err error) {
	hm.totalErrors.Add(1)
	hm.errorCountTotal.Add(1)
}

// GetMetrics returns prometheus collector metrics
func (hm *HealthMetrics) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{
		hm.goroutineCount,
		hm.memoryUsageBytes,
		hm.uptimeSeconds,
		hm.scrapeCountTotal,
		hm.errorCountTotal,
		hm.scrapeDurationMetric,
	}
}

// GetStats returns health statistics
func (hm *HealthMetrics) GetStats() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	hm.scrapeMu.RLock()
	defer hm.scrapeMu.RUnlock()

	return map[string]interface{}{
		"uptime_seconds":      time.Since(hm.startTime).Seconds(),
		"goroutines":          runtime.NumGoroutine(),
		"memory_alloc_bytes":  m.Alloc,
		"memory_sys_bytes":    m.Sys,
		"total_scrapes":       hm.totalScrapes.Load(),
		"total_errors":        hm.totalErrors.Load(),
		"last_scrape_duration_seconds": hm.lastScrapeDuration.Seconds(),
	}
}
