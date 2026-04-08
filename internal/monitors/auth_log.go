package monitors

import (
	"context"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// AuthLogMonitor monitors SSH authentication via auth.log
type AuthLogMonitor struct {
	name        string
	isHealthy   bool
	errors      []error
	errorsMu    sync.RWMutex
	maxErrors   int
	collectors  []prometheus.Collector
}

// NewAuthLogMonitor creates a new auth log monitor
func NewAuthLogMonitor() *AuthLogMonitor {
	alm := &AuthLogMonitor{
		name:      "auth-log",
		isHealthy: true,
		maxErrors: 10,
		errors:    make([]error, 0, 10),
	}
	alm.initMetrics()
	return alm
}

// initMetrics initializes prometheus metrics for this monitor
func (alm *AuthLogMonitor) initMetrics() {
	// Placeholder metrics - will be implemented as Phase 4 expands
	// These will be populated from the existing main.go metrics
	alm.collectors = make([]prometheus.Collector, 0)
}

// Start begins monitoring
func (alm *AuthLogMonitor) Start(ctx context.Context) error {
	// Placeholder: will implement auth log parsing
	alm.recordSuccess()
	return nil
}

// Stop gracefully shuts down monitoring
func (alm *AuthLogMonitor) Stop(ctx context.Context) error {
	return nil
}

// Name returns the monitor's identifier
func (alm *AuthLogMonitor) Name() string {
	return alm.name
}

// IsHealthy returns true if the monitor is functioning
func (alm *AuthLogMonitor) IsHealthy() bool {
	alm.errorsMu.RLock()
	defer alm.errorsMu.RUnlock()
	return alm.isHealthy
}

// GetMetrics returns prometheus metrics
func (alm *AuthLogMonitor) GetMetrics() []prometheus.Collector {
	return alm.collectors
}

// GetErrors returns recent errors
func (alm *AuthLogMonitor) GetErrors() []error {
	alm.errorsMu.RLock()
	defer alm.errorsMu.RUnlock()
	errCopy := make([]error, len(alm.errors))
	copy(errCopy, alm.errors)
	return errCopy
}

// recordError records an error and updates health
func (alm *AuthLogMonitor) recordError(err error) {
	alm.errorsMu.Lock()
	defer alm.errorsMu.Unlock()

	if len(alm.errors) < alm.maxErrors {
		alm.errors = append(alm.errors, err)
	} else {
		copy(alm.errors, alm.errors[1:])
		alm.errors[alm.maxErrors-1] = err
	}

	if len(alm.errors) >= 3 {
		alm.isHealthy = false
	}
}

// recordSuccess clears errors and marks as healthy
func (alm *AuthLogMonitor) recordSuccess() {
	alm.errorsMu.Lock()
	defer alm.errorsMu.Unlock()
	alm.errors = alm.errors[:0]
	alm.isHealthy = true
}
