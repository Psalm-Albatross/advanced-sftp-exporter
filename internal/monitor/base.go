package monitor

import (
	"sync"
	"time"
)

// BaseMonitor provides common functionality for all monitors
type BaseMonitor struct {
	name       string
	lastError  error
	lastCheck  time.Time
	isHealthy  bool
	errorsMu   sync.RWMutex
	errors     []error
	maxErrors  int
}

// NewBaseMonitor creates a new base monitor
func NewBaseMonitor(name string) *BaseMonitor {
	return &BaseMonitor{
		name:      name,
		isHealthy: true,
		maxErrors: 10,
		errors:    make([]error, 0, 10),
	}
}

// RecordError records an error and updates health status
func (b *BaseMonitor) RecordError(err error) {
	b.errorsMu.Lock()
	defer b.errorsMu.Unlock()

	b.lastError = err
	b.lastCheck = time.Now()

	if len(b.errors) < b.maxErrors {
		b.errors = append(b.errors, err)
	} else {
		// Keep a sliding window of errors
		copy(b.errors, b.errors[1:])
		b.errors[b.maxErrors-1] = err
	}

	// After 3 errors in a row, mark as unhealthy
	if len(b.errors) >= 3 {
		b.isHealthy = false
	}
}

// RecordSuccess marks a successful operation
func (b *BaseMonitor) RecordSuccess() {
	b.errorsMu.Lock()
	defer b.errorsMu.Unlock()

	b.lastCheck = time.Now()
	b.errors = b.errors[:0] // Clear errors
	b.isHealthy = true
}

// GetLastError returns the most recent error
func (b *BaseMonitor) GetLastError() error {
	b.errorsMu.RLock()
	defer b.errorsMu.RUnlock()
	return b.lastError
}

// GetIsHealthy returns the health status
func (b *BaseMonitor) GetIsHealthy() bool {
	b.errorsMu.RLock()
	defer b.errorsMu.RUnlock()
	return b.isHealthy
}

// GetErrorsCopy returns a copy of recent errors
func (b *BaseMonitor) GetErrorsCopy() []error {
	b.errorsMu.RLock()
	defer b.errorsMu.RUnlock()

	result := make([]error, len(b.errors))
	copy(result, b.errors)
	return result
}

// GetName returns the monitor's name
func (b *BaseMonitor) GetName() string {
	return b.name
}

// GetLastCheck returns when the monitor last operated
func (b *BaseMonitor) GetLastCheck() time.Time {
	b.errorsMu.RLock()
	defer b.errorsMu.RUnlock()
	return b.lastCheck
}
