package monitors

import (
	"context"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// FileTransferMonitor monitors SFTP file transfers
type FileTransferMonitor struct {
	name       string
	isHealthy  bool
	errors     []error
	errorsMu   sync.RWMutex
	maxErrors  int
	collectors []prometheus.Collector
}

// NewFileTransferMonitor creates a new file transfer monitor
func NewFileTransferMonitor() *FileTransferMonitor {
	ftm := &FileTransferMonitor{
		name:      "file-transfer",
		isHealthy: true,
		maxErrors: 10,
		errors:    make([]error, 0, 10),
	}
	ftm.initMetrics()
	return ftm
}

// initMetrics initializes prometheus metrics
func (ftm *FileTransferMonitor) initMetrics() {
	ftm.collectors = make([]prometheus.Collector, 0)
}

// Start begins monitoring
func (ftm *FileTransferMonitor) Start(ctx context.Context) error {
	ftm.recordSuccess()
	return nil
}

// Stop gracefully shuts down monitoring
func (ftm *FileTransferMonitor) Stop(ctx context.Context) error {
	return nil
}

// Name returns the monitor's identifier
func (ftm *FileTransferMonitor) Name() string {
	return ftm.name
}

// IsHealthy returns true if the monitor is functioning
func (ftm *FileTransferMonitor) IsHealthy() bool {
	ftm.errorsMu.RLock()
	defer ftm.errorsMu.RUnlock()
	return ftm.isHealthy
}

// GetMetrics returns prometheus metrics
func (ftm *FileTransferMonitor) GetMetrics() []prometheus.Collector {
	return ftm.collectors
}

// GetErrors returns recent errors
func (ftm *FileTransferMonitor) GetErrors() []error {
	ftm.errorsMu.RLock()
	defer ftm.errorsMu.RUnlock()
	errCopy := make([]error, len(ftm.errors))
	copy(errCopy, ftm.errors)
	return errCopy
}

// recordError records an error
func (ftm *FileTransferMonitor) recordError(err error) {
	ftm.errorsMu.Lock()
	defer ftm.errorsMu.Unlock()

	if len(ftm.errors) < ftm.maxErrors {
		ftm.errors = append(ftm.errors, err)
	} else {
		copy(ftm.errors, ftm.errors[1:])
		ftm.errors[ftm.maxErrors-1] = err
	}

	if len(ftm.errors) >= 3 {
		ftm.isHealthy = false
	}
}

// recordSuccess marks successful operation
func (ftm *FileTransferMonitor) recordSuccess() {
	ftm.errorsMu.Lock()
	defer ftm.errorsMu.Unlock()
	ftm.errors = ftm.errors[:0]
	ftm.isHealthy = true
}
