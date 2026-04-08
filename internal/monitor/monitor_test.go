package monitor

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestBaseMonitorError tests BaseMonitor error recording
func TestBaseMonitorError(t *testing.T) {
	bm := NewBaseMonitor("test")

	if !bm.GetIsHealthy() {
		t.Error("Monitor should be healthy initially")
	}

	// Simulate errors
	err1 := ErrMonitorStartFailed("test", nil)
	err2 := ErrMonitorStartFailed("test", nil)
	err3 := ErrMonitorStartFailed("test", nil)

	bm.RecordError(err1)
	bm.RecordError(err2)

	if !bm.GetIsHealthy() {
		t.Error("Monitor should still be healthy after 2 errors")
	}

	bm.RecordError(err3)

	if bm.GetIsHealthy() {
		t.Error("Monitor should be unhealthy after 3 errors")
	}

	errors := bm.GetErrorsCopy()
	if len(errors) != 3 {
		t.Errorf("Expected 3 errors, got %d", len(errors))
	}
}

// TestBaseMonitorRecovery tests BaseMonitor recovering from errors
func TestBaseMonitorRecovery(t *testing.T) {
	bm := NewBaseMonitor("recovery-test")

	err := ErrMonitorStartFailed("test", nil)
	bm.RecordError(err)
	bm.RecordError(err)
	bm.RecordError(err)

	if bm.GetIsHealthy() {
		t.Error("Monitor should be unhealthy")
	}

	bm.RecordSuccess()

	if !bm.GetIsHealthy() {
		t.Error("Monitor should be healthy after success")
	}

	if len(bm.GetErrorsCopy()) != 0 {
		t.Error("Errors should be cleared after success")
	}
}

// TestRegistry registers and retrieves monitors
func TestRegistry(t *testing.T) {
	registry := NewRegistry()

	// Create mock monitor
	bm := &mockMonitor{
		name:      "mock1",
		isHealthy: true,
	}

	if err := registry.Register(bm); err != nil {
		t.Fatalf("Failed to register monitor: %v", err)
	}

	// Try to register duplicate
	if err := registry.Register(bm); err == nil {
		t.Error("Should not allow duplicate monitor registration")
	}

	// Retrieve monitor
	retrieved := registry.GetMonitor("mock1")
	if retrieved == nil {
		t.Error("Monitor not found in registry")
	}

	// Check health status
	status := registry.GetHealthStatus()
	if status["mock1"] != true {
		t.Error("Monitor should be reported as healthy")
	}
}

// mockMonitor implements Monitor interface for testing
type mockMonitor struct {
	name      string
	isHealthy bool
	err       error
}

func (m *mockMonitor) Start(ctx context.Context) error {
	return m.err
}

func (m *mockMonitor) Stop(ctx context.Context) error {
	return nil
}

func (m *mockMonitor) Name() string {
	return m.name
}

func (m *mockMonitor) IsHealthy() bool {
	return m.isHealthy
}

func (m *mockMonitor) GetMetrics() []prometheus.Collector {
	return nil
}

func (m *mockMonitor) GetErrors() []error {
	if m.err != nil {
		return []error{m.err}
	}
	return []error{}
}
