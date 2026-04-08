package monitor

import (
	"context"
	"github.com/prometheus/client_golang/prometheus"
)

// Monitor defines the interface for pluggable monitoring components
type Monitor interface {
	// Start begins the monitor's operation in a goroutine
	Start(ctx context.Context) error

	// Stop gracefully shuts down the monitor
	Stop(ctx context.Context) error

	// Name returns the monitor's identifier
	Name() string

	// IsHealthy returns true if monitor is functioning normally
	IsHealthy() bool

	// GetMetrics returns all prometheus metrics this monitor registers
	GetMetrics() []prometheus.Collector

	// GetErrors returns recent errors encountered by this monitor
	GetErrors() []error
}

// Registry manages all active monitors
type Registry struct {
	monitors map[string]Monitor
}

// NewRegistry creates a new monitor registry
func NewRegistry() *Registry {
	return &Registry{
		monitors: make(map[string]Monitor),
	}
}

// Register adds a monitor to the registry
func (r *Registry) Register(monitor Monitor) error {
	name := monitor.Name()
	if _, exists := r.monitors[name]; exists {
		return ErrMonitorAlreadyRegistered(name)
	}
	r.monitors[name] = monitor
	return nil
}

// StartAll starts all registered monitors
func (r *Registry) StartAll(ctx context.Context) error {
	var errs []error
	for name, m := range r.monitors {
		if err := m.Start(ctx); err != nil {
			errs = append(errs, ErrMonitorStartFailed(name, err))
		}
	}
	if len(errs) > 0 {
		return errs[0] // Return first error
	}
	return nil
}

// StopAll stops all registered monitors
func (r *Registry) StopAll(ctx context.Context) error {
	var errs []error
	for name, m := range r.monitors {
		if err := m.Stop(ctx); err != nil {
			errs = append(errs, ErrMonitorStopFailed(name, err))
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// GetMonitor returns a monitor by name
func (r *Registry) GetMonitor(name string) Monitor {
	return r.monitors[name]
}

// GetAllMonitors returns all registered monitors
func (r *Registry) GetAllMonitors() map[string]Monitor {
	return r.monitors
}

// GetHealthStatus returns health status of all monitors
func (r *Registry) GetHealthStatus() map[string]bool {
	status := make(map[string]bool)
	for name, m := range r.monitors {
		status[name] = m.IsHealthy()
	}
	return status
}

// GetAllCollectors returns all prometheus collectors from all monitors
func (r *Registry) GetAllCollectors() []prometheus.Collector {
	var collectors []prometheus.Collector
	for _, m := range r.monitors {
		collectors = append(collectors, m.GetMetrics()...)
	}
	return collectors
}
