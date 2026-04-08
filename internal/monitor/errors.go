package monitor

import "fmt"

// ErrMonitorAlreadyRegistered indicates a monitor was already registered
func ErrMonitorAlreadyRegistered(name string) error {
	return fmt.Errorf("monitor '%s' is already registered", name)
}

// ErrMonitorStartFailed indicates a monitor failed to start
func ErrMonitorStartFailed(name string, err error) error {
	return fmt.Errorf("monitor '%s' failed to start: %w", name, err)
}

// ErrMonitorStopFailed indicates a monitor failed to stop
func ErrMonitorStopFailed(name string, err error) error {
	return fmt.Errorf("monitor '%s' failed to stop: %w", name, err)
}
