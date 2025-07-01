//go:build !linux && !darwin && !freebsd
// +build !linux,!darwin,!freebsd

package main

// Stub for platforms without syslog support
func startExportToOtherBackends() {
	// No-op on unsupported platforms
}
