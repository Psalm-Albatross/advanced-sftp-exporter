package protocol

import (
	"regexp"
	"strings"
	"sync"
)

// ProtocolInfo holds protocol-level intelligence for SFTP connections
type ProtocolInfo struct {
	Version              string // "2", "3", or "unknown"
	Subsystem            string // "internal-sftp", "openssh-sftp", etc.
	CompressionEnabled   bool
	RenegotiationsCount  int64
	KeepalivesReceived   int64
	LastRenegotiation    int64 // unix timestamp
	LastKeepalive        int64 // unix timestamp
	ClientVersion        string
	ServerVersion        string
}

// ProtocolDetector detects and tracks protocol information
type ProtocolDetector struct {
	connections map[string]*ProtocolInfo
	mu          sync.RWMutex

	// Regex patterns for SSH version detection
	sftpV2Pattern *regexp.Regexp
	sftpV3Pattern *regexp.Regexp
	openSSHPattern *regexp.Regexp
}

// NewProtocolDetector creates a new protocol detector
func NewProtocolDetector() *ProtocolDetector {
	return &ProtocolDetector{
		connections:   make(map[string]*ProtocolInfo),
		sftpV2Pattern: regexp.MustCompile(`(?i)(sftp.*v?2|version.*2)`),
		sftpV3Pattern: regexp.MustCompile(`(?i)(sftp.*v?3|version.*3)`),
		openSSHPattern: regexp.MustCompile(`(?i)(openssh|internal.sftp)`),
	}
}

// SetProtocolInfo sets protocol information for a connection
func (pd *ProtocolDetector) SetProtocolInfo(sessionID string, proto *ProtocolInfo) {
	if proto == nil || sessionID == "" {
		return
	}

	pd.mu.Lock()
	defer pd.mu.Unlock()

	pd.connections[sessionID] = proto
}

// GetProtocolInfo retrieves protocol info for a connection
func (pd *ProtocolDetector) GetProtocolInfo(sessionID string) (*ProtocolInfo, bool) {
	pd.mu.RLock()
	defer pd.mu.RUnlock()

	proto, exists := pd.connections[sessionID]
	return proto, exists
}

// DetectSFTPVersion attempts to detect SFTP version from client/server strings
func (pd *ProtocolDetector) DetectSFTPVersion(clientVersion, serverVersion string) string {
	combined := clientVersion + " " + serverVersion

	if pd.sftpV3Pattern.MatchString(combined) {
		return "3"
	}
	if pd.sftpV2Pattern.MatchString(combined) {
		return "2"
	}

	// Default to 2 (most common)
	return "2"
}

// DetectSubsystem attempts to detect SFTP subsystem type
func (pd *ProtocolDetector) DetectSubsystem(serverVersion string) string {
	if strings.Contains(strings.ToLower(serverVersion), "internal-sftp") {
		return "internal-sftp"
	}
	if strings.Contains(strings.ToLower(serverVersion), "openssh") {
		return "openssh-sftp"
	}
	if strings.Contains(strings.ToLower(serverVersion), "libssh") {
		return "libssh-sftp"
	}
	return "unknown"
}

// IncrementRenegotiation increments renegotiation counter
func (pd *ProtocolDetector) IncrementRenegotiation(sessionID string, timestamp int64) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	if proto, exists := pd.connections[sessionID]; exists {
		proto.RenegotiationsCount++
		proto.LastRenegotiation = timestamp
	}
}

// IncrementKeepalive increments keepalive counter
func (pd *ProtocolDetector) IncrementKeepalive(sessionID string, timestamp int64) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	if proto, exists := pd.connections[sessionID]; exists {
		proto.KeepalivesReceived++
		proto.LastKeepalive = timestamp
	}
}

// RemoveConnection removes protocol tracking for a connection
func (pd *ProtocolDetector) RemoveConnection(sessionID string) {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	delete(pd.connections, sessionID)
}

// GetStats returns overall protocol statistics
func (pd *ProtocolDetector) GetStats() map[string]interface{} {
	pd.mu.RLock()
	defer pd.mu.RUnlock()

	v2Count := 0
	v3Count := 0
	unknownCount := 0
	internalSFTPCount := 0
	openSSHCount := 0
	totalRenegotiations := int64(0)
	totalKeepalives := int64(0)
	compressionEnabledCount := 0

	for _, proto := range pd.connections {
		switch proto.Version {
		case "2":
			v2Count++
		case "3":
			v3Count++
		default:
			unknownCount++
		}

		switch proto.Subsystem {
		case "internal-sftp":
			internalSFTPCount++
		case "openssh-sftp":
			openSSHCount++
		}

		if proto.CompressionEnabled {
			compressionEnabledCount++
		}

		totalRenegotiations += proto.RenegotiationsCount
		totalKeepalives += proto.KeepalivesReceived
	}

	return map[string]interface{}{
		"total_connections":      len(pd.connections),
		"sftp_v2_count":          v2Count,
		"sftp_v3_count":          v3Count,
		"unknown_version_count":  unknownCount,
		"internal_sftp_count":    internalSFTPCount,
		"openssh_sftp_count":     openSSHCount,
		"compression_enabled":    compressionEnabledCount,
		"total_renegotiations":   totalRenegotiations,
		"total_keepalives":       totalKeepalives,
	}
}

// GetProtocolDistribution returns version distribution
func (pd *ProtocolDetector) GetProtocolDistribution() map[string]int {
	pd.mu.RLock()
	defer pd.mu.RUnlock()

	distribution := make(map[string]int)
	for _, proto := range pd.connections {
		distribution[proto.Version]++
	}
	return distribution
}

// GetSubsystemDistribution returns subsystem distribution
func (pd *ProtocolDetector) GetSubsystemDistribution() map[string]int {
	pd.mu.RLock()
	defer pd.mu.RUnlock()

	distribution := make(map[string]int)
	for _, proto := range pd.connections {
		distribution[proto.Subsystem]++
	}
	return distribution
}

// GetRenegotiationRate returns average renegotiation count per connection
func (pd *ProtocolDetector) GetRenegotiationRate() float64 {
	pd.mu.RLock()
	defer pd.mu.RUnlock()

	if len(pd.connections) == 0 {
		return 0
	}

	total := int64(0)
	for _, proto := range pd.connections {
		total += proto.RenegotiationsCount
	}

	return float64(total) / float64(len(pd.connections))
}

// GetKeepaliveRate returns average keepalive count per connection
func (pd *ProtocolDetector) GetKeepaliveRate() float64 {
	pd.mu.RLock()
	defer pd.mu.RUnlock()

	if len(pd.connections) == 0 {
		return 0
	}

	total := int64(0)
	for _, proto := range pd.connections {
		total += proto.KeepalivesReceived
	}

	return float64(total) / float64(len(pd.connections))
}
