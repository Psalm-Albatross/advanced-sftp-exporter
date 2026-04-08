package connection

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ConnectionInfo represents a single SFTP connection session
type ConnectionInfo struct {
	SessionID           string
	User                string
	RemoteIP            string
	RemotePort          int
	LocalPort           int
	StartTime           time.Time
	LastActivityTime    time.Time
	ProtocolVersion     string // "SSHv2", "SSHv3", etc.
	BytesUploaded       int64
	BytesDownloaded     int64
	OperationCount      int64
	LastOperation       string
	ConnectionDuration  time.Duration
	IsIdle              bool
	IdleSince           *time.Time
}

// ConnectionStore manages active SFTP connections
type ConnectionStore struct {
	connections map[string]*ConnectionInfo
	mu          sync.RWMutex
	ttl         time.Duration
}

// NewConnectionStore creates a new connection store with TTL for sessions
func NewConnectionStore(ttl time.Duration) *ConnectionStore {
	cs := &ConnectionStore{
		connections: make(map[string]*ConnectionInfo),
		ttl:         ttl,
	}

	// Cleanup expired connections periodically
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			cs.CleanupExpired()
		}
	}()

	return cs
}

// AddConnection adds or updates a connection
func (cs *ConnectionStore) AddConnection(connInfo *ConnectionInfo) {
	if connInfo == nil {
		return
	}

	cs.mu.Lock()
	defer cs.mu.Unlock()

	now := time.Now()
	connInfo.LastActivityTime = now
	if connInfo.StartTime.IsZero() {
		connInfo.StartTime = now
	}
	cs.connections[connInfo.SessionID] = connInfo
}

// GetConnection retrieves a connection by session ID
func (cs *ConnectionStore) GetConnection(sessionID string) (*ConnectionInfo, bool) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	conn, exists := cs.connections[sessionID]
	return conn, exists
}

// GetUserConnections retrieves all connections for a specific user
func (cs *ConnectionStore) GetUserConnections(user string) []*ConnectionInfo {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	var result []*ConnectionInfo
	for _, conn := range cs.connections {
		if conn.User == user {
			result = append(result, conn)
		}
	}
	return result
}

// GetConnectionsByIP retrieves all connections from a specific IP
func (cs *ConnectionStore) GetConnectionsByIP(ip string) []*ConnectionInfo {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	var result []*ConnectionInfo
	for _, conn := range cs.connections {
		if net.ParseIP(conn.RemoteIP) != nil && conn.RemoteIP == ip {
			result = append(result, conn)
		}
	}
	return result
}

// UpdateActivity updates the last activity time for a connection
func (cs *ConnectionStore) UpdateActivity(sessionID string) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	conn, exists := cs.connections[sessionID]
	if !exists {
		return false
	}

	conn.LastActivityTime = time.Now()
	conn.IsIdle = false
	conn.IdleSince = nil
	return true
}

// MarkIdle marks a connection as idle if no activity for threshold
func (cs *ConnectionStore) MarkIdle(sessionID string, idleThreshold time.Duration) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	conn, exists := cs.connections[sessionID]
	if !exists {
		return false
	}

	if time.Since(conn.LastActivityTime) > idleThreshold {
		now := time.Now()
		conn.IsIdle = true
		conn.IdleSince = &now
		return true
	}
	return false
}

// RecordOperation records an operation on a connection
func (cs *ConnectionStore) RecordOperation(sessionID, operation string, bytesTransferred int64) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	conn, exists := cs.connections[sessionID]
	if !exists {
		return false
	}

	conn.LastOperation = operation
	conn.OperationCount++
	conn.LastActivityTime = time.Now()
	conn.IsIdle = false
	conn.IdleSince = nil

	// Track bytes based on operation type
	if operation == "PUT" || operation == "UPLOAD" {
		conn.BytesUploaded += bytesTransferred
	} else if operation == "GET" || operation == "DOWNLOAD" {
		conn.BytesDownloaded += bytesTransferred
	}

	return true
}

// RemoveConnection removes a connection from the store
func (cs *ConnectionStore) RemoveConnection(sessionID string) (*ConnectionInfo, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	conn, exists := cs.connections[sessionID]
	if exists {
		conn.ConnectionDuration = time.Since(conn.StartTime)
		delete(cs.connections, sessionID)
	}
	return conn, exists
}

// GetAllConnections returns all active connections
func (cs *ConnectionStore) GetAllConnections() []*ConnectionInfo {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	result := make([]*ConnectionInfo, 0, len(cs.connections))
	for _, conn := range cs.connections {
		result = append(result, conn)
	}
	return result
}

// GetStats returns statistics about all connections
func (cs *ConnectionStore) GetStats() map[string]interface{} {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	activeCount := 0
	idleCount := 0
	totalBytesUp := int64(0)
	totalBytesDown := int64(0)
	totalOps := int64(0)
	userCount := make(map[string]int)
	ipCount := make(map[string]int)

	for _, conn := range cs.connections {
		if conn.IsIdle {
			idleCount++
		} else {
			activeCount++
		}
		totalBytesUp += conn.BytesUploaded
		totalBytesDown += conn.BytesDownloaded
		totalOps += conn.OperationCount
		userCount[conn.User]++
		ipCount[conn.RemoteIP]++
	}

	return map[string]interface{}{
		"total_connections":   len(cs.connections),
		"active_connections":  activeCount,
		"idle_connections":    idleCount,
		"total_bytes_upload":  totalBytesUp,
		"total_bytes_download": totalBytesDown,
		"total_operations":    totalOps,
		"unique_users":        len(userCount),
		"unique_ips":          len(ipCount),
	}
}

// CleanupExpired removes connections older than TTL
func (cs *ConnectionStore) CleanupExpired() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	now := time.Now()
	removed := 0

	for sessionID, conn := range cs.connections {
		if now.Sub(conn.LastActivityTime) > cs.ttl {
			conn.ConnectionDuration = now.Sub(conn.StartTime)
			delete(cs.connections, sessionID)
			removed++
		}
	}

	return removed
}

// GetConnectionMetrics returns detailed metrics for a connection
func (cs *ConnectionStore) GetConnectionMetrics(sessionID string) map[string]interface{} {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	conn, exists := cs.connections[sessionID]
	if !exists {
		return nil
	}

	duration := time.Since(conn.StartTime)
	uploadRate := 0.0
	downloadRate := 0.0
	totalTransferred := conn.BytesUploaded + conn.BytesDownloaded

	if duration.Seconds() > 0 {
		uploadRate = float64(conn.BytesUploaded) / duration.Seconds()
		downloadRate = float64(conn.BytesDownloaded) / duration.Seconds()
	}

	return map[string]interface{}{
		"session_id":       conn.SessionID,
		"user":             conn.User,
		"remote_ip":        conn.RemoteIP,
		"protocol_version": conn.ProtocolVersion,
		"start_time":       conn.StartTime,
		"last_activity":    conn.LastActivityTime,
		"duration_seconds": duration.Seconds(),
		"bytes_uploaded":   conn.BytesUploaded,
		"bytes_downloaded": conn.BytesDownloaded,
		"total_transferred": totalTransferred,
		"upload_rate_bps":  uploadRate,
		"download_rate_bps": downloadRate,
		"operation_count":  conn.OperationCount,
		"last_operation":   conn.LastOperation,
		"is_idle":          conn.IsIdle,
		"idle_since":       conn.IdleSince,
	}
}

// String returns a string representation
func (ci *ConnectionInfo) String() string {
	duration := time.Since(ci.StartTime)
	return fmt.Sprintf("Connection{user=%s, ip=%s, proto=%s, duration=%v, ops=%d, bytes_up=%d, bytes_down=%d}",
		ci.User, ci.RemoteIP, ci.ProtocolVersion, duration, ci.OperationCount, ci.BytesUploaded, ci.BytesDownloaded)
}
