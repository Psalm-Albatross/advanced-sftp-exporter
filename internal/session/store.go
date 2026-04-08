package session

import (
	"fmt"
	"sync"
	"time"
)

// SessionStore provides thread-safe access to session state
type SessionStore struct {
	data map[string]map[string]SessionInfo  // map[user]map[sessionID]SessionInfo
	mu   sync.RWMutex
	ttl  time.Duration
}

// SessionInfo holds information about a single session
type SessionInfo struct {
	StartTime  time.Time
	LastActive time.Time
	SourceIP   string
	Method     string // login method (key, password, etc)
	Metadata   map[string]string
}

// NewSessionStore creates a new thread-safe session store
func NewSessionStore(ttl time.Duration) *SessionStore {
	store := &SessionStore{
		data: make(map[string]map[string]SessionInfo),
		ttl:  ttl,
	}

	// Start cleanup goroutine
	go store.cleanupExpired()

	return store
}

// Add adds or updates a session
func (s *SessionStore) Add(user, sessionID string, info SessionInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.data[user]; !exists {
		s.data[user] = make(map[string]SessionInfo)
	}

	info.LastActive = time.Now()
	s.data[user][sessionID] = info
}

// Remove removes a session entry
func (s *SessionStore) Remove(user, sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if userSessions, exists := s.data[user]; exists {
		delete(userSessions, sessionID)
		if len(userSessions) == 0 {
			delete(s.data, user)
		}
	}
}

// Get retrieves a session
func (s *SessionStore) Get(user, sessionID string) (SessionInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if userSessions, exists := s.data[user]; exists {
		if session, ok := userSessions[sessionID]; ok {
			return session, true
		}
	}
	return SessionInfo{}, false
}

// GetUserSessions returns all sessions for a user
func (s *SessionStore) GetUserSessions(user string) map[string]SessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if userSessions, exists := s.data[user]; exists {
		// Return a copy to avoid external mutations
		result := make(map[string]SessionInfo)
		for k, v := range userSessions {
			result[k] = v
		}
		return result
	}
	return make(map[string]SessionInfo)
}

// GetAllUsers returns all users currently in the store
func (s *SessionStore) GetAllUsers() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]string, 0, len(s.data))
	for user := range s.data {
		users = append(users, user)
	}
	return users
}

// ActiveSessionCount returns number of active sessions for a user
func (s *SessionStore) ActiveSessionCount(user string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if userSessions, exists := s.data[user]; exists {
		return len(userSessions)
	}
	return 0
}

// TotalActiveSessions returns total active sessions across all users
func (s *SessionStore) TotalActiveSessions() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := 0
	for _, userSessions := range s.data {
		total += len(userSessions)
	}
	return total
}

// GetOldestSession returns the oldest session for a user (for duration calculation)
func (s *SessionStore) GetOldestSession(user string) (string, SessionInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if userSessions, exists := s.data[user]; exists && len(userSessions) > 0 {
		var oldestID string
		var oldestInfo SessionInfo
		oldestTime := time.Now()

		for id, info := range userSessions {
			if info.StartTime.Before(oldestTime) {
				oldestID = id
				oldestInfo = info
				oldestTime = info.StartTime
			}
		}
		return oldestID, oldestInfo, true
	}
	return "", SessionInfo{}, false
}

// UpdateLastActive updates the last activity timestamp for a session
func (s *SessionStore) UpdateLastActive(user, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if userSessions, exists := s.data[user]; exists {
		if session, ok := userSessions[sessionID]; ok {
			session.LastActive = time.Now()
			userSessions[sessionID] = session
			return nil
		}
	}
	return fmt.Errorf("session not found: user=%s, sessionID=%s", user, sessionID)
}

// cleanupExpired removes expired sessions periodically
func (s *SessionStore) cleanupExpired() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.removeExpiredSessions()
	}
}

// removeExpiredSessions removes sessions older than TTL
func (s *SessionStore) removeExpiredSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for user, userSessions := range s.data {
		for sessionID, session := range userSessions {
			if now.Sub(session.StartTime) > s.ttl {
				delete(userSessions, sessionID)
			}
		}
		if len(userSessions) == 0 {
			delete(s.data, user)
		}
	}
}

// Clear removes all sessions (useful for testing)
func (s *SessionStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = make(map[string]map[string]SessionInfo)
}

// Stats returns statistics about the store
type StoreStats struct {
	TotalUsers    int
	TotalSessions int
	AvgSessionsPerUser float64
}

// GetStats returns current store statistics
func (s *SessionStore) GetStats() StoreStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	totalSessions := 0
	for _, userSessions := range s.data {
		totalSessions += len(userSessions)
	}

	avgSessions := 0.0
	if len(s.data) > 0 {
		avgSessions = float64(totalSessions) / float64(len(s.data))
	}

	return StoreStats{
		TotalUsers:     len(s.data),
		TotalSessions:  totalSessions,
		AvgSessionsPerUser: avgSessions,
	}
}
