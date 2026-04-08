package cardinality

import (
	"log"
	"sync"
)

// LabelSet represents a set of label combinations
type LabelSet struct {
	values map[string]struct{}
	mu     sync.RWMutex
}

// NewLabelSet creates a new label set
func NewLabelSet() *LabelSet {
	return &LabelSet{
		values: make(map[string]struct{}),
	}
}

// Add adds a label value
func (ls *LabelSet) Add(value string) bool {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	if _, exists := ls.values[value]; exists {
		return false // Already exists
	}
	ls.values[value] = struct{}{}
	return true // New value added
}

// Contains checks if a label value exists
func (ls *LabelSet) Contains(value string) bool {
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	_, exists := ls.values[value]
	return exists
}

// Size returns the current cardinality
func (ls *LabelSet) Size() int {
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	return len(ls.values)
}

// GetAll returns all label values
func (ls *LabelSet) GetAll() []string {
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	result := make([]string, 0, len(ls.values))
	for value := range ls.values {
		result = append(result, value)
	}
	return result
}

// LimiterConfig holds configuration for the CardinalityLimiter
type LimiterConfig struct {
	MaxUserLabels           int // Max unique users (default: 1000)
	MaxIPLabels             int // Max unique IPs per user (default: 50)
	MaxFileTypeLabels       int // Max unique file types (default: 500)
	MaxSessionLabels        int // Max unique sessions (default: 1000)
	WarnThresholdPercent    int // Warn when exceeded (default: 70)
	OverflowLabelName       string // Label name for overflow (default: "other")
	CardinalityCheckInterval int // Check cardinality every N metric updates (default: 100)
}

// DefaultLimiterConfig returns sensible defaults
func DefaultLimiterConfig() LimiterConfig {
	return LimiterConfig{
		MaxUserLabels:           1000,
		MaxIPLabels:             50,
		MaxFileTypeLabels:       500,
		MaxSessionLabels:        1000,
		WarnThresholdPercent:    70,
		OverflowLabelName:       "other",
		CardinalityCheckInterval: 100,
	}
}

// CardinalityLimiter manages metric label cardinality
type CardinalityLimiter struct {
	config           LimiterConfig
	users            *LabelSet
	ips              map[string]*LabelSet // IPs per user
	fileTypes        *LabelSet
	sessions         *LabelSet
	overflowCounters map[string]int // Count of overflowed labels
	mu               sync.RWMutex
	logger           *log.Logger
	updateCounter    int
}

// NewCardinalityLimiter creates a new cardinality limiter
func NewCardinalityLimiter(cfg LimiterConfig, logger *log.Logger) *CardinalityLimiter {
	return &CardinalityLimiter{
		config:           cfg,
		users:            NewLabelSet(),
		ips:              make(map[string]*LabelSet),
		fileTypes:        NewLabelSet(),
		sessions:         NewLabelSet(),
		overflowCounters: make(map[string]int),
		logger:           logger,
	}
}

// AddUserLabel adds a user label, returns true if added (or already exists)
// Returns false if limit exceeded, along with the overflow counter increment
func (cl *CardinalityLimiter) AddUserLabel(user string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if cl.users.Contains(user) {
		return true
	}

	if cl.users.Size() >= cl.config.MaxUserLabels {
		cl.overflowCounters["users"]++
		cl.logger.Printf("[CardinalityLimiter] User label overflow (user=%s, cardinality=%d/%d)",
			user, cl.users.Size(), cl.config.MaxUserLabels)
		return false
	}

	cl.users.Add(user)

	// Check if we're approaching the limit
	percent := (cl.users.Size() * 100) / cl.config.MaxUserLabels
	if percent >= cl.config.WarnThresholdPercent {
		cl.logger.Printf("[CardinalityLimiter] User label cardinality warning: %d%% of limit reached (%d/%d)",
			percent, cl.users.Size(), cl.config.MaxUserLabels)
	}

	return true
}

// AddIPLabelForUser adds an IP label for a specific user
func (cl *CardinalityLimiter) AddIPLabelForUser(user, ip string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if _, exists := cl.ips[user]; !exists {
		cl.ips[user] = NewLabelSet()
	}

	if cl.ips[user].Contains(ip) {
		return true
	}

	if cl.ips[user].Size() >= cl.config.MaxIPLabels {
		cl.overflowCounters["ips"]++
		cl.logger.Printf("[CardinalityLimiter] IP label overflow for user %s (ip=%s, cardinality=%d/%d)",
			user, ip, cl.ips[user].Size(), cl.config.MaxIPLabels)
		return false
	}

	cl.ips[user].Add(ip)
	return true
}

// AddFileTypeLabel adds a file type label
func (cl *CardinalityLimiter) AddFileTypeLabel(fileType string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if cl.fileTypes.Contains(fileType) {
		return true
	}

	if cl.fileTypes.Size() >= cl.config.MaxFileTypeLabels {
		cl.overflowCounters["file_types"]++
		return false
	}

	cl.fileTypes.Add(fileType)

	// Check if we're approaching the limit
	percent := (cl.fileTypes.Size() * 100) / cl.config.MaxFileTypeLabels
	if percent >= cl.config.WarnThresholdPercent {
		cl.logger.Printf("[CardinalityLimiter] File type label cardinality warning: %d%% of limit reached (%d/%d)",
			percent, cl.fileTypes.Size(), cl.config.MaxFileTypeLabels)
	}

	return true
}

// AddSessionLabel adds a session label
func (cl *CardinalityLimiter) AddSessionLabel(sessionID string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if cl.sessions.Contains(sessionID) {
		return true
	}

	if cl.sessions.Size() >= cl.config.MaxSessionLabels {
		cl.overflowCounters["sessions"]++
		return false
	}

	cl.sessions.Add(sessionID)
	return true
}

// GetStats returns cardinality statistics
func (cl *CardinalityLimiter) GetStats() map[string]interface{} {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	totalIPs := 0
	for _, ipSet := range cl.ips {
		totalIPs += ipSet.Size()
	}

	return map[string]interface{}{
		"users":              cl.users.Size(),
		"max_users":          cl.config.MaxUserLabels,
		"total_ips":          totalIPs,
		"max_ips_per_user":   cl.config.MaxIPLabels,
		"file_types":         cl.fileTypes.Size(),
		"max_file_types":     cl.config.MaxFileTypeLabels,
		"sessions":           cl.sessions.Size(),
		"max_sessions":       cl.config.MaxSessionLabels,
		"overflow_counters":  cl.overflowCounters,
	}
}

// GetUserIPCount returns the number of IPs for a user
func (cl *CardinalityLimiter) GetUserIPCount(user string) int {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	if ipSet, exists := cl.ips[user]; exists {
		return ipSet.Size()
	}
	return 0
}
