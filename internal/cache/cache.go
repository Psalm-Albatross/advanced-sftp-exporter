package cache

import (
	"sync"
	"time"
)

// Entry represents a cached value
type Entry struct {
	Value      interface{}
	ExpiresAt  time.Time
	CreatedAt  time.Time
	TTL        time.Duration
	HitCount   int
	MissCount  int
}

// IsExpired checks if the entry has expired
func (e *Entry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// TTLCache is a thread-safe cache with TTL support
type TTLCache struct {
	data map[string]*Entry
	mu   sync.RWMutex
}

// NewTTLCache creates a new TTL cache
func NewTTLCache() *TTLCache {
	return &TTLCache{
		data: make(map[string]*Entry),
	}
}

// Set stores a value with TTL
func (c *TTLCache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	c.data[key] = &Entry{
		Value:     value,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
		TTL:       ttl,
		HitCount:  0,
		MissCount: 0,
	}
}

// Get retrieves a value from the cache
// Returns (value, found, expired) tuple
func (c *TTLCache) Get(key string) (interface{}, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.data[key]
	if !exists {
		return nil, false, false
	}

	if entry.IsExpired() {
		delete(c.data, key)
		entry.MissCount++
		return nil, true, true
	}

	entry.HitCount++
	return entry.Value, true, false
}

// GetOrSet retrieves a value or sets it if not found/expired using the provided function
func (c *TTLCache) GetOrSet(key string, ttl time.Duration, fn func() (interface{}, error)) (interface{}, error) {
	// Try to get existing value first
	value, found, expired := c.Get(key)
	if found && !expired {
		return value, nil
	}

	// Compute new value
	newValue, err := fn()
	if err != nil {
		return nil, err
	}

	// Store in cache
	c.Set(key, newValue, ttl)
	return newValue, nil
}

// Delete removes a key from the cache
func (c *TTLCache) Delete(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, exists := c.data[key]
	if exists {
		delete(c.data, key)
	}
	return exists
}

// Clear removes all entries from the cache
func (c *TTLCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data = make(map[string]*Entry)
}

// Cleanup removes expired entries
func (c *TTLCache) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	removed := 0
	for key, entry := range c.data {
		if entry.IsExpired() {
			delete(c.data, key)
			removed++
		}
	}
	return removed
}

// Size returns the number of valid (non-expired) entries in the cache
func (c *TTLCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	count := 0
	now := time.Now()
	for _, entry := range c.data {
		if now.Before(entry.ExpiresAt) {
			count++
		}
	}
	return count
}

// GetStats returns cache statistics
func (c *TTLCache) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	totalHits := 0
	totalMisses := 0
	totalEntries := len(c.data)
	expiredEntries := 0

	for _, entry := range c.data {
		totalHits += entry.HitCount
		totalMisses += entry.MissCount
		if entry.IsExpired() {
			expiredEntries++
		}
	}

	hitRate := 0.0
	if totalHits+totalMisses > 0 {
		hitRate = float64(totalHits) / float64(totalHits+totalMisses)
	}

	return map[string]interface{}{
		"total_entries":   totalEntries,
		"valid_entries":   totalEntries - expiredEntries,
		"expired_entries": expiredEntries,
		"total_hits":      totalHits,
		"total_misses":    totalMisses,
		"hit_rate":        hitRate,
	}
}

// CommandCache specifically caches command execution results
type CommandCache struct {
	cache *TTLCache
}

// NewCommandCache creates a new command cache
func NewCommandCache() *CommandCache {
	return &CommandCache{
		cache: NewTTLCache(),
	}
}

// GetCommand retrieves a cached command result
func (cc *CommandCache) GetCommand(cmd string) (string, bool) {
	value, found, expired := cc.cache.Get(cmd)
	if found && !expired {
		if str, ok := value.(string); ok {
			return str, true
		}
	}
	return "", false
}

// SetCommand stores a command result with TTL
func (cc *CommandCache) SetCommand(cmd string, result string, ttl time.Duration) {
	cc.cache.Set(cmd, result, ttl)
}

// GetOrExecute retrieves cached result or executes command
func (cc *CommandCache) GetOrExecute(cmd string, ttl time.Duration, fn func() (string, error)) (string, error) {
	if cached, found := cc.GetCommand(cmd); found {
		return cached, nil
	}

	result, err := fn()
	if err != nil {
		return "", err
	}

	cc.SetCommand(cmd, result, ttl)
	return result, nil
}

// Cleanup removes expired entries
func (cc *CommandCache) Cleanup() int {
	return cc.cache.Cleanup()
}

// GetStats returns cache statistics
func (cc *CommandCache) GetStats() map[string]interface{} {
	return cc.cache.GetStats()
}
