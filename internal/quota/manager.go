package quota

import (
	"sync"
	"time"
)

// UserQuota represents bandwidth and storage quota for a user
type UserQuota struct {
	User                 string
	BandwidthLimitBps    int64     // bits per second
	StorageQuotaBytes    int64     // total bytes allowed
	DailyLimitBytes      int64     // max bytes per day
	CurrentBandwidthUsed int64     // current bandwidth usage
	CurrentStorageUsed   int64     // current storage usage
	DailyUsed            int64     // bytes transferred today
	LastReset            time.Time
	IsThrottled          bool
	ThrottleUntil        *time.Time
}

// QuotaManager manages bandwidth and storage quotas
type QuotaManager struct {
	quotas map[string]*UserQuota
	mu     sync.RWMutex
}

// NewQuotaManager creates a new quota manager
func NewQuotaManager() *QuotaManager {
	qm := &QuotaManager{
		quotas: make(map[string]*UserQuota),
	}

	// Cleanup throttled users periodically
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			qm.checkThrottleStatus()
		}
	}()

	return qm
}

// SetUserQuota sets quotas for a user
func (qm *QuotaManager) SetUserQuota(user string, bandwidthBps, storageBytesLimit, dailyBytesLimit int64) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	qm.quotas[user] = &UserQuota{
		User:              user,
		BandwidthLimitBps: bandwidthBps,
		StorageQuotaBytes: storageBytesLimit,
		DailyLimitBytes:   dailyBytesLimit,
		LastReset:         time.Now(),
	}
}

// GetQuota retrieves the quota for a user
func (qm *QuotaManager) GetQuota(user string) *UserQuota {
	qm.mu.RLock()
	defer qm.mu.RUnlock()

	quota, exists := qm.quotas[user]
	if !exists {
		return nil
	}

	// Return a copy
	return &UserQuota{
		User:                 quota.User,
		BandwidthLimitBps:    quota.BandwidthLimitBps,
		StorageQuotaBytes:    quota.StorageQuotaBytes,
		DailyLimitBytes:      quota.DailyLimitBytes,
		CurrentBandwidthUsed: quota.CurrentBandwidthUsed,
		CurrentStorageUsed:   quota.CurrentStorageUsed,
		DailyUsed:            quota.DailyUsed,
		LastReset:            quota.LastReset,
		IsThrottled:          quota.IsThrottled,
		ThrottleUntil:        quota.ThrottleUntil,
	}
}

// RecordTransfer records bytes transferred for a user
func (qm *QuotaManager) RecordTransfer(user string, bytes int64) (allowed bool, throttle bool) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	quota, exists := qm.quotas[user]
	if !exists {
		return true, false // No quota set = unlimited
	}

	// Check daily limit
	if quota.DailyLimitBytes > 0 {
		if quota.DailyUsed+bytes > quota.DailyLimitBytes {
			return false, true // Exceed daily limit, throttle
		}
		quota.DailyUsed += bytes
	}

	// Check storage quota
	if quota.StorageQuotaBytes > 0 {
		if quota.CurrentStorageUsed+bytes > quota.StorageQuotaBytes {
			return false, true // Exceed storage, throttle
		}
		quota.CurrentStorageUsed += bytes
	}

	return true, false
}

// ResetDailyUsage resets daily usage counters
func (qm *QuotaManager) ResetDailyUsage() {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	now := time.Now()
	for _, quota := range qm.quotas {
		// Reset if a day has passed
		if now.Sub(quota.LastReset) > 24*time.Hour {
			quota.DailyUsed = 0
			quota.LastReset = now
		}
	}
}

// Throttle marks a user as throttled until a specific time
func (qm *QuotaManager) Throttle(user string, duration time.Duration) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	quota, exists := qm.quotas[user]
	if !exists {
		quota = &UserQuota{User: user}
		qm.quotas[user] = quota
	}

	until := time.Now().Add(duration)
	quota.IsThrottled = true
	quota.ThrottleUntil = &until
}

// Unthrottle removes throttling from a user
func (qm *QuotaManager) Unthrottle(user string) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	quota, exists := qm.quotas[user]
	if !exists {
		return
	}

	quota.IsThrottled = false
	quota.ThrottleUntil = nil
}

// IsThrottled checks if a user is currently throttled
func (qm *QuotaManager) IsThrottled(user string) bool {
	qm.mu.RLock()
	defer qm.mu.RUnlock()

	quota, exists := qm.quotas[user]
	if !exists {
		return false
	}

	return quota.IsThrottled
}

// checkThrottleStatus removes expired throttles
func (qm *QuotaManager) checkThrottleStatus() {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	now := time.Now()
	for _, quota := range qm.quotas {
		if quota.IsThrottled && quota.ThrottleUntil != nil {
			if now.After(*quota.ThrottleUntil) {
				quota.IsThrottled = false
				quota.ThrottleUntil = nil
			}
		}
	}
}

// GetUsagePercent returns the percentage of quota used
func (qm *QuotaManager) GetUsagePercent(user string) float64 {
	qm.mu.RLock()
	defer qm.mu.RUnlock()

	quota, exists := qm.quotas[user]
	if !exists {
		return 0
	}

	if quota.StorageQuotaBytes == 0 {
		return 0
	}

	return float64(quota.CurrentStorageUsed) / float64(quota.StorageQuotaBytes) * 100
}

// GetStats returns overall quota statistics
func (qm *QuotaManager) GetStats() map[string]interface{} {
	qm.mu.RLock()
	defer qm.mu.RUnlock()

	totalUsers := len(qm.quotas)
	throttledUsers := 0
	overQuotaUsers := 0
	totalQuotaUsed := int64(0)
	totalQuotaLimit := int64(0)

	for _, quota := range qm.quotas {
		if quota.IsThrottled {
			throttledUsers++
		}

		if quota.StorageQuotaBytes > 0 && quota.CurrentStorageUsed > quota.StorageQuotaBytes {
			overQuotaUsers++
		}

		if quota.StorageQuotaBytes > 0 {
			totalQuotaUsed += quota.CurrentStorageUsed
			totalQuotaLimit += quota.StorageQuotaBytes
		}
	}

	usagePercent := 0.0
	if totalQuotaLimit > 0 {
		usagePercent = float64(totalQuotaUsed) / float64(totalQuotaLimit) * 100
	}

	return map[string]interface{}{
		"total_users":       totalUsers,
		"throttled_users":   throttledUsers,
		"over_quota_users":  overQuotaUsers,
		"total_quota_used":  totalQuotaUsed,
		"total_quota_limit": totalQuotaLimit,
		"usage_percent":     usagePercent,
	}
}

// BandwidthTracker tracks bandwidth usage over time
type BandwidthTracker struct {
	userBandwidth map[string]*BandwidthStats
	mu            sync.RWMutex
}

// BandwidthStats holds bandwidth statistics for a user
type BandwidthStats struct {
	User              string
	BytesUpIn1Min     int64
	BytesUpIn5Min     int64
	BytesUpIn1Hour    int64
	BytesDownIn1Min   int64
	BytesDownIn5Min   int64
	BytesDownIn1Hour  int64
	PeakBandwidthBps  int64
	LastUpdateTime    time.Time
}

// NewBandwidthTracker creates a new bandwidth tracker
func NewBandwidthTracker() *BandwidthTracker {
	return &BandwidthTracker{
		userBandwidth: make(map[string]*BandwidthStats),
	}
}

// RecordUpload records an upload transfer
func (bt *BandwidthTracker) RecordUpload(user string, bytes int64) {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	if _, exists := bt.userBandwidth[user]; !exists {
		bt.userBandwidth[user] = &BandwidthStats{
			User:           user,
			LastUpdateTime: time.Now(),
		}
	}

	stats := bt.userBandwidth[user]
	stats.BytesUpIn1Min += bytes
	stats.BytesUpIn5Min += bytes
	stats.BytesUpIn1Hour += bytes
	stats.LastUpdateTime = time.Now()
}

// RecordDownload records a download transfer
func (bt *BandwidthTracker) RecordDownload(user string, bytes int64) {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	if _, exists := bt.userBandwidth[user]; !exists {
		bt.userBandwidth[user] = &BandwidthStats{
			User:           user,
			LastUpdateTime: time.Now(),
		}
	}

	stats := bt.userBandwidth[user]
	stats.BytesDownIn1Min += bytes
	stats.BytesDownIn5Min += bytes
	stats.BytesDownIn1Hour += bytes
	stats.LastUpdateTime = time.Now()
}

// GetBandwidthStats retrieves bandwidth stats for a user
func (bt *BandwidthTracker) GetBandwidthStats(user string) *BandwidthStats {
	bt.mu.RLock()
	defer bt.mu.RUnlock()

	stats, exists := bt.userBandwidth[user]
	if !exists {
		return nil
	}

	return stats
}

// GetAllBandwidthStats returns stats for all users
func (bt *BandwidthTracker) GetAllBandwidthStats() map[string]*BandwidthStats {
	bt.mu.RLock()
	defer bt.mu.RUnlock()

	result := make(map[string]*BandwidthStats)
	for user, stats := range bt.userBandwidth {
		result[user] = stats
	}
	return result
}
