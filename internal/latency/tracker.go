package latency

import (
	"sync"
	"time"
)

// OperationLatency tracks latency for a specific operation
type OperationLatency struct {
	Operation        string
	User             string
	StartTime        time.Time
	EndTime          time.Time
	Duration         time.Duration
	BytesTransferred int64
	Success          bool
	ErrorMsg         string
}

// LatencyStats holds statistics for an operation type per user
type LatencyStats struct {
	Operation      string
	User           string
	Count          int64
	TotalDuration  time.Duration
	MinDuration    time.Duration
	MaxDuration    time.Duration
	AvgDuration    time.Duration
	P50Duration    time.Duration
	P95Duration    time.Duration
	P99Duration    time.Duration
	SuccessCount   int64
	ErrorCount     int64
	ThroughputBps  float64
}

// LatencyTracker tracks file operation latencies
type LatencyTracker struct {
	operations map[string][]OperationLatency
	mu         sync.RWMutex
	maxOpsSize int // Max operations to keep per type
}

// NewLatencyTracker creates a new latency tracker
func NewLatencyTracker(maxOpsSize int) *LatencyTracker {
	return &LatencyTracker{
		operations: make(map[string][]OperationLatency),
		maxOpsSize: maxOpsSize,
	}
}

// RecordOperation records an operation latency
func (lt *LatencyTracker) RecordOperation(opLatency OperationLatency) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	key := opLatency.Operation + ":" + opLatency.User
	
	if _, exists := lt.operations[key]; !exists {
		lt.operations[key] = make([]OperationLatency, 0)
	}

	lt.operations[key] = append(lt.operations[key], opLatency)

	// Keep only max size
	if len(lt.operations[key]) > lt.maxOpsSize {
		lt.operations[key] = lt.operations[key][1:]
	}
}

// GetStats calculates statistics for an operation type
func (lt *LatencyTracker) GetStats(operation, user string) *LatencyStats {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	key := operation + ":" + user
	ops, exists := lt.operations[key]
	if !exists || len(ops) == 0 {
		return nil
	}

	stats := &LatencyStats{
		Operation:  operation,
		User:       user,
		Count:      int64(len(ops)),
		MinDuration: ops[0].Duration,
		MaxDuration: ops[0].Duration,
	}

	var durations []time.Duration
	totalDuration := time.Duration(0)
	totalBytes := int64(0)

	for _, op := range ops {
		durations = append(durations, op.Duration)
		totalDuration += op.Duration
		totalBytes += op.BytesTransferred

		if op.Duration < stats.MinDuration {
			stats.MinDuration = op.Duration
		}
		if op.Duration > stats.MaxDuration {
			stats.MaxDuration = op.Duration
		}

		if op.Success {
			stats.SuccessCount++
		} else {
			stats.ErrorCount++
		}
	}

	stats.TotalDuration = totalDuration
	stats.AvgDuration = time.Duration(totalDuration.Nanoseconds() / int64(len(ops)))

	// Calculate percentiles
	stats.P50Duration = calculatePercentile(durations, 0.50)
	stats.P95Duration = calculatePercentile(durations, 0.95)
	stats.P99Duration = calculatePercentile(durations, 0.99)

	// Calculate throughput
	if totalDuration.Seconds() > 0 {
		stats.ThroughputBps = float64(totalBytes*8) / totalDuration.Seconds()
	}

	return stats
}

// GetAllStats returns statistics for all tracked operations
func (lt *LatencyTracker) GetAllStats() []*LatencyStats {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	var result []*LatencyStats

	for _, ops := range lt.operations {
		if len(ops) == 0 {
			continue
		}

		op := ops[0]
		stats := lt.calculateStatsUnsafe(op.Operation, op.User, ops)
		result = append(result, stats)
	}

	return result
}

// calculateStatsUnsafe calculates stats without locking (assumes lock held)
func (lt *LatencyTracker) calculateStatsUnsafe(operation, user string, ops []OperationLatency) *LatencyStats {
	if len(ops) == 0 {
		return nil
	}

	stats := &LatencyStats{
		Operation:  operation,
		User:       user,
		Count:      int64(len(ops)),
		MinDuration: ops[0].Duration,
		MaxDuration: ops[0].Duration,
	}

	var durations []time.Duration
	totalDuration := time.Duration(0)
	totalBytes := int64(0)

	for _, op := range ops {
		durations = append(durations, op.Duration)
		totalDuration += op.Duration
		totalBytes += op.BytesTransferred

		if op.Duration < stats.MinDuration {
			stats.MinDuration = op.Duration
		}
		if op.Duration > stats.MaxDuration {
			stats.MaxDuration = op.Duration
		}

		if op.Success {
			stats.SuccessCount++
		} else {
			stats.ErrorCount++
		}
	}

	stats.TotalDuration = totalDuration
	stats.AvgDuration = time.Duration(totalDuration.Nanoseconds() / int64(len(ops)))

	// Calculate percentiles
	stats.P50Duration = calculatePercentile(durations, 0.50)
	stats.P95Duration = calculatePercentile(durations, 0.95)
	stats.P99Duration = calculatePercentile(durations, 0.99)

	// Calculate throughput
	if totalDuration.Seconds() > 0 {
		stats.ThroughputBps = float64(totalBytes*8) / totalDuration.Seconds()
	}

	return stats
}

// calculatePercentile calculates a percentile from a slice of durations
func calculatePercentile(durations []time.Duration, percentile float64) time.Duration {
	if len(durations) == 0 {
		return 0
	}

	// Simple percentile calculation (not sorted, so approximate)
	index := int(float64(len(durations)) * percentile)
	if index >= len(durations) {
		index = len(durations) - 1
	}

	return durations[index]
}

// GetLatestOperations returns the latest N operations for a type
func (lt *LatencyTracker) GetLatestOperations(operation, user string, count int) []OperationLatency {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	key := operation + ":" + user
	ops, exists := lt.operations[key]
	if !exists {
		return []OperationLatency{}
	}

	if count > len(ops) {
		count = len(ops)
	}

	// Return latest count operations
	return append([]OperationLatency{}, ops[len(ops)-count:]...)
}

// GetOperationTypes returns all operation types being tracked
func (lt *LatencyTracker) GetOperationTypes() []string {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	seen := make(map[string]bool)
	var result []string

	for key := range lt.operations {
		// key format: "OPERATION:user"
		ops := key[:len(key)-len(key[len(key)-1:])-1]
		if !seen[ops] {
			result = append(result, ops)
			seen[ops] = true
		}
	}

	return result
}

// ClearOldOperations removes operations older than the specified duration
func (lt *LatencyTracker) ClearOldOperations(maxAge time.Duration) int {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	now := time.Now()
	removed := 0

	for key, ops := range lt.operations {
		var filtered []OperationLatency
		for _, op := range ops {
			if now.Sub(op.EndTime) < maxAge {
				filtered = append(filtered, op)
			} else {
				removed++
			}
		}
		if len(filtered) == 0 {
			delete(lt.operations, key)
		} else {
			lt.operations[key] = filtered
		}
	}

	return removed
}

// GetStats returns overall tracker statistics
func (lt *LatencyTracker) GetTrackerStats() map[string]interface{} {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	totalOps := 0
	operationTypes := make(map[string]int)
	userCount := make(map[string]bool)

	for key, ops := range lt.operations {
		totalOps += len(ops)
		// key format: "OPERATION:user"
		opType := key
		userCount[key] = true
		operationTypes[opType]++
	}

	return map[string]interface{}{
		"total_operations":    totalOps,
		"operation_types":     len(operationTypes),
		"active_users":        len(userCount),
		"operations_by_type":  operationTypes,
	}
}
