package anomaly

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// AnomalyScorer calculates anomaly scores for user behavior
type AnomalyScorer struct {
	userProfiles map[string]*UserProfile
	mu           sync.RWMutex
}

// UserProfile holds behavioral profile for a user
type UserProfile struct {
	User              string
	OperationHistory  []OperationRecord
	LastUpdate        time.Time
	AverageOpsPerSec  float64
	StdDevOpsPerSec   float64
	AverageFileSize   float64
	TypicalLoginHours map[int]int // hour -> count
	IPs               map[string]int
	FileTypes         map[string]int
}

// OperationRecord records a single operation
type OperationRecord struct {
	Timestamp   time.Time
	Operation   string // PUT, GET, DELETE, MKDIR, etc.
	FileSize    int64
	Duration    time.Duration
	Success     bool
}

// AnomalyScore represents an anomaly score for a user
type AnomalyScore struct {
	User                   string
	OperationRateScore     float64 // 0-1: how anomalous is the operation rate
	EntropyScore           float64 // 0-1: randomness of file operations
	TimePatternScore       float64 // 0-1: deviation from typical login hours
	IPReputationScore      float64 // 0-1: how unusual is this IP
	CommandSequenceScore   float64 // 0-1: how suspicious is the operation sequence
	OverallAnomalyScore    float64 // 0-1: combined score
	RiskLevel              string  // "low", "medium", "high", "critical"
	Flags                  []string
}

// NewAnomalyScorer creates a new anomaly scorer
func NewAnomalyScorer() *AnomalyScorer {
	return &AnomalyScorer{
		userProfiles: make(map[string]*UserProfile),
	}
}

// RecordOperation records an operation for a user
func (as *AnomalyScorer) RecordOperation(user string, opRecord OperationRecord) {
	as.mu.Lock()
	defer as.mu.Unlock()

	if _, exists := as.userProfiles[user]; !exists {
		as.userProfiles[user] = &UserProfile{
			User:              user,
			OperationHistory:  make([]OperationRecord, 0),
			TypicalLoginHours: make(map[int]int),
			IPs:               make(map[string]int),
			FileTypes:         make(map[string]int),
		}
	}

	profile := as.userProfiles[user]
	profile.OperationHistory = append(profile.OperationHistory, opRecord)
	profile.LastUpdate = time.Now()

	// Keep only last 10000 operations (sliding window)
	if len(profile.OperationHistory) > 10000 {
		profile.OperationHistory = profile.OperationHistory[1:]
	}
}

// CalculateAnomalyScore calculates the current anomaly score for a user
func (as *AnomalyScorer) CalculateAnomalyScore(user string) *AnomalyScore {
	as.mu.RLock()
	profile, exists := as.userProfiles[user]
	as.mu.RUnlock()

	if !exists || len(profile.OperationHistory) < 5 {
		// Not enough data
		return &AnomalyScore{
			User:                user,
			OperationRateScore:  0,
			EntropyScore:        0,
			TimePatternScore:    0,
			IPReputationScore:   0,
			CommandSequenceScore: 0,
			OverallAnomalyScore: 0,
			RiskLevel:           "low",
			Flags:               []string{"insufficient_data"},
		}
	}

	score := &AnomalyScore{
		User:  user,
		Flags: make([]string, 0),
	}

	// Calculate individual scores
	score.OperationRateScore = as.calculateOperationRateAnomaly(profile)
	score.EntropyScore = as.calculateEntropyAnomaly(profile)
	score.TimePatternScore = as.calculateTimePatternAnomaly(profile)
	score.CommandSequenceScore = as.calculateCommandSequenceAnomaly(profile)

	// Combine scores (weighted average)
	score.OverallAnomalyScore = (score.OperationRateScore*0.3 +
		score.EntropyScore*0.2 +
		score.TimePatternScore*0.2 +
		score.CommandSequenceScore*0.3)

	// Set risk level
	if score.OverallAnomalyScore > 0.8 {
		score.RiskLevel = "critical"
		score.Flags = append(score.Flags, "critical_anomaly_detected")
	} else if score.OverallAnomalyScore > 0.6 {
		score.RiskLevel = "high"
		score.Flags = append(score.Flags, "high_anomaly_detected")
	} else if score.OverallAnomalyScore > 0.3 {
		score.RiskLevel = "medium"
		score.Flags = append(score.Flags, "medium_anomaly_detected")
	} else {
		score.RiskLevel = "low"
	}

	return score
}

// calculateOperationRateAnomaly detects sudden spikes in operation rate
func (as *AnomalyScorer) calculateOperationRateAnomaly(profile *UserProfile) float64 {
	if len(profile.OperationHistory) < 10 {
		return 0
	}

	// Look at recent 5 minutes vs older 5 minutes
	now := time.Now()
	recent := 0
	older := 0

	for _, op := range profile.OperationHistory {
		if now.Sub(op.Timestamp) < 5*time.Minute {
			recent++
		} else if now.Sub(op.Timestamp) < 10*time.Minute {
			older++
		}
	}

	if older == 0 {
		return 0
	}

	// Calculate rate ratio
	recentRate := float64(recent) / 5.0  // ops per minute
	olderRate := float64(older) / 5.0    // ops per minute
	baseline := (recentRate + olderRate) / 2.0

	if baseline == 0 {
		return 0
	}

	ratio := math.Abs(recentRate - baseline) / baseline
	// Clamp to 0-1
	if ratio > 1 {
		ratio = 1
	}

	return ratio
}

// calculateEntropyAnomaly measures randomness of file operations
func (as *AnomalyScorer) calculateEntropyAnomaly(profile *UserProfile) float64 {
	if len(profile.OperationHistory) < 5 {
		return 0
	}

	// Calculate type distribution
	typeDist := make(map[string]int)
	for _, op := range profile.OperationHistory {
		typeDist[op.Operation]++
	}

	// Calculate entropy
	total := len(profile.OperationHistory)
	entropy := 0.0

	for _, count := range typeDist {
		p := float64(count) / float64(total)
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	// Normalize (max entropy for 6 types: log2(6) ≈ 2.58)
	maxEntropy := math.Log2(6.0)
	if maxEntropy > 0 {
		entropy = entropy / maxEntropy
	}

	// High entropy (diverse operations) is normal, low entropy is suspicious
	// Invert: 0 = highly diverse (normal), 1 = very focused (suspicious)
	return 1.0 - entropy
}

// calculateTimePatternAnomaly detects login at unusual times
func (as *AnomalyScorer) calculateTimePatternAnomaly(profile *UserProfile) float64 {
	if len(profile.OperationHistory) < 10 {
		return 0
	}

	// Build hour distribution
	hourDist := make(map[int]int)
	for _, op := range profile.OperationHistory {
		hour := op.Timestamp.Hour()
		hourDist[hour]++
	}

	// Find most common hours
	maxCount := 0
	for _, count := range hourDist {
		if count > maxCount {
			maxCount = count
		}
	}

	// Current hour deviation from max
	now := time.Now()
	currentHour := now.Hour()
	currentHourCount := hourDist[currentHour]

	if maxCount == 0 {
		return 0
	}

	// Score: how far is current hour from typical
	deviation := float64(maxCount-currentHourCount) / float64(maxCount)
	if deviation < 0 {
		deviation = 0
	}

	return deviation
}

// calculateCommandSequenceAnomaly detects suspicious operation patterns
func (as *AnomalyScorer) calculateCommandSequenceAnomaly(profile *UserProfile) float64 {
	if len(profile.OperationHistory) < 3 {
		return 0
	}

	suspiciousPatterns := 0
	totalSequences := 0

	// Look for suspicious patterns: upload -> delete -> download (exfil pattern)
	for i := 0; i < len(profile.OperationHistory)-2; i++ {
		op1 := profile.OperationHistory[i].Operation
		op2 := profile.OperationHistory[i+1].Operation
		op3 := profile.OperationHistory[i+2].Operation
		totalSequences++

		// Exfiltration pattern: upload -> delete -> download
		if (op1 == "PUT" || op1 == "UPLOAD") &&
			(op2 == "DELETE" || op2 == "RM") &&
			(op3 == "GET" || op3 == "DOWNLOAD") {
			suspiciousPatterns++
		}

		// Reconnaissance pattern: many STATs in a row
		if op1 == "STAT" && op2 == "STAT" && op3 == "STAT" {
			suspiciousPatterns++
		}
	}

	if totalSequences == 0 {
		return 0
	}

	score := float64(suspiciousPatterns) / float64(totalSequences)
	if score > 1 {
		score = 1
	}

	return score
}

// GetStats returns statistics about all tracked users
func (as *AnomalyScorer) GetStats() map[string]interface{} {
	as.mu.RLock()
	defer as.mu.RUnlock()

	totalUsers := len(as.userProfiles)
	highRiskCount := 0
	totalOps := 0

	for _, profile := range as.userProfiles {
		totalOps += len(profile.OperationHistory)
	}

	return map[string]interface{}{
		"total_tracked_users": totalUsers,
		"high_risk_users":     highRiskCount,
		"total_operations":    totalOps,
	}
}

// GetUserProfile returns the profile for a user
func (as *AnomalyScorer) GetUserProfile(user string) *UserProfile {
	as.mu.RLock()
	defer as.mu.RUnlock()

	profile, exists := as.userProfiles[user]
	if !exists {
		return nil
	}

	// Return a copy
	return &UserProfile{
		User:              profile.User,
		OperationHistory:  append([]OperationRecord{}, profile.OperationHistory...),
		LastUpdate:        profile.LastUpdate,
		AverageOpsPerSec:  profile.AverageOpsPerSec,
		StdDevOpsPerSec:   profile.StdDevOpsPerSec,
		AverageFileSize:   profile.AverageFileSize,
		TypicalLoginHours: copyIntIntMap(profile.TypicalLoginHours),
		IPs:               copyIntMap(profile.IPs),
		FileTypes:         copyIntMap(profile.FileTypes),
	}
}

// Helper function to copy map[string]int
func copyIntMap(m map[string]int) map[string]int {
	result := make(map[string]int)
	for k, v := range m {
		result[k] = v
	}
	return result
}

// Helper function to copy map[int]int
func copyIntIntMap(m map[int]int) map[int]int {
	result := make(map[int]int)
	for k, v := range m {
		result[k] = v
	}
	return result
}

// String returns string representation of anomaly score
func (as *AnomalyScore) String() string {
	return fmt.Sprintf("AnomalyScore{user=%s, overall=%.2f, risk=%s, flags=%v}",
		as.User, as.OverallAnomalyScore, as.RiskLevel, as.Flags)
}
