package poller

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"
)

// PollerConfig holds configuration for the PollerManager
type PollerConfig struct {
	MaxWorkers           int           // Max concurrent monitor goroutines (default: 10)
	DefaultTickInterval  time.Duration // Default poll interval (default: 10s)
	AdaptiveBackoff      bool          // Enable adaptive polling backoff (default: true)
	StabilityThreshold   int           // Number of cycles without change before backoff (default: 5)
	BackoffMultiplier    float64       // Multiplier for backoff (default: 2.0)
	MaxBackoffInterval   time.Duration // Maximum interval when backing off (default: 60s)
	CardinalityWarnLimit int           // Warn when metric cardinality exceeds this (default: 1000)
}

// DefaultConfig returns sensible defaults for PollerConfig
func DefaultConfig() PollerConfig {
	return PollerConfig{
		MaxWorkers:         10,
		DefaultTickInterval: 10 * time.Second,
		AdaptiveBackoff:    true,
		StabilityThreshold: 5,
		BackoffMultiplier:  2.0,
		MaxBackoffInterval: 60 * time.Second,
		CardinalityWarnLimit: 1000,
	}
}

// PollerManager manages a pool of monitor goroutines with adaptive polling
type PollerManager struct {
	config        PollerConfig
	ctx           context.Context
	cancel        context.CancelFunc
	workers       *semaphore
	pollers       map[string]*PollerState
	mu            sync.RWMutex
	wg            sync.WaitGroup
	logger        *log.Logger
	shutdownCh    chan struct{}
	gracePeriod   time.Duration
}

// PollerState tracks the state of an individual poller
type PollerState struct {
	Name                string
	Interval            time.Duration // Current interval (may be adaptive)
	BaseInterval        time.Duration // Base interval before adaptation
	LastChangeTime      time.Time
	StableCountdown     int // Cycles until backoff
	IsBackedOff         bool
	LastRunTime         time.Time
	LastErrorTime       *time.Time
	ErrorCount          int
	SuccessCount        int
	TotalRuns           int
	mu                  sync.RWMutex
}

// semaphore limits concurrent goroutines
type semaphore struct {
	ch chan struct{}
}

func newSemaphore(maxWorkers int) *semaphore {
	return &semaphore{
		ch: make(chan struct{}, maxWorkers),
	}
}

func (s *semaphore) Acquire(ctx context.Context) error {
	select {
	case s.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *semaphore) Release() {
	<-s.ch
}

// NewPollerManager creates a new PollerManager with the given configuration
func NewPollerManager(cfg PollerConfig, logger *log.Logger) *PollerManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &PollerManager{
		config:      cfg,
		ctx:         ctx,
		cancel:      cancel,
		workers:     newSemaphore(cfg.MaxWorkers),
		pollers:     make(map[string]*PollerState),
		logger:      logger,
		shutdownCh:  make(chan struct{}),
		gracePeriod: 30 * time.Second,
	}
}

// Register registers a poller with the manager
func (pm *PollerManager) Register(name string, baseInterval time.Duration) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.pollers[name] = &PollerState{
		Name:           name,
		Interval:       baseInterval,
		BaseInterval:   baseInterval,
		StableCountdown: pm.config.StabilityThreshold,
		LastChangeTime: time.Now(),
	}
	pm.logger.Printf("[PollerManager] Registered poller: %s (interval: %v)", name, baseInterval)
}

// SchedulePoller runs a poller function with adaptive polling
// The poller function should return true if changes were detected, false otherwise
func (pm *PollerManager) SchedulePoller(name string, pollerFn func(context.Context) (bool, error)) {
	pm.wg.Add(1)
	go func() {
		defer pm.wg.Done()

		ps := pm.pollers[name]
		if ps == nil {
			pm.logger.Printf("[PollerManager] ERROR: Poller %s not registered", name)
			return
		}

		ticker := time.NewTicker(ps.Interval)
		defer ticker.Stop()

		for {
			select {
			case <-pm.ctx.Done():
				pm.logger.Printf("[PollerManager] Poller %s shutting down", name)
				return
			case <-ticker.C:
				// Acquire worker slot with timeout
				if err := pm.workers.Acquire(pm.ctx); err != nil {
					pm.logger.Printf("[PollerManager] Poller %s failed to acquire worker slot: %v", name, err)
					continue
				}

				startTime := time.Now()
				changed, err := pollerFn(pm.ctx)
				duration := time.Since(startTime)

				pm.workers.Release()

				// Update poller state
				ps.mu.Lock()
				ps.TotalRuns++
				ps.LastRunTime = startTime

				if err != nil {
					ps.ErrorCount++
					ps.LastErrorTime = &startTime
					pm.logger.Printf("[PollerManager] Poller %s error: %v (took %v)", name, err, duration)
				} else {
					ps.SuccessCount++
				}

				// Adapt polling interval based on changes
				if pm.config.AdaptiveBackoff {
					if changed {
						// Reset backoff on change
						ps.LastChangeTime = time.Now()
						ps.StableCountdown = pm.config.StabilityThreshold
						ps.IsBackedOff = false
						ps.Interval = ps.BaseInterval
						pm.logger.Printf("[PollerManager] Poller %s detected changes, reset interval to %v", name, ps.Interval)
					} else {
						// Countdown to backoff
						ps.StableCountdown--
						if ps.StableCountdown <= 0 && !ps.IsBackedOff {
							ps.IsBackedOff = true
							newInterval := time.Duration(float64(ps.BaseInterval) * pm.config.BackoffMultiplier)
							if newInterval > pm.config.MaxBackoffInterval {
								newInterval = pm.config.MaxBackoffInterval
							}
							ps.Interval = newInterval
							pm.logger.Printf("[PollerManager] Poller %s backing off to interval %v (no changes for %d cycles)", 
								name, ps.Interval, pm.config.StabilityThreshold)
						}
					}

					// Update ticker with new interval
					ticker.Reset(ps.Interval)
				}

				ps.mu.Unlock()
			}
		}
	}()
}

// GetPollerStats returns statistics for a registered poller
func (pm *PollerManager) GetPollerStats(name string) *PollerState {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	ps, exists := pm.pollers[name]
	if !exists {
		return nil
	}

	ps.mu.RLock()
	defer ps.mu.RUnlock()

	// Return a copy
	return &PollerState{
		Name:           ps.Name,
		Interval:       ps.Interval,
		BaseInterval:   ps.BaseInterval,
		LastChangeTime: ps.LastChangeTime,
		StableCountdown: ps.StableCountdown,
		IsBackedOff:    ps.IsBackedOff,
		LastRunTime:    ps.LastRunTime,
		LastErrorTime:  ps.LastErrorTime,
		ErrorCount:     ps.ErrorCount,
		SuccessCount:   ps.SuccessCount,
		TotalRuns:      ps.TotalRuns,
	}
}

// GetAllPollerStats returns statistics for all registered pollers
func (pm *PollerManager) GetAllPollerStats() map[string]*PollerState {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	result := make(map[string]*PollerState)
	for name, ps := range pm.pollers {
		ps.mu.RLock()
		result[name] = &PollerState{
			Name:           ps.Name,
			Interval:       ps.Interval,
			BaseInterval:   ps.BaseInterval,
			LastChangeTime: ps.LastChangeTime,
			StableCountdown: ps.StableCountdown,
			IsBackedOff:    ps.IsBackedOff,
			LastRunTime:    ps.LastRunTime,
			LastErrorTime:  ps.LastErrorTime,
			ErrorCount:     ps.ErrorCount,
			SuccessCount:   ps.SuccessCount,
			TotalRuns:      ps.TotalRuns,
		}
		ps.mu.RUnlock()
	}
	return result
}

// Shutdown gracefully stops all pollers
func (pm *PollerManager) Shutdown() error {
	pm.logger.Printf("[PollerManager] Initiating graceful shutdown...")
	pm.cancel()

	// Wait for all pollers to finish with timeout
	done := make(chan struct{})
	go func() {
		pm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		pm.logger.Printf("[PollerManager] All pollers shut down gracefully")
		return nil
	case <-time.After(pm.gracePeriod):
		pm.logger.Printf("[PollerManager] Grace period expired, forcing shutdown")
		return errors.New("shutdown grace period exceeded")
	}
}

// IsHealthy checks if the PollerManager is healthy
func (pm *PollerManager) IsHealthy() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if len(pm.pollers) == 0 {
		return false // No pollers registered
	}

	// Check if all pollers have recent activity
	now := time.Now()
	for _, ps := range pm.pollers {
		ps.mu.RLock()
		timeSinceLastRun := now.Sub(ps.LastRunTime).Seconds()
		// Consider unhealthy if no run for 5x the normal interval
		maxExpectedTime := ps.Interval.Seconds() * 5
		if timeSinceLastRun > maxExpectedTime {
			ps.mu.RUnlock()
			return false
		}
		ps.mu.RUnlock()
	}

	return true
}
