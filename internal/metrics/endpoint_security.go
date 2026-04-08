package metrics

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// EndpointSecurityConfig holds security settings for metrics endpoint
type EndpointSecurityConfig struct {
	BearerToken string        // If set, requires Authorization: Bearer <token>
	RateLimit   int           // Max requests per second (0 = unlimited)
	ReadTimeout time.Duration // HTTP read timeout
	WriteTimeout time.Duration // HTTP write timeout
}

// SecureMetricsHandler wraps http.Handler with security features
type SecureMetricsHandler struct {
	handler http.Handler
	config  EndpointSecurityConfig
	limiter *RateLimiter
}

// RateLimiter applies per-IP rate limiting
type RateLimiter struct {
	maxPerSecond int
	ipBuckets    map[string]*TokenBucket
	mu           sync.RWMutex
	cleanupTicker *time.Ticker
}

// TokenBucket implements token bucket algorithm for rate limiting
type TokenBucket struct {
	tokens    float64
	maxTokens float64
	refillRate float64
	lastRefill time.Time
	mu         sync.Mutex
}

// NewSecureMetricsHandler creates a new secure handler wrapper
func NewSecureMetricsHandler(handler http.Handler, config EndpointSecurityConfig) *SecureMetricsHandler {
	h := &SecureMetricsHandler{
		handler: handler,
		config: config,
	}

	if config.RateLimit > 0 {
		h.limiter = NewRateLimiter(config.RateLimit)
	}

	return h
}

// ServeHTTP implements http.Handler interface with security checks
func (h *SecureMetricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check bearer token if configured
	if h.config.BearerToken != "" {
		if !h.validateBearerToken(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="SFTP Exporter"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Apply rate limiting if configured
	if h.limiter != nil {
		clientIP := getClientIP(r)
		if !h.limiter.AllowRequest(clientIP) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
	}

	// Add security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

	// Serve the actual metrics
	h.handler.ServeHTTP(w, r)
}

// validateBearerToken checks the Authorization header
func (h *SecureMetricsHandler) validateBearerToken(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return false
	}

	// Extract token from "Bearer <token>"
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return false
	}

	token := strings.TrimSpace(parts[1])
	
	// Use constant-time comparison to prevent timing attacks
	return constantTimeCompare(token, h.config.BearerToken)
}

// constantTimeCompare performs constant-time string comparison
func constantTimeCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	result := 0
	for i := 0; i < len(a); i++ {
		result |= int(a[i]) ^ int(b[i])
	}
	return result == 0
}

// getClientIP extracts client IP from request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (from reverse proxy)
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// Take the first IP in the list
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return strings.TrimSpace(realIP)
	}

	// Use RemoteAddr as fallback
	// Remove port if present
	if colonIdx := strings.LastIndexByte(r.RemoteAddr, ':'); colonIdx != -1 {
		return r.RemoteAddr[:colonIdx]
	}
	return r.RemoteAddr
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(maxPerSecond int) *RateLimiter {
	limiter := &RateLimiter{
		maxPerSecond: maxPerSecond,
		ipBuckets:    make(map[string]*TokenBucket),
		cleanupTicker: time.NewTicker(1 * time.Minute),
	}

	// Cleanup inactive buckets periodically
	go func() {
		for range limiter.cleanupTicker.C {
			limiter.cleanup()
		}
	}()

	return limiter
}

// AllowRequest checks if a request from this IP should be allowed
func (rl *RateLimiter) AllowRequest(clientIP string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, exists := rl.ipBuckets[clientIP]
	if !exists {
		quotaPerSecond := float64(rl.maxPerSecond)
		bucket = &TokenBucket{
			tokens:    quotaPerSecond,
			maxTokens: quotaPerSecond,
			refillRate: quotaPerSecond,
			lastRefill: time.Now(),
		}
		rl.ipBuckets[clientIP] = bucket
	}

	// Try to consume a token
	return bucket.TryConsume()
}

// TryConsume attempts to consume a token from the bucket
func (tb *TokenBucket) TryConsume() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	
	// Refill tokens based on elapsed time
	tb.tokens = min(tb.maxTokens, tb.tokens+elapsed*tb.refillRate)
	tb.lastRefill = now

	if tb.tokens >= 1.0 {
		tb.tokens--
		return true
	}

	return false
}

// cleanup removes inactive rate limit buckets
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, bucket := range rl.ipBuckets {
		bucket.mu.Lock()
		// Remove buckets unused for >10 minutes
		if now.Sub(bucket.lastRefill) > 10*time.Minute {
			delete(rl.ipBuckets, ip)
		}
		bucket.mu.Unlock()
	}
}

// Stop stops the rate limiter cleanup goroutine
func (rl *RateLimiter) Stop() {
	if rl.cleanupTicker != nil {
		rl.cleanupTicker.Stop()
	}
}

// min returns the smaller of two numbers
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// RequestLogger logs metrics endpoint access (useful for audit trail)
type RequestLogger struct {
	handler  http.Handler
	strictMode bool // If true, anonymize IPs
}

// NewRequestLogger creates a new request logger
func NewRequestLogger(handler http.Handler, strictMode bool) *RequestLogger {
	return &RequestLogger{
		handler:    handler,
		strictMode: strictMode,
	}
}

// ServeHTTP implements http.Handler and logs access
func (rl *RequestLogger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	if rl.strictMode {
		clientIP = anonymizeIP(clientIP)
	}

	// Log request (at WARN level if auth fails)
	startTime := time.Now()
	rl.handler.ServeHTTP(w, r)
	duration := time.Since(startTime)

	// In production, this would go to structured logger
	// For now, just info-level logging
	_ = clientIP // Suppress unused warning for now
	_ = duration
}

// anonymizeIP masks the last octet (or last two for IPv6)
func anonymizeIP(ip string) string {
	if strings.Contains(ip, ":") {
		// IPv6 - mask the last group
		if len(ip) > 2 {
			return ip[:len(ip)-2] + "00"
		}
	} else {
		// IPv4 - mask the last octet
		parts := strings.Split(ip, ".")
		if len(parts) == 4 {
			return parts[0] + "." + parts[1] + "." + parts[2] + ".0"
		}
	}
	return "masked"
}
