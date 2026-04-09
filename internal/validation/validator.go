package validation

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// ConfigValidator holds configuration parameters for validation
type ConfigValidator struct {
	MinUID            int
	MaxMemoryThreshold int64
	MaxIdleThreshold  int
	MaxRegexPatternLen int
}

// DefaultValidator returns a validator with safe defaults
func DefaultValidator() ConfigValidator {
	return ConfigValidator{
		MinUID:             1000,
		MaxMemoryThreshold: 10 * 1024 * 1024 * 1024, // 10GB
		MaxIdleThreshold:   86400,                   // 24 hours
		MaxRegexPatternLen: 1000,
	}
}

// ValidateAuthLogPath checks if auth log path is valid and readable
func (cv ConfigValidator) ValidateAuthLogPath(path string) error {
	if path == "" {
		return errors.New("auth log path cannot be empty")
	}

	// Check if file exists
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("auth log path check failed: %w", err)
	}

	// Check if it's a regular file or device (log files may be on special devices)
	if info.IsDir() {
		return fmt.Errorf("auth log path is a directory, not a file: %s", path)
	}

	// Check if readable
	if err := hasReadPermission(path); err != nil {
		return fmt.Errorf("auth log path not readable: %w", err)
	}

	return nil
}

// ValidateHomeBasePath validates the home base directory
func (cv ConfigValidator) ValidateHomeBasePath(path string) error {
	if path == "" {
		return errors.New("home base path cannot be empty")
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("home base path check failed: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("home base path is not a directory: %s", path)
	}

	return nil
}

// ValidateSSHDConfigPath validates the sshd config path
func (cv ConfigValidator) ValidateSSHDConfigPath(path string) error {
	if path == "" {
		return errors.New("sshd config path cannot be empty")
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("sshd config path check failed: %w", err)
	}

	if info.IsDir() {
		return fmt.Errorf("sshd config path is a directory, not a file: %s", path)
	}

	if err := hasReadPermission(path); err != nil {
		return fmt.Errorf("sshd config path not readable: %w", err)
	}

	return nil
}

// ValidateMemoryThreshold validates memory thresholds
func (cv ConfigValidator) ValidateMemoryThreshold(threshold int64) error {
	if threshold <= 0 {
		return errors.New("memory threshold must be positive")
	}

	if threshold > cv.MaxMemoryThreshold {
		return fmt.Errorf("memory threshold too large (max: %d bytes)", cv.MaxMemoryThreshold)
	}

	return nil
}

// ValidateIdleThreshold validates idle session threshold
func (cv ConfigValidator) ValidateIdleThreshold(seconds int) error {
	if seconds <= 0 {
		return errors.New("idle threshold must be positive")
	}

	if seconds > cv.MaxIdleThreshold {
		return fmt.Errorf("idle threshold too large (max: %d seconds)", cv.MaxIdleThreshold)
	}

	return nil
}

// ValidateMinUID validates minimum UID
func (cv ConfigValidator) ValidateMinUID(uid int) error {
	if uid < 0 {
		return errors.New("min UID cannot be negative")
	}

	if uid > 65534 {
		return errors.New("min UID unreasonably high (max typical: 65534)")
	}

	return nil
}

// ValidateRegexPattern validates a regex pattern for safety and validity
func (cv ConfigValidator) ValidateRegexPattern(pattern string) error {
	if pattern == "" {
		return nil // Empty pattern is valid (no filtering)
	}

	if len(pattern) > cv.MaxRegexPatternLen {
		return fmt.Errorf("regex pattern too long (max %d chars)", cv.MaxRegexPatternLen)
	}

	// Check for ReDoS-prone patterns: excessive quantifiers
	if matched, _ := regexp.MatchString(`\{\d{3,}\}`, pattern); matched {
		return errors.New("regex pattern contains excessive quantifiers {N,M} with large values: possible ReDoS")
	}

	if matched, _ := regexp.MatchString(`\*{2,}|\+{2,}`, pattern); matched {
		return errors.New("regex pattern contains chained quantifiers (**, ++): possible ReDoS")
	}

	// Try to compile
	if _, err := regexp.Compile(pattern); err != nil {
		return fmt.Errorf("invalid regex pattern: %w", err)
	}

	return nil
}

// ValidateGlobPattern validates a glob pattern
func (cv ConfigValidator) ValidateGlobPattern(pattern string) error {
	if pattern == "" {
		return nil // Empty pattern is valid
	}

	// Check if pattern is absurdly complex
	if len(pattern) > 500 {
		return errors.New("glob pattern too long (max 500 chars)")
	}

	// Try matching against a sample path to catch syntax errors early
	_, err := filepath.Match(pattern, "/home/testuser")
	if err != nil {
		return fmt.Errorf("invalid glob pattern: %w", err)
	}

	return nil
}

// ValidateListenAddress validates a network listen address
func (cv ConfigValidator) ValidateListenAddress(addr string) error {
	if addr == "" {
		return errors.New("listen address cannot be empty")
	}

	// Basic format check
	if len(addr) > 256 {
		return errors.New("listen address too long (max 256 chars)")
	}

	// Check basic format (host:port or :port)
	if addr[0] != ':' {
		// If starts with host, should have colon
		hasColon := false
		for _, c := range addr {
			if c == ':' {
				hasColon = true
				break
			}
		}
		if !hasColon {
			return errors.New("listen address must include port (format: :1210 or host:1210)")
		}
	}

	return nil
}

// ValidateBearerToken validates a bearer token format
func (cv ConfigValidator) ValidateBearerToken(token string) error {
	if token == "" {
		return nil // Empty token is valid (means disabled)
	}

	if len(token) < 16 {
		return errors.New("bearer token too short (min 16 chars)")
	}

	if len(token) > 512 {
		return errors.New("bearer token too long (max 512 chars)")
	}

	return nil
}

// hasReadPermission checks if the current process can read a file
func hasReadPermission(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return nil
}

// ValidateTLSPaths validates TLS certificate and key file paths
func (cv ConfigValidator) ValidateTLSPaths(certPath, keyPath string) error {
	if certPath == "" || keyPath == "" {
		return errors.New("TLS cert and key paths cannot be empty")
	}

	if certPath == keyPath {
		return errors.New("TLS cert and key cannot be the same file")
	}

	// Check cert file
	if _, err := os.Stat(certPath); err != nil {
		return fmt.Errorf("TLS cert file not accessible: %w", err)
	}

	if err := hasReadPermission(certPath); err != nil {
		return fmt.Errorf("TLS cert file not readable: %w", err)
	}

	// Check key file
	if _, err := os.Stat(keyPath); err != nil {
		return fmt.Errorf("TLS key file not accessible: %w", err)
	}

	if err := hasReadPermission(keyPath); err != nil {
		return fmt.Errorf("TLS key file not readable: %w", err)
	}

	return nil
}

// ValidateAllConfig runs comprehensive validation on all config parameters
func (cv ConfigValidator) ValidateAllConfig(params map[string]interface{}) error {
	if params == nil {
		return errors.New("config parameters cannot be nil")
	}

	// Validate each known parameter
	checks := []struct {
		key      string
		value    interface{}
		validate func(interface{}) error
	}{
		{"auth_log", params["auth_log"], func(v interface{}) error {
			if s, ok := v.(string); ok {
				return cv.ValidateAuthLogPath(s)
			}
			return errors.New("auth_log must be a string")
		}},
		{"home_base", params["home_base"], func(v interface{}) error {
			if s, ok := v.(string); ok {
				return cv.ValidateHomeBasePath(s)
			}
			return errors.New("home_base must be a string")
		}},
		{"min_uid", params["min_uid"], func(v interface{}) error {
			if i, ok := v.(int); ok {
				return cv.ValidateMinUID(i)
			}
			return errors.New("min_uid must be an integer")
		}},
	}

	for _, check := range checks {
		if check.value != nil {
			if err := check.validate(check.value); err != nil {
				return fmt.Errorf("validation failed for %s: %w", check.key, err)
			}
		}
	}

	return nil
}
