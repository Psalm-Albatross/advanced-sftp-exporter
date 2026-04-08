package safety

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ExecSafeConfig holds configuration for safe command execution
type ExecSafeConfig struct {
	Timeout         time.Duration
	MaxOutput       int64 // Max bytes to capture
	EnforceTimeout  bool  // Kill process if timeout exceeded
	LogStderr       bool
	AllowedCommands map[string]bool // Whitelist of allowed commands
}

// DefaultConfig returns a safe default configuration
func DefaultConfig() ExecSafeConfig {
	return ExecSafeConfig{
		Timeout:        5 * time.Second,
		MaxOutput:      10 * 1024 * 1024, // 10MB
		EnforceTimeout: true,
		LogStderr:      true,
		AllowedCommands: map[string]bool{
			"ps":       true,
			"pgrep":    true,
			"lsof":     true,
			"file":     true,
			"stat":     true,
			"getcwd":   true,
			"getconf":  true,
			"systemctl": true,
		},
	}
}

var (
	ErrCommandTimeout   = errors.New("command execution timeout")
	ErrCommandBlocked   = errors.New("command not in whitelist")
	ErrOutputTooLarge   = errors.New("command output exceeded max size")
	ErrCommandNotFound  = errors.New("command not found")
)

// ExecuteCommand safely executes a command with timeout and resource limits
func ExecuteCommand(ctx context.Context, config ExecSafeConfig, name string, args ...string) (string, error) {
	// Validate command is in whitelist
	if config.AllowedCommands != nil && !config.AllowedCommands[name] {
		return "", fmt.Errorf("%w: %s", ErrCommandBlocked, name)
	}

	// Check command exists
	if _, err := exec.LookPath(name); err != nil {
		return "", fmt.Errorf("%w: %s", ErrCommandNotFound, name)
	}

	// Apply timeout
	if config.Timeout > 0 && ctx == context.Background() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, config.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, name, args...)
	
	// Capture output
	output, err := cmd.Output()
	
	// Check for timeout
	if ctx.Err() == context.DeadlineExceeded {
		// Try to kill process if still running
		if cmd.Process != nil && config.EnforceTimeout {
			_ = cmd.Process.Kill()
		}
		return "", ErrCommandTimeout
	}

	// Check output size
	if int64(len(output)) > config.MaxOutput {
		return "", fmt.Errorf("%w: got %d bytes", ErrOutputTooLarge, len(output))
	}

	if err != nil {
		return "", fmt.Errorf("command failed: %w", err)
	}

	return string(output), nil
}

// ValidatePath ensures a path is within an allowed base directory and safe from traversal
func ValidatePath(path, baseDir string) error {
	// Ensure baseDir exists and is readable
	baseStat, err := os.Stat(baseDir)
	if err != nil {
		return fmt.Errorf("base directory check failed: %w", err)
	}
	if !baseStat.IsDir() {
		return fmt.Errorf("base path is not a directory: %s", baseDir)
	}

	// Resolve symlinks and clean path
	absPath := path
	if !filepath.IsAbs(path) {
		absPath = filepath.Join(baseDir, path)
	}

	// Resolve symlinks to detect traversal
	resolvedPath, err := filepath.EvalSymlinks(absPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("path resolution failed: %w", err)
	}

	// If EvalSymlinks succeeded, use resolved path for relative check
	if err == nil {
		absPath = resolvedPath
	} else {
		// For non-existent paths, at least normalize the path
		absPath, _ = filepath.Abs(absPath)
	}

	// Ensure path is within baseDir
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("base directory resolution failed: %w", err)
	}

	rel, err := filepath.Rel(absBase, absPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("path traversal attempt detected: %s is outside %s", path, baseDir)
	}

	return nil
}

// ValidateRegex checks if a regex pattern is safe (not ReDoS prone)
// Simple heuristic: disallow very long patterns and excessive quantifiers
func ValidateRegex(pattern string) error {
	if len(pattern) > 1000 {
		return errors.New("regex pattern too long (max 1000 chars)")
	}

	// Check for excessive quantifiers (***+, {1,1000}, etc)
	if matched, _ := regexp.MatchString(`\{\d{3,}\}|\*{2,}|\+{2,}`, pattern); matched {
		return errors.New("regex pattern contains excessive quantifiers, possible ReDoS")
	}

	// Try to compile - will catch invalid patterns
	_, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %w", err)
	}

	return nil
}

// SanitizeLabel removes or escapes potentially problematic label values
// Prometheus label values can contain any UTF-8, but we want to be careful about
// untrusted input from log files or command output
func SanitizeLabel(s string, maxLen int) string {
	// Truncate if too long
	if len(s) > maxLen {
		s = s[:maxLen]
	}

	// Replace common problematic characters with underscore
	replacer := strings.NewReplacer(
		"\n", "_",
		"\r", "_",
		"\x00", "_",
		"\"", "_",
		"\\", "_",
	)
	return replacer.Replace(s)
}

// ValidateIPAddress does basic IP validation (IPv4 + IPv6)
func ValidateIPAddress(ip string) bool {
	// Simple IPv4 check: 4 octets 0-255
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		for _, part := range parts {
			var num int
			if _, err := fmt.Sscanf(part, "%d", &num); err != nil || num < 0 || num > 255 {
				return false
			}
		}
		return true
	}

	// IPv6 basic check (just ensure it contains colons and hex)
	if strings.Contains(ip, ":") {
		return true // Simplified - real validation would be more thorough
	}

	return false
}
