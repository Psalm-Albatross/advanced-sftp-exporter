package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config represents the exporter configuration
type Config struct {
	// Monitoring settings
	Monitoring MonitoringConfig `yaml:"monitoring"`

	// Security settings
	Security SecurityConfig `yaml:"security"`

	// Performance settings
	Performance PerformanceConfig `yaml:"performance"`

	// Web settings
	Web WebConfig `yaml:"web"`

	// Logging settings
	Logging LoggingConfig `yaml:"logging"`
}

// MonitoringConfig holds monitoring-related settings
type MonitoringConfig struct {
	AuthLogPath        string `yaml:"auth-log-path"`
	HomeBasePath       string `yaml:"home-base-path"`
	HomeGlob           string `yaml:"home-glob"`
	HomeRegex          string `yaml:"home-regex"`
	UserRegex          string `yaml:"user-regex"`
	UploadMarkerSuffix string `yaml:"upload-marker-suffix"`
	DownloadMarkerSuffix string `yaml:"download-marker-suffix"`
	IdleThresholdSec   int    `yaml:"idle-threshold-seconds"`
	EnableStrictMode   bool   `yaml:"enable-strict-mode"`
}

// SecurityConfig holds security-related settings
type SecurityConfig struct {
	AllowedCommands     []string `yaml:"allowed-commands"`
	CommandTimeoutSec   int      `yaml:"command-timeout-seconds"`
	EnablePathValidation bool    `yaml:"enable-path-validation"`
	PathValidationBase  string   `yaml:"path-validation-base"`
}

// PerformanceConfig holds performance-related settings
type PerformanceConfig struct {
	MaxMonitorGoroutines int `yaml:"max-monitor-goroutines"`
	EnableAdaptivePolling bool `yaml:"enable-adaptive-polling"`
	PollingBackoffMax     int `yaml:"polling-backoff-max-seconds"`
	EnableCaching         bool `yaml:"enable-caching"`
	CacheTTLSec           int `yaml:"cache-ttl-seconds"`
}

// WebConfig holds web/HTTP settings
type WebConfig struct {
	ListenAddress  string `yaml:"listen-address"`
	EnableTLS      bool   `yaml:"enable-tls"`
	TLSCertPath    string `yaml:"tls-cert-path"`
	TLSKeyPath     string `yaml:"tls-key-path"`
	BearerToken    string `yaml:"bearer-token"`
	RateLimitReqSec int   `yaml:"rate-limit-req-sec"`
}

// LoggingConfig holds logging-related settings
type LoggingConfig struct {
	Level     string `yaml:"level"`
	JSONMode  bool   `yaml:"json-mode"`
	Component string `yaml:"component"`
}

// NewDefaultConfig returns a configuration with sensible defaults
func NewDefaultConfig() *Config {
	return &Config{
		Monitoring: MonitoringConfig{
			AuthLogPath:        "/var/log/auth.log",
			HomeBasePath:       "/home",
			HomeGlob:           "/home/*",
			UploadMarkerSuffix: ".uploaded",
			DownloadMarkerSuffix: ".downloaded",
			IdleThresholdSec:   300,
			EnableStrictMode:   false,
		},
		Security: SecurityConfig{
			CommandTimeoutSec:    5,
			EnablePathValidation: true,
			PathValidationBase:   "/",
		},
		Performance: PerformanceConfig{
			MaxMonitorGoroutines: 10,
			EnableAdaptivePolling: true,
			PollingBackoffMax:    60,
			EnableCaching:        true,
			CacheTTLSec:          3600,
		},
		Web: WebConfig{
			ListenAddress:   ":1210",
			EnableTLS:       false,
			RateLimitReqSec: 100,
		},
		Logging: LoggingConfig{
			Level:    "INFO",
			JSONMode: false,
		},
	}
}

// LoadFromEnv updates config from environment variables
func (c *Config) LoadFromEnv() error {
	// Monitoring
	if val := os.Getenv("SFTP_EXPORTER_AUTH_LOG"); val != "" {
		c.Monitoring.AuthLogPath = val
	}
	if val := os.Getenv("SFTP_EXPORTER_HOME_BASE"); val != "" {
		c.Monitoring.HomeBasePath = val
	}
	if val := os.Getenv("SFTP_EXPORTER_USER_REGEX"); val != "" {
		c.Monitoring.UserRegex = val
	}
	if val := os.Getenv("SFTP_EXPORTER_STRICT_MODE"); val != "" {
		c.Monitoring.EnableStrictMode = val == "true" || val == "1"
	}

	// Security
	if val := os.Getenv("SFTP_EXPORTER_COMMAND_TIMEOUT"); val != "" {
		timeout, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("invalid SFTP_EXPORTER_COMMAND_TIMEOUT: %w", err)
		}
		c.Security.CommandTimeoutSec = timeout
	}

	// Performance
	if val := os.Getenv("SFTP_EXPORTER_MAX_GOROUTINES"); val != "" {
		max, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("invalid SFTP_EXPORTER_MAX_GOROUTINES: %w", err)
		}
		c.Performance.MaxMonitorGoroutines = max
	}

	// Web
	if val := os.Getenv("SFTP_EXPORTER_LISTEN_ADDRESS"); val != "" {
		c.Web.ListenAddress = val
	}
	if val := os.Getenv("SFTP_EXPORTER_BEARER_TOKEN"); val != "" {
		c.Web.BearerToken = val
	}

	// Logging
	if val := os.Getenv("SFTP_EXPORTER_LOG_LEVEL"); val != "" {
		c.Logging.Level = strings.ToUpper(val)
	}
	if val := os.Getenv("SFTP_EXPORTER_LOG_JSON"); val != "" {
		c.Logging.JSONMode = val == "true" || val == "1"
	}

	return nil
}

// Validate checks configuration validity
func (c *Config) Validate() error {
	// Validate monitoring
	if c.Monitoring.AuthLogPath == "" {
		return fmt.Errorf("auth_log_path cannot be empty")
	}
	if c.Monitoring.HomeBasePath == "" {
		return fmt.Errorf("home_base_path cannot be empty")
	}
	if c.Monitoring.IdleThresholdSec < 0 {
		return fmt.Errorf("idle_threshold_sec must be non-negative")
	}

	// Validate security
	if c.Security.CommandTimeoutSec <= 0 {
		return fmt.Errorf("command_timeout_sec must be positive")
	}

	// Validate performance
	if c.Performance.MaxMonitorGoroutines <= 0 {
		return fmt.Errorf("max_monitor_goroutines must be positive")
	}
	if c.Performance.CacheTTLSec < 0 {
		return fmt.Errorf("cache_ttl_sec must be non-negative")
	}

	// Validate web
	if c.Web.ListenAddress == "" {
		return fmt.Errorf("listen_address cannot be empty")
	}
	if c.Web.EnableTLS && c.Web.TLSCertPath == "" {
		return fmt.Errorf("tls_cert_path required when enable_tls is true")
	}

	// Validate logging
	level := strings.ToUpper(c.Logging.Level)
	if level != "DEBUG" && level != "INFO" && level != "WARN" && level != "ERROR" {
		return fmt.Errorf("invalid log level: %s", c.Logging.Level)
	}

	return nil
}

// SetTLS sets TLS configuration
func (c *Config) SetTLS(enable bool, certPath, keyPath string) {
	c.Web.EnableTLS = enable
	c.Web.TLSCertPath = certPath
	c.Web.TLSKeyPath = keyPath
}
