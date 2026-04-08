package config

import (
	"testing"
)

// TestDefaultConfig verifies default configuration is valid
func TestDefaultConfig(t *testing.T) {
	cfg := NewDefaultConfig()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Default config should be valid: %v", err)
	}

	if cfg.Monitoring.AuthLogPath == "" {
		t.Error("AuthLogPath should have default value")
	}

	if cfg.Performance.MaxMonitorGoroutines <= 0 {
		t.Error("MaxMonitorGoroutines should be positive")
	}
}

// TestConfigValidation verifies config validation works
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*Config)
		wantErr bool
	}{
		{
			name: "valid config",
			setup: func(c *Config) {
				// Keep defaults
			},
			wantErr: false,
		},
		{
			name: "empty auth log path",
			setup: func(c *Config) {
				c.Monitoring.AuthLogPath = ""
			},
			wantErr: true,
		},
		{
			name: "invalid command timeout",
			setup: func(c *Config) {
				c.Security.CommandTimeoutSec = 0
			},
			wantErr: true,
		},
		{
			name: "invalid max goroutines",
			setup: func(c *Config) {
				c.Performance.MaxMonitorGoroutines = -1
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := NewDefaultConfig()
			tc.setup(cfg)

			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validation error mismatch: got %v, want error: %v", err, tc.wantErr)
			}
		})
	}
}

// TestConfigEnvironmentOverrides verifies environment variables override defaults
func TestConfigEnvironmentOverrides(t *testing.T) {
	t.Setenv("SFTP_EXPORTER_LISTEN_ADDRESS", ":8080")
	t.Setenv("SFTP_EXPORTER_LOG_LEVEL", "debug")

	cfg := NewDefaultConfig()
	if err := cfg.LoadFromEnv(); err != nil {
		t.Fatalf("Failed to load config from env: %v", err)
	}

	if cfg.Web.ListenAddress != ":8080" {
		t.Errorf("Listen address not overridden: %s", cfg.Web.ListenAddress)
	}

	if cfg.Logging.Level != "DEBUG" {
		t.Errorf("Log level not overridden: %s", cfg.Logging.Level)
	}
}
