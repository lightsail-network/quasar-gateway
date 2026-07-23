package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfigFile(t *testing.T, data string) string {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "test_config.toml")
	if err := os.WriteFile(configPath, []byte(data), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}
	return configPath
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		configData  string
		expectError string // substring of the expected error, "" = no error
		check       func(t *testing.T, c *Config)
	}{
		{
			name: "valid config with auth",
			configData: `
[server]
host = "localhost"
port = 8081

[rpc]
url = "http://localhost:8080"

[auth]
service_url = "https://auth.example.com"
service_token = "test-token"
cache_expiration = 300
http_timeout = 5
`,
			check: func(t *testing.T, c *Config) {
				if c.Server.Host != "localhost" {
					t.Errorf("Expected server host localhost, got %s", c.Server.Host)
				}
				if c.Server.Port != 8081 {
					t.Errorf("Expected server port 8081, got %d", c.Server.Port)
				}
				if c.RPC.URL != "http://localhost:8080" {
					t.Errorf("Expected RPC URL http://localhost:8080, got %s", c.RPC.URL)
				}
				if c.Auth.ServiceURL != "https://auth.example.com" {
					t.Errorf("Expected auth service URL https://auth.example.com, got %s", c.Auth.ServiceURL)
				}
				if c.Auth.ServiceToken != "test-token" {
					t.Errorf("Expected auth service token test-token, got %s", c.Auth.ServiceToken)
				}
				// Defaults must have been applied.
				if c.Server.Type != GatewayTypeRPC {
					t.Errorf("Expected default type rpc, got %s", c.Server.Type)
				}
				if c.Server.HealthPort != 8082 {
					t.Errorf("Expected default health port 8082, got %d", c.Server.HealthPort)
				}
				if c.Auth.CacheSize != 10000 {
					t.Errorf("Expected default cache size 10000, got %d", c.Auth.CacheSize)
				}
			},
		},
		{
			name: "invalid toml",
			configData: `
[server
host = "localhost"
port = 8081
`,
			expectError: "error decoding config file",
		},
		{
			name: "missing rpc url",
			configData: `
[server]
host = "localhost"
port = 8081

[auth]
service_url = "https://auth.example.com"
`,
			expectError: "rpc.url is required",
		},
		{
			name: "missing auth service url",
			configData: `
[server]
host = "0.0.0.0"
port = 3000

[rpc]
url = "http://example.com"
`,
			expectError: "auth.service_url is required",
		},
		{
			name: "auth disabled needs no auth service",
			configData: `
[server]
host = "0.0.0.0"
port = 3000

[rpc]
url = "http://example.com"

[auth]
enabled = false
`,
			check: func(t *testing.T, c *Config) {
				if c.AuthEnabled() {
					t.Errorf("Expected auth to be disabled")
				}
			},
		},
		{
			name: "auth explicitly enabled still requires service url",
			configData: `
[server]
host = "0.0.0.0"
port = 3000

[rpc]
url = "http://example.com"

[auth]
enabled = true
`,
			expectError: "auth.service_url is required",
		},
		{
			name: "valid http config",
			configData: `
[server]
type = "http"

[http]
url = "http://wallet-backend:8003"

[auth]
enabled = false
`,
			check: func(t *testing.T, c *Config) {
				if c.HTTP.URL != "http://wallet-backend:8003" {
					t.Errorf("Expected http URL http://wallet-backend:8003, got %s", c.HTTP.URL)
				}
				if c.HTTP.HealthPath != "/health" {
					t.Errorf("Expected default health path /health, got %s", c.HTTP.HealthPath)
				}
			},
		},
		{
			name: "http type missing url",
			configData: `
[server]
type = "http"

[auth]
enabled = false
`,
			expectError: "http.url is required",
		},
		{
			name: "s3 type missing bucket",
			configData: `
[server]
type = "s3"

[auth]
service_url = "https://auth.example.com"
`,
			expectError: "s3.bucket is required",
		},
		{
			name: "s3 type missing credentials",
			configData: `
[server]
type = "s3"

[s3]
bucket = "my-bucket"

[auth]
service_url = "https://auth.example.com"
`,
			expectError: "s3.access_key_id and s3.secret_key are required",
		},
		{
			name: "unsupported type",
			configData: `
[server]
type = "ftp"

[auth]
service_url = "https://auth.example.com"
`,
			expectError: "unsupported gateway type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := LoadConfig(writeConfigFile(t, tt.configData))

			if tt.expectError != "" {
				if err == nil {
					t.Fatalf("Expected error containing %q, but got none", tt.expectError)
				}
				if !strings.Contains(err.Error(), tt.expectError) {
					t.Errorf("Expected error containing %q, got %q", tt.expectError, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if config == nil {
				t.Fatalf("Expected config, but got nil")
			}
			tt.check(t, config)
		})
	}
}

// One shared config file with full auth settings can serve both a pro
// (authenticated) and a free (open) gateway instance: the free instance just
// sets QUASAR_AUTH_ENABLED=false, which wins over the file.
func TestLoadConfig_SharedFileEnvDisablesAuth(t *testing.T) {
	configData := `
[server]
host = "0.0.0.0"
port = 8080

[rpc]
url = "http://rpc:8000"

[auth]
service_url = "https://auth.example.com"
service_token = "pro-token"
`
	t.Setenv("QUASAR_AUTH_ENABLED", "false")

	config, err := LoadConfig(writeConfigFile(t, configData))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if config.AuthEnabled() {
		t.Errorf("Expected env override to disable auth over the shared file")
	}
	// File values are still loaded, just ignored in open mode.
	if config.Auth.ServiceURL != "https://auth.example.com" {
		t.Errorf("Expected file auth values to remain readable, got %q", config.Auth.ServiceURL)
	}
}

func TestLoadConfigNonExistentFile(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.toml")
	if err == nil {
		t.Errorf("Expected error for non-existent file, but got none")
	}
}

func TestApplyDefaults(t *testing.T) {
	c := &Config{}
	c.ApplyDefaults()

	if !c.AuthEnabled() {
		t.Errorf("Expected auth enabled by default")
	}
	if c.Auth.Enabled == nil || !*c.Auth.Enabled {
		t.Errorf("Expected ApplyDefaults to materialize auth.enabled = true, got %v", c.Auth.Enabled)
	}
	if c.Server.Type != GatewayTypeRPC {
		t.Errorf("Expected default type rpc, got %s", c.Server.Type)
	}
	if c.Server.Port != 8080 {
		t.Errorf("Expected default port 8080, got %d", c.Server.Port)
	}
	if c.Server.HealthPort != 8081 {
		t.Errorf("Expected default health port 8081, got %d", c.Server.HealthPort)
	}
	if c.Server.GracefulShutdownSec != 30 {
		t.Errorf("Expected default graceful shutdown 30, got %d", c.Server.GracefulShutdownSec)
	}
	if c.Auth.CacheExpiration != 300 {
		t.Errorf("Expected default cache expiration 300, got %d", c.Auth.CacheExpiration)
	}
	if c.Auth.HTTPTimeout != 5 {
		t.Errorf("Expected default HTTP timeout 5, got %d", c.Auth.HTTPTimeout)
	}
	if c.Auth.CacheSize != 10000 {
		t.Errorf("Expected default cache size 10000, got %d", c.Auth.CacheSize)
	}
}

func TestApplyDefaults_HealthPortFollowsPort(t *testing.T) {
	c := &Config{Server: ServerConfig{Port: 9000}}
	c.ApplyDefaults()

	if c.Server.HealthPort != 9001 {
		t.Errorf("Expected health port 9001, got %d", c.Server.HealthPort)
	}
}

func TestApplyDefaults_KeepsExplicitValues(t *testing.T) {
	c := &Config{
		Server: ServerConfig{Type: GatewayTypeS3, Port: 9000, HealthPort: 9100, GracefulShutdownSec: 5},
		Auth:   AuthConfig{CacheExpiration: 60, HTTPTimeout: 2, CacheSize: 100},
	}
	c.ApplyDefaults()

	if c.Server.Type != GatewayTypeS3 || c.Server.Port != 9000 || c.Server.HealthPort != 9100 || c.Server.GracefulShutdownSec != 5 {
		t.Errorf("Explicit server values were overwritten: %+v", c.Server)
	}
	if c.Auth.CacheExpiration != 60 || c.Auth.HTTPTimeout != 2 || c.Auth.CacheSize != 100 {
		t.Errorf("Explicit auth values were overwritten: %+v", c.Auth)
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	c := &Config{
		Server: ServerConfig{Host: "default-host", Port: 8080},
		RPC:    RPCConfig{URL: "http://default.com"},
		Auth:   AuthConfig{ServiceURL: "http://auth-default.com", FailOpen: true},
	}

	t.Setenv("QUASAR_SERVER_HOST", "env-host")
	t.Setenv("QUASAR_SERVER_PORT", "9090")
	t.Setenv("QUASAR_RPC_URL", "http://env-rpc.com")
	t.Setenv("QUASAR_HTTP_URL", "http://env-http.com")
	t.Setenv("QUASAR_HTTP_HEALTH_PATH", "/env-health")
	t.Setenv("QUASAR_AUTH_ENABLED", "false")
	t.Setenv("QUASAR_AUTH_SERVICE_URL", "http://env-auth.com")
	t.Setenv("QUASAR_AUTH_FAIL_OPEN", "false")

	if err := c.ApplyEnvOverrides(); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if c.Server.Host != "env-host" {
		t.Errorf("Expected host env-host, got %s", c.Server.Host)
	}
	if c.Server.Port != 9090 {
		t.Errorf("Expected port 9090, got %d", c.Server.Port)
	}
	if c.RPC.URL != "http://env-rpc.com" {
		t.Errorf("Expected RPC URL http://env-rpc.com, got %s", c.RPC.URL)
	}
	if c.Auth.ServiceURL != "http://env-auth.com" {
		t.Errorf("Expected auth URL http://env-auth.com, got %s", c.Auth.ServiceURL)
	}
	if c.Auth.FailOpen {
		t.Errorf("Expected fail_open false")
	}
	if c.AuthEnabled() {
		t.Errorf("Expected auth disabled via QUASAR_AUTH_ENABLED=false")
	}
	if c.HTTP.URL != "http://env-http.com" {
		t.Errorf("Expected HTTP URL http://env-http.com, got %s", c.HTTP.URL)
	}
	if c.HTTP.HealthPath != "/env-health" {
		t.Errorf("Expected HTTP health path /env-health, got %s", c.HTTP.HealthPath)
	}
}

func TestApplyEnvOverrides_UnsetKeepsValues(t *testing.T) {
	c := &Config{Server: ServerConfig{Host: "keep-me", Port: 1234}}

	if err := c.ApplyEnvOverrides(); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if c.Server.Host != "keep-me" || c.Server.Port != 1234 {
		t.Errorf("Values changed without env overrides: %+v", c.Server)
	}
}

func TestApplyEnvOverrides_InvalidInt(t *testing.T) {
	c := &Config{}
	t.Setenv("QUASAR_SERVER_PORT", "not-a-number")

	err := c.ApplyEnvOverrides()
	if err == nil {
		t.Fatalf("Expected error for invalid integer, but got none")
	}
	if !strings.Contains(err.Error(), "QUASAR_SERVER_PORT") {
		t.Errorf("Expected error to name the variable, got %q", err.Error())
	}
}

func TestApplyEnvOverrides_InvalidBool(t *testing.T) {
	c := &Config{}
	t.Setenv("QUASAR_AUTH_FAIL_OPEN", "maybe")

	err := c.ApplyEnvOverrides()
	if err == nil {
		t.Fatalf("Expected error for invalid boolean, but got none")
	}
	if !strings.Contains(err.Error(), "QUASAR_AUTH_FAIL_OPEN") {
		t.Errorf("Expected error to name the variable, got %q", err.Error())
	}
}

func TestEnvUsage_CoversAllOverrides(t *testing.T) {
	usage := EnvUsage()
	for _, e := range envOverrides {
		if !strings.Contains(usage, e.name) {
			t.Errorf("EnvUsage is missing %s", e.name)
		}
	}
	if !strings.Contains(usage, "QUASAR_CONFIG_PATH") {
		t.Errorf("EnvUsage is missing QUASAR_CONFIG_PATH")
	}
}
