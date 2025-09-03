package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		configData  string
		expectError bool
		expected    *Config
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
			expectError: false,
			expected: &Config{
				Server: ServerConfig{
					Host: "localhost",
					Port: 8081,
				},
				RPC: RPCConfig{
					URL: "http://localhost:8080",
				},
				Auth: AuthConfig{
					ServiceURL:      "https://auth.example.com",
					ServiceToken:    "test-token",
					CacheExpiration: 300,
					HTTPTimeout:     5,
				},
			},
		},
		{
			name: "minimal config",
			configData: `
[server]
host = "0.0.0.0"
port = 3000

[rpc]
url = "http://example.com"
`,
			expectError: false,
			expected: &Config{
				Server: ServerConfig{
					Host: "0.0.0.0",
					Port: 3000,
				},
				RPC: RPCConfig{
					URL: "http://example.com",
				},
				Auth: AuthConfig{},
			},
		},
		{
			name: "invalid toml",
			configData: `
[server
host = "localhost"
port = 8081
`,
			expectError: true,
			expected:    nil,
		},
		{
			name: "missing sections",
			configData: `
[server]
host = "localhost"
port = 8081
`,
			expectError: false,
			expected: &Config{
				Server: ServerConfig{
					Host: "localhost",
					Port: 8081,
				},
				RPC:  RPCConfig{},
				Auth: AuthConfig{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "config_test")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			configPath := filepath.Join(tmpDir, "test_config.toml")
			err = os.WriteFile(configPath, []byte(tt.configData), 0644)
			if err != nil {
				t.Fatalf("Failed to write config file: %v", err)
			}

			config, err := LoadConfig(configPath)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error, but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if config == nil {
				t.Errorf("Expected config, but got nil")
				return
			}

			if config.Server.Host != tt.expected.Server.Host {
				t.Errorf("Expected server host %s, got %s", tt.expected.Server.Host, config.Server.Host)
			}

			if config.Server.Port != tt.expected.Server.Port {
				t.Errorf("Expected server port %d, got %d", tt.expected.Server.Port, config.Server.Port)
			}

			if config.RPC.URL != tt.expected.RPC.URL {
				t.Errorf("Expected RPC URL %s, got %s", tt.expected.RPC.URL, config.RPC.URL)
			}

			if config.Auth.ServiceURL != tt.expected.Auth.ServiceURL {
				t.Errorf("Expected Auth service URL %s, got %s", tt.expected.Auth.ServiceURL, config.Auth.ServiceURL)
			}

			if config.Auth.ServiceToken != tt.expected.Auth.ServiceToken {
				t.Errorf("Expected Auth service token %s, got %s", tt.expected.Auth.ServiceToken, config.Auth.ServiceToken)
			}

			if config.Auth.CacheExpiration != tt.expected.Auth.CacheExpiration {
				t.Errorf("Expected Auth cache expiration %d, got %d", tt.expected.Auth.CacheExpiration, config.Auth.CacheExpiration)
			}

			if config.Auth.HTTPTimeout != tt.expected.Auth.HTTPTimeout {
				t.Errorf("Expected Auth HTTP timeout %d, got %d", tt.expected.Auth.HTTPTimeout, config.Auth.HTTPTimeout)
			}
		})
	}
}

func TestLoadConfigNonExistentFile(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.toml")
	if err == nil {
		t.Errorf("Expected error for non-existent file, but got none")
	}
}
