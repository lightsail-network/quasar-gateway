package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Gateway types selectable via server.type.
const (
	GatewayTypeRPC  = "rpc"
	GatewayTypeS3   = "s3"
	GatewayTypeHTTP = "http"
)

type Config struct {
	Server ServerConfig `toml:"server"`
	RPC    RPCConfig    `toml:"rpc"`
	HTTP   HTTPConfig   `toml:"http"`
	Auth   AuthConfig   `toml:"auth"`
	S3     S3Config     `toml:"s3"`
}

type ServerConfig struct {
	Port                int    `toml:"port"`
	Host                string `toml:"host"`
	HealthPort          int    `toml:"health_port"`           // Port for health check endpoint (default 8081)
	GracefulShutdownSec int    `toml:"graceful_shutdown_sec"` // Time to wait before shutdown (default 30)
	Type                string `toml:"type"`                  // Gateway type: "rpc" or "s3" (default "rpc")
}

type RPCConfig struct {
	URL string `toml:"url"`
}

// HTTPConfig configures a plain-HTTP backend (e.g. wallet-backend): requests
// are proxied as-is and health is a GET on HealthPath expecting a 2xx status.
type HTTPConfig struct {
	URL        string `toml:"url"`
	HealthPath string `toml:"health_path"` // health endpoint path (default "/health")
}

type AuthConfig struct {
	Enabled         *bool  `toml:"enabled"`     // API key authentication (default true); false runs an open gateway
	ServiceURL      string `toml:"service_url"` // Base URL of auth service (e.g., "https://auth.example.com")
	ServiceToken    string `toml:"service_token"`
	CacheExpiration int    `toml:"cache_expiration"` // seconds (default 300 = 5 minutes)
	HTTPTimeout     int    `toml:"http_timeout"`     // seconds (default 5)
	CacheSize       int    `toml:"cache_size"`       // max entries in cache (default 10000)
	FailOpen        bool   `toml:"fail_open"`        // Allow requests when auth service is down (default false)
}

// AuthEnabled reports whether API key authentication is on. Unset means
// enabled: an open gateway must be an explicit choice (`enabled = false`),
// never the result of an omitted line.
func (c *Config) AuthEnabled() bool {
	return c.Auth.Enabled == nil || *c.Auth.Enabled
}

type S3Config struct {
	Endpoint    string `toml:"endpoint"`      // S3 endpoint URL (e.g., "https://s3.amazonaws.com" or "https://account-id.r2.cloudflarestorage.com")
	Region      string `toml:"region"`        // S3 region (e.g., "us-east-1" or "auto" for R2)
	Bucket      string `toml:"bucket"`        // S3 bucket name
	AccessKeyID string `toml:"access_key_id"` // S3 access key ID
	SecretKey   string `toml:"secret_key"`    // S3 secret access key
}

// LoadConfig reads the TOML file at configPath, applies QUASAR_* environment
// overrides and defaults, and validates the result so misconfiguration is
// caught at startup instead of on the first request.
func LoadConfig(configPath string) (*Config, error) {
	var config Config

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file does not exist: %s", configPath)
	}

	if _, err := toml.DecodeFile(configPath, &config); err != nil {
		return nil, fmt.Errorf("error decoding config file: %v", err)
	}

	if err := config.ApplyEnvOverrides(); err != nil {
		return nil, err
	}
	config.ApplyDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &config, nil
}

// ApplyDefaults fills in defaults for values that were not set. It is
// idempotent.
func (c *Config) ApplyDefaults() {
	if c.Server.Type == "" {
		c.Server.Type = GatewayTypeRPC
	}
	if c.Auth.Enabled == nil {
		enabled := true
		c.Auth.Enabled = &enabled
	}
	if c.HTTP.HealthPath == "" {
		c.HTTP.HealthPath = "/health"
	}
	if c.Server.Port == 0 {
		c.Server.Port = 8080
	}
	if c.Server.HealthPort == 0 {
		c.Server.HealthPort = c.Server.Port + 1
	}
	if c.Server.GracefulShutdownSec == 0 {
		c.Server.GracefulShutdownSec = 30
	}
	if c.Auth.CacheExpiration == 0 {
		c.Auth.CacheExpiration = 300
	}
	if c.Auth.HTTPTimeout == 0 {
		c.Auth.HTTPTimeout = 5
	}
	if c.Auth.CacheSize == 0 {
		c.Auth.CacheSize = 10000
	}
}

// Validate reports configuration errors. It expects defaults to have been
// applied already.
func (c *Config) Validate() error {
	switch c.Server.Type {
	case GatewayTypeRPC:
		if c.RPC.URL == "" {
			return fmt.Errorf("rpc.url is required when server.type is %q", GatewayTypeRPC)
		}
	case GatewayTypeS3:
		if c.S3.Bucket == "" {
			return fmt.Errorf("s3.bucket is required when server.type is %q", GatewayTypeS3)
		}
		if c.S3.AccessKeyID == "" || c.S3.SecretKey == "" {
			return fmt.Errorf("s3.access_key_id and s3.secret_key are required when server.type is %q", GatewayTypeS3)
		}
	case GatewayTypeHTTP:
		if c.HTTP.URL == "" {
			return fmt.Errorf("http.url is required when server.type is %q", GatewayTypeHTTP)
		}
	default:
		return fmt.Errorf("unsupported gateway type: %s (must be 'rpc', 's3' or 'http')", c.Server.Type)
	}
	if c.AuthEnabled() && c.Auth.ServiceURL == "" {
		return fmt.Errorf("auth.service_url is required (or set auth.enabled = false for an open gateway)")
	}
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535, got %d", c.Server.Port)
	}
	if c.Server.HealthPort < 1 || c.Server.HealthPort > 65535 {
		return fmt.Errorf("server.health_port must be between 1 and 65535, got %d", c.Server.HealthPort)
	}
	return nil
}
