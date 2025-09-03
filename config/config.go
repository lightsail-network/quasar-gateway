package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server ServerConfig `toml:"server"`
	RPC    RPCConfig    `toml:"rpc"`
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

type AuthConfig struct {
	ServiceURL      string `toml:"service_url"` // Base URL of auth service (e.g., "https://auth.example.com")
	ServiceToken    string `toml:"service_token"`
	CacheExpiration int    `toml:"cache_expiration"` // seconds (default 300 = 5 minutes)
	HTTPTimeout     int    `toml:"http_timeout"`     // seconds (default 5)
	CacheSize       int    `toml:"cache_size"`       // max entries in cache (default 10000)
	FailOpen        bool   `toml:"fail_open"`        // Allow requests when auth service is down (default true)
}

type S3Config struct {
	Endpoint    string `toml:"endpoint"`      // S3 endpoint URL (e.g., "https://s3.amazonaws.com" or "https://account-id.r2.cloudflarestorage.com")
	Region      string `toml:"region"`        // S3 region (e.g., "us-east-1" or "auto" for R2)
	Bucket      string `toml:"bucket"`        // S3 bucket name
	AccessKeyID string `toml:"access_key_id"` // S3 access key ID
	SecretKey   string `toml:"secret_key"`    // S3 secret access key
	PathPrefix  string `toml:"path_prefix"`   // URL path prefix for S3 requests (not used in s3 mode)
}

func LoadConfig(configPath string) (*Config, error) {
	var config Config

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file does not exist: %s", configPath)
	}

	if _, err := toml.DecodeFile(configPath, &config); err != nil {
		return nil, fmt.Errorf("error decoding config file: %v", err)
	}

	return &config, nil
}
