package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// envOverride binds one QUASAR_* environment variable to a config field.
// The same table drives both ApplyEnvOverrides and EnvUsage so the --help
// output can never drift from what is actually supported.
type envOverride struct {
	name  string
	desc  string
	apply func(c *Config, value string) error
}

var envOverrides = []envOverride{
	{"QUASAR_SERVER_HOST", "Server host (e.g., 0.0.0.0)", func(c *Config, v string) error { c.Server.Host = v; return nil }},
	{"QUASAR_SERVER_PORT", "Server port (e.g., 8080)", func(c *Config, v string) error { return setInt(&c.Server.Port, v) }},
	{"QUASAR_SERVER_HEALTH_PORT", "Health check server port (e.g., 8081)", func(c *Config, v string) error { return setInt(&c.Server.HealthPort, v) }},
	{"QUASAR_SERVER_GRACEFUL_SHUTDOWN_SEC", "Graceful shutdown wait time (e.g., 30)", func(c *Config, v string) error { return setInt(&c.Server.GracefulShutdownSec, v) }},
	{"QUASAR_SERVER_TYPE", "Gateway type (rpc or s3)", func(c *Config, v string) error { c.Server.Type = v; return nil }},
	{"QUASAR_RPC_URL", "RPC server URL", func(c *Config, v string) error { c.RPC.URL = v; return nil }},
	{"QUASAR_HTTP_URL", "HTTP backend URL", func(c *Config, v string) error { c.HTTP.URL = v; return nil }},
	{"QUASAR_HTTP_HEALTH_PATH", "HTTP backend health path (default: /health)", func(c *Config, v string) error { c.HTTP.HealthPath = v; return nil }},
	{"QUASAR_S3_ENDPOINT", "S3 endpoint URL", func(c *Config, v string) error { c.S3.Endpoint = v; return nil }},
	{"QUASAR_S3_REGION", "S3 region", func(c *Config, v string) error { c.S3.Region = v; return nil }},
	{"QUASAR_S3_BUCKET", "S3 bucket name", func(c *Config, v string) error { c.S3.Bucket = v; return nil }},
	{"QUASAR_S3_ACCESS_KEY_ID", "S3 access key ID", func(c *Config, v string) error { c.S3.AccessKeyID = v; return nil }},
	{"QUASAR_S3_SECRET_KEY", "S3 secret access key", func(c *Config, v string) error { c.S3.SecretKey = v; return nil }},
	{"QUASAR_AUTH_ENABLED", "Enable API key authentication (default: true)", func(c *Config, v string) error { return setBoolPtr(&c.Auth.Enabled, v) }},
	{"QUASAR_AUTH_SERVICE_URL", "Auth service URL", func(c *Config, v string) error { c.Auth.ServiceURL = v; return nil }},
	{"QUASAR_AUTH_SERVICE_TOKEN", "Auth service token", func(c *Config, v string) error { c.Auth.ServiceToken = v; return nil }},
	{"QUASAR_AUTH_CACHE_EXPIRATION", "Auth cache expiration (seconds)", func(c *Config, v string) error { return setInt(&c.Auth.CacheExpiration, v) }},
	{"QUASAR_AUTH_HTTP_TIMEOUT", "Auth HTTP timeout (seconds)", func(c *Config, v string) error { return setInt(&c.Auth.HTTPTimeout, v) }},
	{"QUASAR_AUTH_CACHE_SIZE", "Auth cache size (max entries)", func(c *Config, v string) error { return setInt(&c.Auth.CacheSize, v) }},
	{"QUASAR_AUTH_FAIL_OPEN", "Allow requests when auth service is down (default: false)", func(c *Config, v string) error { return setBool(&c.Auth.FailOpen, v) }},
}

func setInt(dst *int, value string) error {
	n, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("expected an integer, got %q", value)
	}
	*dst = n
	return nil
}

func setBool(dst *bool, value string) error {
	b, err := strconv.ParseBool(value)
	if err != nil {
		return fmt.Errorf("expected a boolean, got %q", value)
	}
	*dst = b
	return nil
}

func setBoolPtr(dst **bool, value string) error {
	b, err := strconv.ParseBool(value)
	if err != nil {
		return fmt.Errorf("expected a boolean, got %q", value)
	}
	*dst = &b
	return nil
}

// ApplyEnvOverrides overrides config values from QUASAR_* environment
// variables. A set but unparseable value is an error: a typo in the
// environment must not silently fall back to the file value.
func (c *Config) ApplyEnvOverrides() error {
	for _, e := range envOverrides {
		value := os.Getenv(e.name)
		if value == "" {
			continue
		}
		if err := e.apply(c, value); err != nil {
			return fmt.Errorf("invalid value for %s: %v", e.name, err)
		}
	}
	return nil
}

// EnvUsage returns one line of documentation per supported environment
// variable, for use in --help output.
func EnvUsage() string {
	var b strings.Builder
	fmt.Fprintf(&b, "    %-36s - %s\n", "QUASAR_CONFIG_PATH", "Path to configuration file")
	for _, e := range envOverrides {
		fmt.Fprintf(&b, "    %-36s - %s\n", e.name, e.desc)
	}
	return b.String()
}
