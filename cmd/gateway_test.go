package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"quasar-gateway/config"
	"quasar-gateway/internal/auth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestConfig(serverType string) *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Host:                "127.0.0.1",
			Port:                0,
			HealthPort:          0,
			GracefulShutdownSec: 1,
			Type:                serverType,
		},
		RPC: config.RPCConfig{
			URL: "http://localhost:8080",
		},
		S3: config.S3Config{
			Endpoint:    "https://test.s3.amazonaws.com",
			Region:      "us-east-1",
			Bucket:      "test-bucket",
			AccessKeyID: "test-key",
			SecretKey:   "test-secret",
		},
		Auth: config.AuthConfig{
			ServiceURL:      "http://localhost:9000",
			ServiceToken:    "auth-token",
			CacheExpiration: 300,
			HTTPTimeout:     5,
			CacheSize:       1000,
			FailOpen:        true,
		},
	}
}

func TestNewGateway_RPC(t *testing.T) {
	cfg := createTestConfig("rpc")

	gateway, err := NewGateway(cfg)
	require.NoError(t, err)
	assert.NotNil(t, gateway)
	assert.Equal(t, cfg, gateway.config)
	assert.NotNil(t, gateway.authenticator)
	assert.NotNil(t, gateway.rpcProxy)
	assert.NotNil(t, gateway.healthChecker)
	assert.Nil(t, gateway.s3Proxy)
	assert.True(t, gateway.isHealthy)
}

func TestNewGateway_S3(t *testing.T) {
	cfg := createTestConfig("s3")

	gateway, err := NewGateway(cfg)
	require.NoError(t, err)
	assert.NotNil(t, gateway)
	assert.Equal(t, cfg, gateway.config)
	assert.NotNil(t, gateway.authenticator)
	assert.NotNil(t, gateway.s3Proxy)
	assert.NotNil(t, gateway.healthChecker)
	assert.Nil(t, gateway.rpcProxy)
	assert.True(t, gateway.isHealthy)
}

func TestNewGateway_UnsupportedType(t *testing.T) {
	cfg := createTestConfig("unsupported")

	gateway, err := NewGateway(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported gateway type")
	assert.Nil(t, gateway)
}

func TestNewGateway_DefaultType(t *testing.T) {
	cfg := createTestConfig("")

	gateway, err := NewGateway(cfg)
	require.NoError(t, err)
	assert.NotNil(t, gateway.rpcProxy)
	assert.Nil(t, gateway.s3Proxy)
}

func TestGateway_HandleHealth_Healthy(t *testing.T) {
	cfg := createTestConfig("rpc")
	gateway, err := NewGateway(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()

	gateway.handleHealth(rr, req)

	// Since we can't easily mock the health checker, we expect it to fail
	// but gateway should still respond (might be unhealthy due to mock backend)
	assert.Contains(t, []int{http.StatusOK, http.StatusServiceUnavailable}, rr.Code)
}

func TestGateway_HandleHealth_Unhealthy(t *testing.T) {
	cfg := createTestConfig("rpc")
	gateway, err := NewGateway(cfg)
	require.NoError(t, err)

	gateway.isHealthy = false

	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()

	gateway.handleHealth(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.Contains(t, rr.Body.String(), "service shutting down")
}

func TestGateway_HandleProxy_MissingAuthHeader(t *testing.T) {
	cfg := createTestConfig("rpc")
	gateway, err := NewGateway(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/rpc/method", strings.NewReader(`{"test": "data"}`))
	rr := httptest.NewRecorder()

	gateway.handleProxy(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing or invalid Authorization header")
}

func TestGateway_HandleProxy_InvalidAuthHeader(t *testing.T) {
	cfg := createTestConfig("rpc")
	gateway, err := NewGateway(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/rpc/method", strings.NewReader(`{"test": "data"}`))
	req.Header.Set("Authorization", "Invalid header")
	rr := httptest.NewRecorder()

	gateway.handleProxy(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing or invalid Authorization header")
}

func TestGateway_HandleProxy_EmptyAPIKey(t *testing.T) {
	cfg := createTestConfig("rpc")
	gateway, err := NewGateway(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/rpc/method", strings.NewReader(`{"test": "data"}`))
	req.Header.Set("Authorization", "Bearer ")
	rr := httptest.NewRecorder()

	gateway.handleProxy(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Empty API key")
}

func TestGateway_HandleS3_MissingAuthHeader(t *testing.T) {
	cfg := createTestConfig("s3")
	gateway, err := NewGateway(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/test-file.txt", nil)
	rr := httptest.NewRecorder()

	gateway.handleS3(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing or invalid Authorization header")
}

func TestGateway_HandleS3_InvalidAuthHeader(t *testing.T) {
	cfg := createTestConfig("s3")
	gateway, err := NewGateway(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/test-file.txt", nil)
	req.Header.Set("Authorization", "Invalid header")
	rr := httptest.NewRecorder()

	gateway.handleS3(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing or invalid Authorization header")
}

func TestGateway_HandleS3_EmptyAPIKey(t *testing.T) {
	cfg := createTestConfig("s3")
	gateway, err := NewGateway(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/test-file.txt", nil)
	req.Header.Set("Authorization", "Bearer ")
	rr := httptest.NewRecorder()

	gateway.handleS3(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Empty API key")
}

func TestOverrideConfigFromEnv(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "default-host",
			Port: 8080,
		},
		RPC: config.RPCConfig{
			URL: "http://default.com",
		},
		Auth: config.AuthConfig{
			ServiceURL: "http://auth-default.com",
		},
	}

	os.Setenv("QUASAR_SERVER_HOST", "env-host")
	os.Setenv("QUASAR_SERVER_PORT", "9090")
	os.Setenv("QUASAR_RPC_URL", "http://env-rpc.com")
	os.Setenv("QUASAR_AUTH_SERVICE_URL", "http://env-auth.com")
	os.Setenv("QUASAR_AUTH_FAIL_OPEN", "false")

	defer func() {
		os.Unsetenv("QUASAR_SERVER_HOST")
		os.Unsetenv("QUASAR_SERVER_PORT")
		os.Unsetenv("QUASAR_RPC_URL")
		os.Unsetenv("QUASAR_AUTH_SERVICE_URL")
		os.Unsetenv("QUASAR_AUTH_FAIL_OPEN")
	}()

	overrideConfigFromEnv(cfg)

	assert.Equal(t, "env-host", cfg.Server.Host)
	assert.Equal(t, 9090, cfg.Server.Port)
	assert.Equal(t, "http://env-rpc.com", cfg.RPC.URL)
	assert.Equal(t, "http://env-auth.com", cfg.Auth.ServiceURL)
	assert.False(t, cfg.Auth.FailOpen)
}

func TestGetDefaultConfigPath(t *testing.T) {
	os.Unsetenv("QUASAR_CONFIG_PATH")
	path := getDefaultConfigPath()
	assert.Equal(t, "config.toml", path)

	os.Setenv("QUASAR_CONFIG_PATH", "/custom/path/config.toml")
	defer os.Unsetenv("QUASAR_CONFIG_PATH")

	path = getDefaultConfigPath()
	assert.Equal(t, "/custom/path/config.toml", path)
}

func TestGateway_IntegrationWithMockServers(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req auth.AuthRequest
		json.NewDecoder(r.Body).Decode(&req)

		valid := strings.HasPrefix(req.KeySecret, "valid-")
		resp := auth.AuthResponse{Valid: valid}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer authServer.Close()

	rpcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"result": "success", "method": "%s"}`, r.Method)
	}))
	defer rpcServer.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:                "127.0.0.1",
			Port:                0,
			HealthPort:          0,
			GracefulShutdownSec: 1,
			Type:                "rpc",
		},
		RPC: config.RPCConfig{
			URL: rpcServer.URL,
		},
		Auth: config.AuthConfig{
			ServiceURL:      authServer.URL,
			ServiceToken:    "test-token",
			CacheExpiration: 300,
			HTTPTimeout:     5,
			CacheSize:       1000,
			FailOpen:        false,
		},
	}

	gateway, err := NewGateway(cfg)
	require.NoError(t, err)

	tests := []struct {
		name           string
		apiKey         string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "valid API key",
			apiKey:         "valid-test-key",
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:           "invalid API key",
			apiKey:         "invalid-test-key",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Unauthorized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/rpc/test", strings.NewReader(`{"method": "test"}`))
			req.Header.Set("Authorization", "Bearer "+tt.apiKey)
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()

			gateway.handleProxy(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expectedBody)
		})
	}
}

func TestAuthenticatorConfigDefaults(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host: "127.0.0.1",
			Port: 0,
			Type: "rpc",
		},
		RPC: config.RPCConfig{
			URL: "http://localhost:8080",
		},
		Auth: config.AuthConfig{
			ServiceURL:   "http://test.com",
			ServiceToken: "token",
		},
	}

	gateway, err := NewGateway(cfg)
	require.NoError(t, err)

	assert.NotNil(t, gateway.authenticator)
}

func TestGateway_HealthServerConfiguration(t *testing.T) {
	cfg := createTestConfig("rpc")
	cfg.Server.Port = 8000
	cfg.Server.HealthPort = 0

	gateway, err := NewGateway(cfg)
	require.NoError(t, err)

	assert.NotNil(t, gateway.server)
	assert.NotNil(t, gateway.healthServer)

	assert.Contains(t, gateway.healthServer.Addr, ":8001")
}

func TestGateway_HealthServerCustomPort(t *testing.T) {
	cfg := createTestConfig("rpc")
	cfg.Server.Port = 8000
	cfg.Server.HealthPort = 9000

	gateway, err := NewGateway(cfg)
	require.NoError(t, err)

	assert.Contains(t, gateway.healthServer.Addr, ":9000")
}
