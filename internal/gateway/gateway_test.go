package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"quasar-gateway/config"
	"quasar-gateway/internal/auth"
	"quasar-gateway/internal/health"
	"quasar-gateway/internal/rpc"
	"quasar-gateway/internal/s3"

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
		HTTP: config.HTTPConfig{
			URL: "http://localhost:8003",
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

// serve sends req through the gateway's real handler chain (mux + auth
// middleware + backend) and returns the recorded response.
func serve(g *Gateway, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	g.server.Handler.ServeHTTP(rr, req)
	return rr
}

func TestNew_RPC(t *testing.T) {
	cfg := createTestConfig("rpc")

	gateway, err := New(cfg)
	require.NoError(t, err)
	assert.NotNil(t, gateway)
	assert.Equal(t, cfg, gateway.config)
	assert.NotNil(t, gateway.authenticator)
	assert.NotNil(t, gateway.healthChecker)
	assert.IsType(t, &rpc.RPCProxy{}, gateway.backend)
	assert.True(t, gateway.isHealthy.Load())
	assert.Equal(t, 30*time.Second, gateway.server.WriteTimeout)
}

func TestNew_S3(t *testing.T) {
	cfg := createTestConfig("s3")

	gateway, err := New(cfg)
	require.NoError(t, err)
	assert.NotNil(t, gateway)
	assert.Equal(t, cfg, gateway.config)
	assert.NotNil(t, gateway.authenticator)
	assert.NotNil(t, gateway.healthChecker)
	assert.IsType(t, &s3.S3Proxy{}, gateway.backend)
	assert.True(t, gateway.isHealthy.Load())
	// No write deadline in S3 mode: large downloads must not be cut off.
	assert.Zero(t, gateway.server.WriteTimeout)
}

func TestNew_HTTP(t *testing.T) {
	cfg := createTestConfig("http")

	gateway, err := New(cfg)
	require.NoError(t, err)
	assert.NotNil(t, gateway)
	assert.NotNil(t, gateway.authenticator)
	assert.IsType(t, &rpc.RPCProxy{}, gateway.backend)
	assert.IsType(t, &health.HTTPStatusChecker{}, gateway.healthChecker)
	assert.True(t, gateway.isHealthy.Load())
	// Short-lived API exchanges: same write deadline as RPC mode.
	assert.Equal(t, 30*time.Second, gateway.server.WriteTimeout)
}

// HTTP mode extracts keys from the header only: a single-segment path like
// /graphql is a real route on the backend and must never be consumed as a
// URL token.
func TestGateway_HTTP_PathNeverTreatedAsToken(t *testing.T) {
	cfg := createTestConfig("http")
	gateway, err := New(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/graphql", strings.NewReader(`{"query": "{}"}`))
	rr := serve(gateway, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing or invalid Authorization header")
	// The path must survive untouched — no rewrite to "/".
	assert.Equal(t, "/graphql", req.URL.Path)
}

// Open HTTP gateway in front of a wallet-backend-shaped API: requests pass
// through untouched and the gateway health endpoint mirrors the backend's
// /health status.
func TestGateway_HTTP_AuthDisabled_EndToEnd(t *testing.T) {
	backendHealthy := true
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			if backendHealthy {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"status": "ok"}`)
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprint(w, `{"error": "wallet backend is not in sync with the RPC"}`)
			}
		case "/graphql":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"data": {}, "method": "%s"}`, r.Method)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer backend.Close()

	cfg := createTestConfig("http")
	cfg.HTTP.URL = backend.URL
	disableAuth(cfg)

	gateway, err := New(cfg)
	require.NoError(t, err)
	assert.Nil(t, gateway.authenticator)

	// GraphQL request passes through without credentials.
	req := httptest.NewRequest("POST", "/graphql", strings.NewReader(`{"query": "{}"}`))
	rr := serve(gateway, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"method": "POST"`)
	assert.Equal(t, "*", rr.Header().Get("Access-Control-Allow-Origin"))

	// Gateway health follows the backend's /health status code.
	healthReq := httptest.NewRequest("GET", "/health", nil)
	healthRR := httptest.NewRecorder()
	gateway.handleHealth(healthRR, healthReq)
	assert.Equal(t, http.StatusOK, healthRR.Code)

	backendHealthy = false
	healthRR = httptest.NewRecorder()
	gateway.handleHealth(healthRR, healthReq)
	assert.Equal(t, http.StatusServiceUnavailable, healthRR.Code)
	assert.Contains(t, healthRR.Body.String(), "503")
}

func TestNew_UnsupportedType(t *testing.T) {
	cfg := createTestConfig("unsupported")

	gateway, err := New(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported gateway type")
	assert.Nil(t, gateway)
}

func TestNew_DefaultType(t *testing.T) {
	cfg := createTestConfig("")

	gateway, err := New(cfg)
	require.NoError(t, err)
	assert.IsType(t, &rpc.RPCProxy{}, gateway.backend)
}

func TestGateway_HandleHealth_Healthy(t *testing.T) {
	cfg := createTestConfig("rpc")
	gateway, err := New(cfg)
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
	gateway, err := New(cfg)
	require.NoError(t, err)

	gateway.isHealthy.Store(false)

	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()

	gateway.handleHealth(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	assert.Contains(t, rr.Body.String(), "service shutting down")
}

func TestGateway_HandleRPC_MissingAuthHeader(t *testing.T) {
	cfg := createTestConfig("rpc")
	gateway, err := New(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/rpc/method", strings.NewReader(`{"test": "data"}`))
	rr := serve(gateway, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing or invalid Authorization header")
}

func TestGateway_HandleRPC_InvalidAuthHeader(t *testing.T) {
	cfg := createTestConfig("rpc")
	gateway, err := New(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/rpc/method", strings.NewReader(`{"test": "data"}`))
	req.Header.Set("Authorization", "Invalid header")
	rr := serve(gateway, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing or invalid Authorization header")
}

func TestGateway_HandleRPC_EmptyAPIKey(t *testing.T) {
	cfg := createTestConfig("rpc")
	gateway, err := New(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/rpc/method", strings.NewReader(`{"test": "data"}`))
	req.Header.Set("Authorization", "Bearer ")
	rr := serve(gateway, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Empty API key")
}

func TestGateway_HandleS3_MissingAuthHeader(t *testing.T) {
	cfg := createTestConfig("s3")
	gateway, err := New(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/test-file.txt", nil)
	rr := serve(gateway, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing or invalid Authorization header")
}

func TestGateway_HandleS3_InvalidAuthHeader(t *testing.T) {
	cfg := createTestConfig("s3")
	gateway, err := New(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/test-file.txt", nil)
	req.Header.Set("Authorization", "Invalid header")
	rr := serve(gateway, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing or invalid Authorization header")
}

func TestGateway_HandleS3_EmptyAPIKey(t *testing.T) {
	cfg := createTestConfig("s3")
	gateway, err := New(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/test-file.txt", nil)
	req.Header.Set("Authorization", "Bearer ")
	rr := serve(gateway, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Empty API key")
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

	cfg := createTestConfig("rpc")
	cfg.RPC.URL = rpcServer.URL
	cfg.Auth.ServiceURL = authServer.URL
	cfg.Auth.ServiceToken = "test-token"
	cfg.Auth.FailOpen = false

	gateway, err := New(cfg)
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

			rr := serve(gateway, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			assert.Contains(t, rr.Body.String(), tt.expectedBody)
		})
	}
}

// disableAuth turns cfg into an open-gateway config, clearing the auth
// service fields to prove they are not needed in that mode.
func disableAuth(cfg *config.Config) {
	enabled := false
	cfg.Auth = config.AuthConfig{Enabled: &enabled}
}

// With auth disabled, requests without any credentials are proxied straight
// to the backend, single-segment paths are NOT treated as URL tokens, and no
// authenticator is created at all.
func TestGateway_AuthDisabled_RPCPassthrough(t *testing.T) {
	rpcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"result": "success", "path": "%s"}`, r.URL.Path)
	}))
	defer rpcServer.Close()

	cfg := createTestConfig("rpc")
	cfg.RPC.URL = rpcServer.URL
	disableAuth(cfg)

	gateway, err := New(cfg)
	require.NoError(t, err)
	assert.Nil(t, gateway.authenticator)

	for _, path := range []string{"/", "/looks-like-a-token", "/api/v1/method"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("POST", path, strings.NewReader(`{"method": "test"}`))
			rr := serve(gateway, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			// The path must reach the backend unchanged: no URL-token rewrite.
			assert.Contains(t, rr.Body.String(), fmt.Sprintf(`"path": "%s"`, path))
			// CORS headers still apply in open mode.
			assert.Equal(t, "*", rr.Header().Get("Access-Control-Allow-Origin"))
		})
	}
}

func TestGateway_AuthDisabled_S3(t *testing.T) {
	cfg := createTestConfig("s3")
	disableAuth(cfg)

	gateway, err := New(cfg)
	require.NoError(t, err)
	assert.Nil(t, gateway.authenticator)
	assert.IsType(t, &s3.S3Proxy{}, gateway.backend)
}

// Open mode still terminates CORS preflight at the gateway.
func TestGateway_AuthDisabled_OPTIONSPreflight(t *testing.T) {
	cfg := createTestConfig("rpc")
	disableAuth(cfg)

	gateway, err := New(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("OPTIONS", "/some/path", nil)
	req.Header.Set("Origin", "https://example.com")
	rr := serve(gateway, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)
	assert.Equal(t, "*", rr.Header().Get("Access-Control-Allow-Origin"))
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

	gateway, err := New(cfg)
	require.NoError(t, err)

	assert.NotNil(t, gateway.authenticator)
}

func TestGateway_HealthServerConfiguration(t *testing.T) {
	cfg := createTestConfig("rpc")
	cfg.Server.Port = 8000
	cfg.Server.HealthPort = 0

	gateway, err := New(cfg)
	require.NoError(t, err)

	assert.NotNil(t, gateway.server)
	assert.NotNil(t, gateway.healthServer)

	assert.Contains(t, gateway.healthServer.Addr, ":8001")
}

func TestGateway_HealthServerCustomPort(t *testing.T) {
	cfg := createTestConfig("rpc")
	cfg.Server.Port = 8000
	cfg.Server.HealthPort = 9000

	gateway, err := New(cfg)
	require.NoError(t, err)

	assert.Contains(t, gateway.healthServer.Addr, ":9000")
}

func TestGateway_HandleRPC_URLToken(t *testing.T) {
	cfg := createTestConfig("rpc")
	cfg.Auth.FailOpen = false // Ensure authentication failures result in 401
	gateway, err := New(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/test-token-123", strings.NewReader(`{"test": "data"}`))
	rr := serve(gateway, req)

	// Should fail authentication since auth service is unreachable
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	// Check that URL path was modified to root
	assert.Equal(t, "/", req.URL.Path)
}

func TestGateway_HandleRPC_URLTokenEmpty(t *testing.T) {
	cfg := createTestConfig("rpc")
	gateway, err := New(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"test": "data"}`))
	rr := serve(gateway, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing or invalid Authorization header or token in URL path")
}

func TestGateway_HandleRPC_URLTokenWithPath(t *testing.T) {
	cfg := createTestConfig("rpc")
	gateway, err := New(cfg)
	require.NoError(t, err)

	// URL with multiple path segments should fall back to header auth
	req := httptest.NewRequest("POST", "/api/v1/method", strings.NewReader(`{"test": "data"}`))
	rr := serve(gateway, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Missing or invalid Authorization header or token in URL path")
	// Path should remain unchanged since it contains multiple segments
	assert.Equal(t, "/api/v1/method", req.URL.Path)
}

func TestGateway_HandleRPC_FallbackToHeader(t *testing.T) {
	cfg := createTestConfig("rpc")
	cfg.Auth.FailOpen = false // Ensure authentication failures result in proper error
	gateway, err := New(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/method", strings.NewReader(`{"test": "data"}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rr := serve(gateway, req)

	// Should fail auth since auth service is unreachable
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	// Path should remain unchanged
	assert.Equal(t, "/api/method", req.URL.Path)
}

// CORS preflight requests terminate at the gateway in both modes: no
// authentication, no backend involved.
func TestGateway_OPTIONS_Preflight(t *testing.T) {
	for _, serverType := range []string{"rpc", "s3"} {
		t.Run(serverType, func(t *testing.T) {
			cfg := createTestConfig(serverType)
			gateway, err := New(cfg)
			require.NoError(t, err)

			req := httptest.NewRequest("OPTIONS", "/some/path", nil)
			req.Header.Set("Origin", "https://example.com")
			rr := serve(gateway, req)

			assert.Equal(t, http.StatusNoContent, rr.Code)
			assert.Equal(t, "*", rr.Header().Get("Access-Control-Allow-Origin"))
			// Authorization is not covered by a wildcard, so it must be listed.
			assert.Contains(t, rr.Header().Get("Access-Control-Allow-Headers"), "Authorization")
			assert.Equal(t, "GET, POST, HEAD, OPTIONS", rr.Header().Get("Access-Control-Allow-Methods"))
			assert.Equal(t, "86400", rr.Header().Get("Access-Control-Max-Age"))
			assert.Empty(t, rr.Body.String())
		})
	}
}

// Error responses must carry Access-Control-Allow-Origin too, otherwise
// browser scripts cannot read them at all.
func TestGateway_CORSHeaderOnErrorResponse(t *testing.T) {
	cfg := createTestConfig("rpc")
	gateway, err := New(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"test": "data"}`))
	rr := serve(gateway, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Equal(t, "*", rr.Header().Get("Access-Control-Allow-Origin"))
}

// A backend that sets its own Allow-Origin header must not lead to a
// duplicated value ("*, *"), which browsers reject.
func TestGateway_CORSHeaderNotDuplicatedFromBackend(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(auth.AuthResponse{Valid: true})
	}))
	defer authServer.Close()

	rpcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"result": "success"}`)
	}))
	defer rpcServer.Close()

	cfg := createTestConfig("rpc")
	cfg.RPC.URL = rpcServer.URL
	cfg.Auth.ServiceURL = authServer.URL

	gateway, err := New(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"method": "test"}`))
	req.Header.Set("Authorization", "Bearer some-key")
	rr := serve(gateway, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []string{"*"}, rr.Header().Values("Access-Control-Allow-Origin"))
}

func TestGateway_HandleRPC_URLToken_Integration(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req auth.AuthRequest
		json.NewDecoder(r.Body).Decode(&req)

		// Accept tokens that start with "valid-"
		valid := strings.HasPrefix(req.KeySecret, "valid-")
		resp := auth.AuthResponse{Valid: valid}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer authServer.Close()

	rpcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"result": "success", "path": "%s"}`, r.URL.Path)
	}))
	defer rpcServer.Close()

	cfg := createTestConfig("rpc")
	cfg.RPC.URL = rpcServer.URL
	cfg.Auth.ServiceURL = authServer.URL
	cfg.Auth.ServiceToken = "test-token"
	cfg.Auth.FailOpen = false

	gateway, err := New(cfg)
	require.NoError(t, err)

	tests := []struct {
		name           string
		path           string
		header         string
		expectedStatus int
		expectedPath   string
	}{
		{
			name:           "valid URL token",
			path:           "/valid-token-123",
			header:         "",
			expectedStatus: http.StatusOK,
			expectedPath:   "/", // Should be rewritten to root
		},
		{
			name:           "invalid URL token",
			path:           "/invalid-token-123",
			header:         "",
			expectedStatus: http.StatusUnauthorized,
			expectedPath:   "/", // Should still be rewritten
		},
		{
			name:           "valid header token with path",
			path:           "/api/v1/method",
			header:         "Bearer valid-header-token",
			expectedStatus: http.StatusOK,
			expectedPath:   "/api/v1/method", // Should remain unchanged
		},
		{
			name:           "invalid header token with path",
			path:           "/api/v1/method",
			header:         "Bearer invalid-header-token",
			expectedStatus: http.StatusUnauthorized,
			expectedPath:   "/api/v1/method", // Should remain unchanged
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", tt.path, strings.NewReader(`{"method": "test"}`))
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			req.Header.Set("Content-Type", "application/json")

			rr := serve(gateway, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			if rr.Code == http.StatusOK {
				assert.Contains(t, rr.Body.String(), fmt.Sprintf(`"path": "%s"`, tt.expectedPath))
			}
		})
	}
}
