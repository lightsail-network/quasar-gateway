package rpc

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRPCProxy(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid URL",
			target:      "http://example.com:8080",
			expectError: false,
		},
		{
			name:        "valid HTTPS URL",
			target:      "https://api.example.com/rpc",
			expectError: false,
		},
		{
			name:        "empty target",
			target:      "",
			expectError: true,
			errorMsg:    "target URL cannot be empty",
		},
		{
			name:        "invalid URL",
			target:      "not-a-url",
			expectError: true,
			errorMsg:    "invalid target URL: missing scheme or host",
		},
		{
			name:        "URL without scheme",
			target:      "example.com:8080",
			expectError: true,
			errorMsg:    "invalid target URL: missing scheme or host",
		},
		{
			name:        "URL without host",
			target:      "http://",
			expectError: true,
			errorMsg:    "invalid target URL: missing scheme or host",
		},
		{
			name:        "malformed URL",
			target:      "http://[invalid-ipv6",
			expectError: true,
			errorMsg:    "failed to parse target URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy, err := NewRPCProxy(tt.target)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, proxy)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, proxy)
				assert.NotNil(t, proxy.proxy)
			}
		})
	}
}

func TestRPCProxy_ServeHTTP(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"method":"%s","path":"%s","headers":%d}`,
			r.Method, r.URL.Path, len(r.Header))
	}))
	defer backendServer.Close()

	proxy, err := NewRPCProxy(backendServer.URL)
	require.NoError(t, err)

	tests := []struct {
		name           string
		method         string
		path           string
		body           string
		headers        map[string]string
		expectedStatus int
	}{
		{
			name:           "GET request",
			method:         "GET",
			path:           "/test",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST request with body",
			method:         "POST",
			path:           "/rpc/method",
			body:           `{"jsonrpc":"2.0","method":"test","id":1}`,
			headers:        map[string]string{"Content-Type": "application/json"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "PUT request",
			method:         "PUT",
			path:           "/data/123",
			body:           `{"data":"updated"}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "DELETE request",
			method:         "DELETE",
			path:           "/data/123",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with custom headers",
			method:         "GET",
			path:           "/test",
			headers:        map[string]string{"X-Custom": "value", "Authorization": "Bearer token"},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bodyReader io.Reader
			if tt.body != "" {
				bodyReader = strings.NewReader(tt.body)
			}

			req := httptest.NewRequest(tt.method, tt.path, bodyReader)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			rr := httptest.NewRecorder()
			proxy.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedStatus == http.StatusOK {
				body := rr.Body.String()
				assert.Contains(t, body, fmt.Sprintf(`"method":"%s"`, tt.method))
				assert.Contains(t, body, fmt.Sprintf(`"path":"%s"`, tt.path))
			}
		})
	}
}

func TestRPCProxy_ServeHTTP_BackendError(t *testing.T) {
	proxy, err := NewRPCProxy("http://nonexistent.example.com:9999")
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.Contains(t, rr.Body.String(), "Proxy error:")
}

func TestRPCProxy_ServeHTTPWithAuth_Authenticated(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("authenticated request"))
	}))
	defer backendServer.Close()

	proxy, err := NewRPCProxy(backendServer.URL)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	proxy.ServeHTTPWithAuth(rr, req, true)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "authenticated request")
}

func TestRPCProxy_ServeHTTPWithAuth_Unauthenticated(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Backend should not be called for unauthenticated requests")
	}))
	defer backendServer.Close()

	proxy, err := NewRPCProxy(backendServer.URL)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	proxy.ServeHTTPWithAuth(rr, req, false)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "Unauthorized")
}

func TestRPCProxy_PreservesRequestDetails(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/method", r.URL.Path)
		assert.Equal(t, "param=value", r.URL.RawQuery)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "Bearer token123", r.Header.Get("Authorization"))

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, `{"test":"data"}`, string(body))

		w.Header().Set("X-Response-Header", "backend-value")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"success":true}`))
	}))
	defer backendServer.Close()

	proxy, err := NewRPCProxy(backendServer.URL)
	require.NoError(t, err)

	reqBody := `{"test":"data"}`
	req := httptest.NewRequest("POST", "/api/v1/method?param=value", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer token123")

	rr := httptest.NewRecorder()
	proxy.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)
	assert.Equal(t, "backend-value", rr.Header().Get("X-Response-Header"))
	assert.JSONEq(t, `{"success":true}`, rr.Body.String())
}

func TestRPCProxy_ErrorHandler(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("backend panic")
	}))
	backendServer.Close() // Close immediately to simulate connection error

	proxy, err := NewRPCProxy(backendServer.URL)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.Contains(t, rr.Body.String(), "Proxy error:")
}

func TestRPCProxy_HandlesLargeRequests(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"received_bytes":%d}`, len(body))
	}))
	defer backendServer.Close()

	proxy, err := NewRPCProxy(backendServer.URL)
	require.NoError(t, err)

	largeBody := strings.Repeat("x", 10000) // 10KB of data
	req := httptest.NewRequest("POST", "/large", strings.NewReader(largeBody))
	req.Header.Set("Content-Type", "text/plain")

	rr := httptest.NewRecorder()
	proxy.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"received_bytes":10000`)
}

func TestNewRPCHealthChecker(t *testing.T) {
	checker := NewRPCHealthChecker("http://example.com:8080")
	assert.NotNil(t, checker)
	assert.Equal(t, "http://example.com:8080", checker.rpcURL)
	assert.NotNil(t, checker.httpClient)
}

func TestRPCHealthChecker_CheckHealth_Healthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req JSONRPCRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, "2.0", req.JSONRPC)
		assert.Equal(t, "getHealth", req.Method)
		assert.Equal(t, 0, req.ID)

		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      0,
			Result:  map[string]interface{}{"status": "healthy"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	checker := NewRPCHealthChecker(server.URL)
	statusCode, body, err := checker.CheckHealth()

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, statusCode)
	assert.JSONEq(t, `{"status":"healthy"}`, string(body))
}

func TestRPCHealthChecker_CheckHealth_Unhealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      0,
			Result:  map[string]interface{}{"status": "unhealthy"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	checker := NewRPCHealthChecker(server.URL)
	statusCode, body, err := checker.CheckHealth()

	require.Error(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, statusCode)
	assert.Contains(t, string(body), "service not healthy")
}

func TestRPCHealthChecker_CheckHealth_RPCError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      0,
			Error: &JSONRPCError{
				Code:    -32601,
				Message: "Method not found",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	checker := NewRPCHealthChecker(server.URL)
	statusCode, body, err := checker.CheckHealth()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Method not found")
	assert.Equal(t, http.StatusServiceUnavailable, statusCode)
	assert.Contains(t, string(body), "RPC error")
}

func TestRPCHealthChecker_CheckHealth_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	checker := NewRPCHealthChecker(server.URL)
	statusCode, body, err := checker.CheckHealth()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "RPC server returned status: 500")
	assert.Equal(t, http.StatusServiceUnavailable, statusCode)
	assert.Contains(t, string(body), "RPC server error")
}

func TestRPCHealthChecker_CheckHealth_NetworkError(t *testing.T) {
	checker := NewRPCHealthChecker("http://nonexistent.example.com:9999")
	statusCode, body, err := checker.CheckHealth()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to make request to RPC server")
	assert.Equal(t, http.StatusServiceUnavailable, statusCode)
	assert.Contains(t, string(body), "RPC server unreachable")
}

func TestRPCHealthChecker_CheckHealth_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	checker := NewRPCHealthChecker(server.URL)
	statusCode, body, err := checker.CheckHealth()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal JSON-RPC response")
	assert.Equal(t, http.StatusServiceUnavailable, statusCode)
	assert.Contains(t, string(body), "invalid RPC response")
}

func TestRPCHealthChecker_CheckHealth_MissingStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      0,
			Result:  map[string]interface{}{"other": "data"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	checker := NewRPCHealthChecker(server.URL)
	statusCode, body, err := checker.CheckHealth()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "service is not healthy")
	assert.Equal(t, http.StatusServiceUnavailable, statusCode)
	assert.Contains(t, string(body), "service not healthy")
}

func TestCreateUnhealthyResponse(t *testing.T) {
	response := createUnhealthyResponse("test reason")
	expected := `{"status":"unhealthy","reason":"test reason"}`
	assert.JSONEq(t, expected, string(response))
}
