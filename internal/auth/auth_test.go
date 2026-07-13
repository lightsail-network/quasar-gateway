package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthenticator(t *testing.T) {
	auth, err := NewAuthenticator("http://example.com", "test-token")
	require.NoError(t, err)
	assert.NotNil(t, auth)
	assert.Equal(t, "http://example.com", auth.authServiceURL)
	assert.Equal(t, "test-token", auth.authServiceToken)
	assert.Equal(t, 5*time.Minute, auth.cacheExpiration)
	assert.False(t, auth.failOpen)
}

func TestNewAuthenticatorWithConfig(t *testing.T) {
	config := AuthenticatorConfig{
		AuthServiceURL:   "http://test.com",
		AuthServiceToken: "token123",
		CacheExpiration:  10 * time.Minute,
		HTTPTimeout:      2 * time.Second,
		CacheSize:        5000,
		FailOpen:         false,
	}

	auth, err := NewAuthenticatorWithConfig(config)
	require.NoError(t, err)
	assert.NotNil(t, auth)
	assert.Equal(t, "http://test.com", auth.authServiceURL)
	assert.Equal(t, "token123", auth.authServiceToken)
	assert.Equal(t, 10*time.Minute, auth.cacheExpiration)
	assert.False(t, auth.failOpen)
}

func TestNewAuthenticatorWithConfigDefaults(t *testing.T) {
	config := AuthenticatorConfig{
		AuthServiceURL:   "http://test.com",
		AuthServiceToken: "token123",
	}

	auth, err := NewAuthenticatorWithConfig(config)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, auth.cacheExpiration)
	assert.Equal(t, 5*time.Second, auth.httpClient.Timeout)
}

func TestValidateAPIKey_Empty(t *testing.T) {
	auth, err := NewAuthenticator("http://example.com", "test-token")
	require.NoError(t, err)

	valid, err := auth.ValidateAPIKey(context.Background(), "")
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestValidateAPIKey_ValidResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/validate", r.URL.Path)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req AuthRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)
		assert.Equal(t, "test-api-key", req.KeySecret)

		resp := AuthResponse{Valid: true}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	auth, err := NewAuthenticator(server.URL, "test-token")
	require.NoError(t, err)

	valid, err := auth.ValidateAPIKey(context.Background(), "test-api-key")
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestValidateAPIKey_InvalidResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := AuthResponse{Valid: false}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	auth, err := NewAuthenticator(server.URL, "test-token")
	require.NoError(t, err)

	valid, err := auth.ValidateAPIKey(context.Background(), "invalid-key")
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestValidateAPIKey_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	auth, err := NewAuthenticator(server.URL, "test-token")
	require.NoError(t, err)

	valid, err := auth.ValidateAPIKey(context.Background(), "test-key")
	require.Error(t, err)
	assert.False(t, valid)
}

func TestValidateAPIKey_ServerError_FailOpen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := AuthenticatorConfig{
		AuthServiceURL:   server.URL,
		AuthServiceToken: "test-token",
		FailOpen:         true,
	}
	auth, err := NewAuthenticatorWithConfig(config)
	require.NoError(t, err)

	valid, err := auth.ValidateAPIKey(context.Background(), "test-key")
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestValidateAPIKey_Rejected_FailOpen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	config := AuthenticatorConfig{
		AuthServiceURL:   server.URL,
		AuthServiceToken: "test-token",
		FailOpen:         true,
	}
	auth, err := NewAuthenticatorWithConfig(config)
	require.NoError(t, err)

	// An explicit 4xx rejection from the auth service must not be treated
	// as "service down": fail-open does not apply and the key is invalid.
	valid, err := auth.ValidateAPIKey(context.Background(), "test-key")
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestValidateAPIKey_Rejected_FailClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	auth, err := NewAuthenticator(server.URL, "test-token")
	require.NoError(t, err)

	// An explicit rejection is a normal "invalid key" outcome, not an
	// internal error, so no error is returned to the caller.
	valid, err := auth.ValidateAPIKey(context.Background(), "test-key")
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestValidateAPIKey_Caching(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		resp := AuthResponse{Valid: true}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	auth, err := NewAuthenticator(server.URL, "test-token")
	require.NoError(t, err)

	apiKey := "cached-key"

	// First call should hit the server
	valid, err := auth.ValidateAPIKey(context.Background(), apiKey)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.Equal(t, 1, callCount)

	// Second call should use cache
	valid, err = auth.ValidateAPIKey(context.Background(), apiKey)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.Equal(t, 1, callCount)
}

func TestValidateAPIKey_CacheExpiration(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		resp := AuthResponse{Valid: true}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := AuthenticatorConfig{
		AuthServiceURL:   server.URL,
		AuthServiceToken: "test-token",
		CacheExpiration:  100 * time.Millisecond,
	}
	auth, err := NewAuthenticatorWithConfig(config)
	require.NoError(t, err)

	apiKey := "expiring-key"

	// First call
	valid, err := auth.ValidateAPIKey(context.Background(), apiKey)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.Equal(t, 1, callCount)

	// Wait for cache to expire
	time.Sleep(150 * time.Millisecond)
	valid, err = auth.ValidateAPIKey(context.Background(), apiKey)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.Equal(t, 2, callCount)
}

func TestValidateAPIKey_NetworkError_FailOpen(t *testing.T) {
	config := AuthenticatorConfig{
		AuthServiceURL:   "http://nonexistent.example.com",
		AuthServiceToken: "test-token",
		FailOpen:         true,
	}
	auth, err := NewAuthenticatorWithConfig(config)
	require.NoError(t, err)

	valid, err := auth.ValidateAPIKey(context.Background(), "test-key")
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestValidateAPIKey_NetworkError_FailClosed(t *testing.T) {
	auth, err := NewAuthenticator("http://nonexistent.example.com", "test-token")
	require.NoError(t, err)

	valid, err := auth.ValidateAPIKey(context.Background(), "test-key")
	require.Error(t, err)
	assert.False(t, valid)
}

func TestHashAPIKey(t *testing.T) {
	hash1 := hashAPIKey("test-key")
	assert.NotEmpty(t, hash1)
	assert.Equal(t, hash1, hashAPIKey("test-key"))
	assert.NotEqual(t, hash1, hashAPIKey("different-key"))
}

func TestValidateAPIKey_SingleFlight(t *testing.T) {
	var callCount atomic.Int32
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		<-release // Hold the response so all clients pile up on one in-flight call
		json.NewEncoder(w).Encode(AuthResponse{Valid: true})
	}))
	defer server.Close()

	auth, err := NewAuthenticator(server.URL, "test-token")
	require.NoError(t, err)

	const concurrency = 10
	var wg sync.WaitGroup
	results := make([]bool, concurrency)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			valid, err := auth.ValidateAPIKey(context.Background(), "shared-key")
			assert.NoError(t, err)
			results[i] = valid
		}(i)
	}

	// Give the goroutines a moment to reach the in-flight call, then respond.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	// All callers share one upstream validation; latecomers hit the cache.
	assert.Equal(t, int32(1), callCount.Load())
	for i, valid := range results {
		assert.True(t, valid, "request %d should be valid", i)
	}
}

func TestValidateAPIKey_InvalidJSONResponse_FailClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	auth, err := NewAuthenticator(server.URL, "test-token")
	require.NoError(t, err)

	valid, err := auth.ValidateAPIKey(context.Background(), "test-key")
	require.Error(t, err)
	assert.False(t, valid)
}

func TestValidateAPIKey_InvalidJSONResponse_FailOpen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	config := AuthenticatorConfig{
		AuthServiceURL:   server.URL,
		AuthServiceToken: "test-token",
		FailOpen:         true,
	}
	auth, err := NewAuthenticatorWithConfig(config)
	require.NoError(t, err)

	valid, err := auth.ValidateAPIKey(context.Background(), "test-key")
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestValidateAPIKey_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // Simulate slow response
		resp := AuthResponse{Valid: true}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := AuthenticatorConfig{
		AuthServiceURL:   server.URL,
		AuthServiceToken: "test-token",
		HTTPTimeout:      50 * time.Millisecond,
		FailOpen:         true,
	}
	auth, err := NewAuthenticatorWithConfig(config)
	require.NoError(t, err)

	valid, err := auth.ValidateAPIKey(context.Background(), "test-key")
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestClose(t *testing.T) {
	auth, err := NewAuthenticator("http://example.com", "test-token")
	require.NoError(t, err)

	err = auth.Close()
	assert.NoError(t, err)
}
