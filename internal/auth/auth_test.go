package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	auth, err := NewAuthenticator("http://example.com", "test-token")
	require.NoError(t, err)

	hash1, err := auth.hashAPIKey("test-key")
	require.NoError(t, err)
	assert.NotEmpty(t, hash1)

	hash2, err := auth.hashAPIKey("test-key")
	require.NoError(t, err)
	assert.Equal(t, hash1, hash2)

	hash3, err := auth.hashAPIKey("different-key")
	require.NoError(t, err)
	assert.NotEqual(t, hash1, hash3)
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
