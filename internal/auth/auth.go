package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/crypto/blake2b"
)

// CacheEntry represents a cached validation result
type CacheEntry struct {
	Valid      bool
	Expiration time.Time
}

// AuthRequest represents the request to the auth service
type AuthRequest struct {
	KeySecret string `json:"key_secret"`
}

// AuthResponse represents the response from the auth service
type AuthResponse struct {
	Valid bool `json:"valid"`
}

type Authenticator struct {
	authServiceURL   string
	authServiceToken string
	httpClient       *http.Client
	cache            *lru.Cache[string, *CacheEntry]
	cacheExpiration  time.Duration
	failOpen         bool
}

// AuthenticatorConfig contains configuration for the authenticator
type AuthenticatorConfig struct {
	AuthServiceURL   string
	AuthServiceToken string
	CacheExpiration  time.Duration
	HTTPTimeout      time.Duration
	CacheSize        int  // Maximum number of entries in cache (default: 10000)
	FailOpen         bool // Allow requests when auth service is down (default: true)
}

func NewAuthenticator(authServiceURL, authServiceToken string) (*Authenticator, error) {
	config := AuthenticatorConfig{
		AuthServiceURL:   authServiceURL,
		AuthServiceToken: authServiceToken,
		CacheExpiration:  5 * time.Minute,
		HTTPTimeout:      5 * time.Second,
		CacheSize:        10000,
		FailOpen:         false,
	}
	return NewAuthenticatorWithConfig(config)
}

func NewAuthenticatorWithConfig(config AuthenticatorConfig) (*Authenticator, error) {
	// Set defaults
	if config.CacheExpiration == 0 {
		config.CacheExpiration = 5 * time.Minute
	}
	if config.HTTPTimeout == 0 {
		config.HTTPTimeout = 5 * time.Second
	}
	if config.CacheSize == 0 {
		config.CacheSize = 10000
	}

	httpClient := &http.Client{
		Timeout: config.HTTPTimeout,
	}

	// Create LRU cache with size limit
	cache, err := lru.New[string, *CacheEntry](config.CacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create LRU cache: %v", err)
	}

	auth := &Authenticator{
		authServiceURL:   config.AuthServiceURL,
		authServiceToken: config.AuthServiceToken,
		httpClient:       httpClient,
		cache:            cache,
		cacheExpiration:  config.CacheExpiration,
		failOpen:         config.FailOpen,
	}

	return auth, nil
}

func (a *Authenticator) ValidateAPIKey(ctx context.Context, apiKey string) (bool, error) {
	if apiKey == "" {
		return false, nil
	}

	// Hash the API key for caching
	hash, err := a.hashAPIKey(apiKey)
	if err != nil {
		return false, fmt.Errorf("failed to hash API key: %v", err)
	}

	// Check cache first
	if cacheEntry, exists := a.cache.Get(hash); exists {
		// Check if entry has expired
		if time.Now().Before(cacheEntry.Expiration) {
			return cacheEntry.Valid, nil
		}
		// Entry expired, remove it
		a.cache.Remove(hash)
	}

	// Try to validate with HTTP
	valid, err := a.validateWithHTTP(ctx, apiKey)
	if err != nil {
		if a.failOpen {
			// Auth service call failed, allow the request to pass through
			log.Printf("Auth service call failed, allowing request to pass (fail_open=true): %v", err)
			return true, nil
		} else {
			// Auth service call failed, reject the request
			log.Printf("Auth service call failed, rejecting request (fail_open=false): %v", err)
			return false, err
		}
	}

	// Cache the result (LRU will handle eviction if cache is full)
	a.cache.Add(hash, &CacheEntry{
		Valid:      valid,
		Expiration: time.Now().Add(a.cacheExpiration),
	})

	return valid, nil
}

func (a *Authenticator) hashAPIKey(apiKey string) (string, error) {
	hasher, err := blake2b.New256(nil)
	if err != nil {
		return "", err
	}

	hasher.Write([]byte(apiKey))
	hash := hasher.Sum(nil)

	return fmt.Sprintf("%x", hash), nil
}

func (a *Authenticator) validateWithHTTP(ctx context.Context, apiKey string) (bool, error) {
	req := AuthRequest{
		KeySecret: apiKey,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request: %v", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", a.authServiceURL+"/validate", bytes.NewBuffer(reqBody))
	if err != nil {
		return false, fmt.Errorf("failed to create HTTP request: %v", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+a.authServiceToken)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("auth service returned status %d", resp.StatusCode)
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return false, fmt.Errorf("failed to decode response: %v", err)
	}

	return authResp.Valid, nil
}

func (a *Authenticator) Close() error {
	// Clean up resources - no external connections to close
	return nil
}
