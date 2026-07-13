package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sync/singleflight"
)

// AuthRequest represents the request to the auth service
type AuthRequest struct {
	KeySecret string `json:"key_secret"`
}

// AuthResponse represents the response from the auth service
type AuthResponse struct {
	Valid bool `json:"valid"`
}

// errAuthRejected marks responses where the auth service explicitly rejected
// the request (4xx status). The fail-open policy only covers the service
// being unreachable or broken, so it must never apply to these.
var errAuthRejected = errors.New("auth service rejected the request")

type Authenticator struct {
	authServiceURL   string
	authServiceToken string
	httpClient       *http.Client
	cache            *expirable.LRU[string, bool]
	cacheExpiration  time.Duration
	failOpen         bool
	group            singleflight.Group
}

// AuthenticatorConfig contains configuration for the authenticator
type AuthenticatorConfig struct {
	AuthServiceURL   string
	AuthServiceToken string
	CacheExpiration  time.Duration
	HTTPTimeout      time.Duration
	CacheSize        int  // Maximum number of entries in cache (default: 10000)
	FailOpen         bool // Allow requests when auth service is down (default: false)
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

	auth := &Authenticator{
		authServiceURL:   config.AuthServiceURL,
		authServiceToken: config.AuthServiceToken,
		httpClient:       &http.Client{Timeout: config.HTTPTimeout},
		cache:            expirable.NewLRU[string, bool](config.CacheSize, nil, config.CacheExpiration),
		cacheExpiration:  config.CacheExpiration,
		failOpen:         config.FailOpen,
	}

	return auth, nil
}

func (a *Authenticator) ValidateAPIKey(ctx context.Context, apiKey string) (bool, error) {
	if apiKey == "" {
		return false, nil
	}

	// Cache by hash so raw API keys are never kept in memory
	hash := hashAPIKey(apiKey)

	if valid, ok := a.cache.Get(hash); ok {
		return valid, nil
	}

	// Collapse concurrent validations of the same key into a single call to
	// the auth service, so a cache miss under load cannot stampede it.
	result, err, _ := a.group.Do(hash, func() (interface{}, error) {
		if valid, ok := a.cache.Get(hash); ok {
			return valid, nil
		}

		// Detach from the individual request context: the result is shared
		// with other in-flight requests, so one canceled request must not
		// fail all of them. The HTTP client timeout still applies.
		valid, err := a.validateWithHTTP(context.WithoutCancel(ctx), apiKey)
		if err != nil {
			return false, err
		}

		a.cache.Add(hash, valid)
		return valid, nil
	})

	if err != nil {
		if errors.Is(err, errAuthRejected) {
			// The auth service is up and explicitly rejected the request,
			// so fail-open does not apply.
			log.Printf("Auth service rejected request: %v", err)
			return false, nil
		}
		if a.failOpen {
			// Auth service call failed, allow the request to pass through
			log.Printf("Auth service call failed, allowing request to pass (fail_open=true): %v", err)
			return true, nil
		}
		// Auth service call failed, reject the request
		log.Printf("Auth service call failed, rejecting request (fail_open=false): %v", err)
		return false, err
	}

	return result.(bool), nil
}

func hashAPIKey(apiKey string) string {
	hash := blake2b.Sum256([]byte(apiKey))
	return fmt.Sprintf("%x", hash)
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

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return false, fmt.Errorf("%w: status %d", errAuthRejected, resp.StatusCode)
	}
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
