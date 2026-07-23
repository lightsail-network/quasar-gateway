package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"quasar-gateway/config"
	"quasar-gateway/internal/auth"
	"quasar-gateway/internal/health"
	"quasar-gateway/internal/rpc"
	"quasar-gateway/internal/s3"
)

// Gateway ties one backend (RPC or S3) together with API key authentication
// and a health check server on a separate port.
type Gateway struct {
	config        *config.Config
	authenticator *auth.Authenticator
	healthChecker health.HealthChecker
	backend       http.Handler // *rpc.RPCProxy or *s3.S3Proxy
	server        *http.Server
	healthServer  *http.Server
	isHealthy     atomic.Bool
}

// New assembles a gateway from cfg. Missing values are defaulted, but cfg is
// expected to have been validated (config.LoadConfig does both).
func New(cfg *config.Config) (*Gateway, error) {
	cfg.ApplyDefaults()

	gateway := &Gateway{
		config: cfg,
	}
	gateway.isHealthy.Store(true) // Start as healthy

	if cfg.AuthEnabled() {
		authConfig := auth.AuthenticatorConfig{
			AuthServiceURL:   cfg.Auth.ServiceURL,
			AuthServiceToken: cfg.Auth.ServiceToken,
			CacheExpiration:  time.Duration(cfg.Auth.CacheExpiration) * time.Second,
			HTTPTimeout:      time.Duration(cfg.Auth.HTTPTimeout) * time.Second,
			CacheSize:        cfg.Auth.CacheSize,
			FailOpen:         cfg.Auth.FailOpen,
		}

		slog.Info("authenticator configured",
			"auth_service_url", authConfig.AuthServiceURL,
			"cache_size", authConfig.CacheSize,
			"cache_expiration", authConfig.CacheExpiration,
			"fail_open", authConfig.FailOpen)

		authenticator, err := auth.NewAuthenticatorWithConfig(authConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create authenticator: %v", err)
		}
		gateway.authenticator = authenticator
	} else {
		slog.Warn("authentication disabled: gateway is open, all requests are proxied without an API key")
	}

	slog.Info("gateway type", "type", cfg.Server.Type)

	var extractKey keyExtractor
	switch cfg.Server.Type {
	case config.GatewayTypeRPC:
		proxy, err := rpc.NewRPCProxy(cfg.RPC.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to create RPC proxy: %v", err)
		}
		gateway.backend = proxy
		gateway.healthChecker = rpc.NewRPCHealthChecker(cfg.RPC.URL)
		extractKey = pathOrHeaderKey
		slog.Info("RPC proxy configured", "url", cfg.RPC.URL)

	case config.GatewayTypeS3:
		proxy := s3.NewS3Proxy(s3.S3Config{
			Endpoint:    cfg.S3.Endpoint,
			Region:      cfg.S3.Region,
			Bucket:      cfg.S3.Bucket,
			AccessKeyID: cfg.S3.AccessKeyID,
			SecretKey:   cfg.S3.SecretKey,
		})
		gateway.backend = proxy
		gateway.healthChecker = proxy
		extractKey = headerKey
		slog.Info("S3 proxy configured", "bucket", cfg.S3.Bucket, "endpoint", cfg.S3.Endpoint, "region", cfg.S3.Region)

	case config.GatewayTypeHTTP:
		// The RPC proxy is a generic single-host reverse proxy; HTTP mode
		// reuses it and differs only in health checking and key extraction.
		proxy, err := rpc.NewRPCProxy(cfg.HTTP.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP proxy: %v", err)
		}
		gateway.backend = proxy
		gateway.healthChecker = health.NewHTTPStatusChecker(cfg.HTTP.URL, cfg.HTTP.HealthPath)
		// Header-only key extraction: an HTTP backend has real single-segment
		// paths (e.g. /graphql), so URL-token extraction must not eat them.
		extractKey = headerKey
		slog.Info("HTTP proxy configured", "url", cfg.HTTP.URL, "health_path", cfg.HTTP.HealthPath)

	default:
		return nil, fmt.Errorf("unsupported gateway type: %s (must be 'rpc', 's3' or 'http')", cfg.Server.Type)
	}

	// Main server: every path goes through CORS handling — and, unless the
	// gateway is open, API key authentication — to the backend. With auth
	// disabled no key is extracted, so RPC-mode URL-token paths are not
	// rewritten and reach the backend as-is.
	handler := gateway.backend
	if cfg.AuthEnabled() {
		handler = gateway.requireAPIKey(extractKey, handler)
	}
	mux := http.NewServeMux()
	mux.Handle("/", corsMiddleware(handler))

	gateway.server = &http.Server{
		Addr:        fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:     mux,
		ReadTimeout: 30 * time.Second,
		IdleTimeout: 60 * time.Second,
	}
	if cfg.Server.Type == config.GatewayTypeRPC || cfg.Server.Type == config.GatewayTypeHTTP {
		// JSON-RPC and plain-HTTP API exchanges are short-lived, so a write
		// deadline is safe. S3 mode streams arbitrarily large objects:
		// WriteTimeout is measured from the start of the request, so any
		// fixed value would cut off large or slow downloads mid-body. Rely
		// on the client/LB timeouts there instead.
		gateway.server.WriteTimeout = 30 * time.Second
	}

	// Health server (separate port)
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", gateway.handleHealth)

	gateway.healthServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.HealthPort),
		Handler:      healthMux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	return gateway, nil
}

func (g *Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
	// While shutting down, report unhealthy so the load balancer drains
	// traffic away from this instance.
	if !g.isHealthy.Load() {
		writeHealthResponse(w, http.StatusServiceUnavailable, "service shutting down")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := g.healthChecker.CheckHealth(ctx); err != nil {
		slog.Warn("health check failed", "error", err)
		writeHealthResponse(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeHealthResponse(w, http.StatusOK, "")
}

func writeHealthResponse(w http.ResponseWriter, statusCode int, reason string) {
	resp := map[string]string{"status": "healthy"}
	if statusCode != http.StatusOK {
		resp = map[string]string{"status": "unhealthy", "reason": reason}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(resp)
}

// Start runs both servers until SIGINT/SIGTERM, then drains traffic and shuts
// down gracefully. It also returns if either server fails to run.
func (g *Gateway) Start() error {
	slog.Info("starting gateway server", "addr", g.server.Addr)
	slog.Info("starting health server", "addr", g.healthServer.Addr)

	// Server failures (e.g. a busy port) are reported here instead of
	// exiting from inside a goroutine, so cleanup still runs.
	serverErr := make(chan error, 2)

	go func() {
		if err := g.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- fmt.Errorf("gateway server: %w", err)
		}
	}()

	go func() {
		if err := g.healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- fmt.Errorf("health server: %w", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		// One server failed; stop the other and report the failure.
		slog.Error("server failed", "error", err)
		g.isHealthy.Store(false)
		if shutdownErr := g.shutdown(); shutdownErr != nil {
			slog.Error("shutdown after server failure", "error", shutdownErr)
		}
		return err
	case <-quit:
	}

	slog.Info("shutdown signal received, starting graceful shutdown")

	// Mark service as unhealthy to prevent new traffic
	g.isHealthy.Store(false)
	slog.Info("health check marked unhealthy, load balancer will stop sending traffic")

	// Wait for configured time to allow existing requests to complete
	gracefulWait := time.Duration(g.config.Server.GracefulShutdownSec) * time.Second

	slog.Info("waiting for existing requests to complete", "wait", gracefulWait)
	time.Sleep(gracefulWait)

	return g.shutdown()
}

// shutdown stops both servers and closes the authenticator.
func (g *Gateway) shutdown() error {
	slog.Info("starting server shutdown")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var shutdownErr error
	if err := g.server.Shutdown(ctx); err != nil {
		slog.Error("gateway server forced to shutdown", "error", err)
		shutdownErr = err
	}

	if err := g.healthServer.Shutdown(ctx); err != nil {
		slog.Error("health server forced to shutdown", "error", err)
		if shutdownErr == nil {
			shutdownErr = err
		}
	}

	if g.authenticator != nil {
		if err := g.authenticator.Close(); err != nil {
			slog.Error("failed to close authenticator", "error", err)
		}
	}

	slog.Info("servers exited")
	return shutdownErr
}
