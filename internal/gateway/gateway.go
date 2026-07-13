package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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

	authConfig := auth.AuthenticatorConfig{
		AuthServiceURL:   cfg.Auth.ServiceURL,
		AuthServiceToken: cfg.Auth.ServiceToken,
		CacheExpiration:  time.Duration(cfg.Auth.CacheExpiration) * time.Second,
		HTTPTimeout:      time.Duration(cfg.Auth.HTTPTimeout) * time.Second,
		CacheSize:        cfg.Auth.CacheSize,
		FailOpen:         cfg.Auth.FailOpen,
	}

	log.Printf("Auth service URL: %s", authConfig.AuthServiceURL)
	log.Printf("Auth cache: size=%d, expiration=%v", authConfig.CacheSize, authConfig.CacheExpiration)
	if authConfig.FailOpen {
		log.Printf("Auth requests that fail will be allowed to pass through (fail_open=true)")
	} else {
		log.Printf("Auth requests that fail will be rejected (fail_open=false)")
	}

	authenticator, err := auth.NewAuthenticatorWithConfig(authConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticator: %v", err)
	}

	gateway := &Gateway{
		config:        cfg,
		authenticator: authenticator,
	}
	gateway.isHealthy.Store(true) // Start as healthy

	log.Printf("Gateway type: %s", cfg.Server.Type)

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
		log.Printf("RPC proxy configured: %s", cfg.RPC.URL)

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
		log.Printf("S3 proxy configured: bucket=%s, endpoint=%s, region=%s", cfg.S3.Bucket, cfg.S3.Endpoint, cfg.S3.Region)

	default:
		return nil, fmt.Errorf("unsupported gateway type: %s (must be 'rpc' or 's3')", cfg.Server.Type)
	}

	// Main server: every path goes through CORS handling and authentication
	// to the backend.
	mux := http.NewServeMux()
	mux.Handle("/", corsMiddleware(gateway.requireAPIKey(extractKey, gateway.backend)))

	gateway.server = &http.Server{
		Addr:        fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:     mux,
		ReadTimeout: 30 * time.Second,
		IdleTimeout: 60 * time.Second,
	}
	if cfg.Server.Type == config.GatewayTypeRPC {
		// JSON-RPC exchanges are short-lived, so a write deadline is safe.
		// S3 mode streams arbitrarily large objects: WriteTimeout is measured
		// from the start of the request, so any fixed value would cut off
		// large or slow downloads mid-body. Rely on the client/LB timeouts
		// there instead.
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
		log.Printf("Health check failed: %v", err)
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
// down gracefully.
func (g *Gateway) Start() error {
	log.Printf("Starting gateway server on %s", g.server.Addr)
	log.Printf("Starting health server on %s", g.healthServer.Addr)

	// Start main server
	go func() {
		if err := g.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Gateway server failed to start: %v", err)
		}
	}()

	// Start health server
	go func() {
		if err := g.healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Health server failed to start: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutdown signal received, starting graceful shutdown...")

	// Mark service as unhealthy to prevent new traffic
	g.isHealthy.Store(false)
	log.Println("Health check marked as unhealthy, load balancer will stop sending traffic")

	// Wait for configured time to allow existing requests to complete
	gracefulWait := time.Duration(g.config.Server.GracefulShutdownSec) * time.Second

	log.Printf("Waiting %v for existing requests to complete...", gracefulWait)
	time.Sleep(gracefulWait)

	log.Println("Starting server shutdown...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown both servers
	var shutdownErr error
	if err := g.server.Shutdown(ctx); err != nil {
		log.Printf("Gateway server forced to shutdown: %v", err)
		shutdownErr = err
	}

	if err := g.healthServer.Shutdown(ctx); err != nil {
		log.Printf("Health server forced to shutdown: %v", err)
		if shutdownErr == nil {
			shutdownErr = err
		}
	}

	if err := g.authenticator.Close(); err != nil {
		log.Printf("Failed to close authenticator: %v", err)
	}

	log.Println("Servers exited")
	return shutdownErr
}
