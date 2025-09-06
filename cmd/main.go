package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"quasar-gateway/config"
	"quasar-gateway/internal/auth"
	"quasar-gateway/internal/health"
	"quasar-gateway/internal/rpc"
	"quasar-gateway/internal/s3"
)

type Gateway struct {
	config        *config.Config
	authenticator *auth.Authenticator
	healthChecker health.HealthChecker
	rpcProxy      *rpc.RPCProxy
	s3Proxy       *s3.S3Proxy
	server        *http.Server
	healthServer  *http.Server
	isHealthy     bool
}

func main() {
	var configPath string
	var showHelp bool

	// Check for environment variable first
	if envConfigPath := os.Getenv("QUASAR_CONFIG_PATH"); envConfigPath != "" {
		configPath = envConfigPath
	}

	flag.StringVar(&configPath, "config", getDefaultConfigPath(), "Path to configuration file")
	flag.BoolVar(&showHelp, "help", false, "Show help message")
	flag.Parse()

	if showHelp {
		showUsage()
		return
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Override config values with environment variables if present
	overrideConfigFromEnv(cfg)

	gateway, err := NewGateway(cfg)
	if err != nil {
		log.Fatalf("Failed to create gateway: %v", err)
	}

	if err := gateway.Start(); err != nil {
		log.Fatalf("Failed to start gateway: %v", err)
	}
}

func getDefaultConfigPath() string {
	if envPath := os.Getenv("QUASAR_CONFIG_PATH"); envPath != "" {
		return envPath
	}
	return "config.toml"
}

func overrideConfigFromEnv(cfg *config.Config) {
	// Server configuration
	if host := os.Getenv("QUASAR_SERVER_HOST"); host != "" {
		cfg.Server.Host = host
	}
	if port := os.Getenv("QUASAR_SERVER_PORT"); port != "" {
		if p, err := fmt.Sscanf(port, "%d", &cfg.Server.Port); err == nil && p == 1 {
			// Port parsed successfully
		}
	}
	if healthPort := os.Getenv("QUASAR_SERVER_HEALTH_PORT"); healthPort != "" {
		if hp, err := fmt.Sscanf(healthPort, "%d", &cfg.Server.HealthPort); err == nil && hp == 1 {
			// Health port parsed successfully
		}
	}
	if gracefulShutdown := os.Getenv("QUASAR_SERVER_GRACEFUL_SHUTDOWN_SEC"); gracefulShutdown != "" {
		if gs, err := fmt.Sscanf(gracefulShutdown, "%d", &cfg.Server.GracefulShutdownSec); err == nil && gs == 1 {
			// Graceful shutdown time parsed successfully
		}
	}

	// Server type configuration
	if serverType := os.Getenv("QUASAR_SERVER_TYPE"); serverType != "" {
		cfg.Server.Type = serverType
	}

	// RPC configuration
	if rpcURL := os.Getenv("QUASAR_RPC_URL"); rpcURL != "" {
		cfg.RPC.URL = rpcURL
	}

	// S3 configuration
	if s3Endpoint := os.Getenv("QUASAR_S3_ENDPOINT"); s3Endpoint != "" {
		cfg.S3.Endpoint = s3Endpoint
	}
	if s3Region := os.Getenv("QUASAR_S3_REGION"); s3Region != "" {
		cfg.S3.Region = s3Region
	}
	if s3Bucket := os.Getenv("QUASAR_S3_BUCKET"); s3Bucket != "" {
		cfg.S3.Bucket = s3Bucket
	}
	if s3AccessKeyID := os.Getenv("QUASAR_S3_ACCESS_KEY_ID"); s3AccessKeyID != "" {
		cfg.S3.AccessKeyID = s3AccessKeyID
	}
	if s3SecretKey := os.Getenv("QUASAR_S3_SECRET_KEY"); s3SecretKey != "" {
		cfg.S3.SecretKey = s3SecretKey
	}

	// Auth configuration
	if authURL := os.Getenv("QUASAR_AUTH_SERVICE_URL"); authURL != "" {
		cfg.Auth.ServiceURL = authURL
	}
	if authToken := os.Getenv("QUASAR_AUTH_SERVICE_TOKEN"); authToken != "" {
		cfg.Auth.ServiceToken = authToken
	}
	if cacheExp := os.Getenv("QUASAR_AUTH_CACHE_EXPIRATION"); cacheExp != "" {
		if exp, err := fmt.Sscanf(cacheExp, "%d", &cfg.Auth.CacheExpiration); err == nil && exp == 1 {
			// Cache expiration parsed successfully
		}
	}
	if httpTimeout := os.Getenv("QUASAR_AUTH_HTTP_TIMEOUT"); httpTimeout != "" {
		if timeout, err := fmt.Sscanf(httpTimeout, "%d", &cfg.Auth.HTTPTimeout); err == nil && timeout == 1 {
			// HTTP timeout parsed successfully
		}
	}
	if cacheSize := os.Getenv("QUASAR_AUTH_CACHE_SIZE"); cacheSize != "" {
		if size, err := fmt.Sscanf(cacheSize, "%d", &cfg.Auth.CacheSize); err == nil && size == 1 {
			// Cache size parsed successfully
		}
	}
	if failOpen := os.Getenv("QUASAR_AUTH_FAIL_OPEN"); failOpen != "" {
		cfg.Auth.FailOpen = failOpen == "true" || failOpen == "1"
	}
}

func showUsage() {
	fmt.Println("Quasar Gateway - High-performance RPC gateway with API key authentication")
	fmt.Println()
	fmt.Println("USAGE:")
	fmt.Println("    gateway [OPTIONS]")
	fmt.Println()
	fmt.Println("OPTIONS:")
	fmt.Println("    --config <file>    Path to configuration file (default: config.toml)")
	fmt.Println("    --help            Show this help message")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Println("    gateway                           # Use default config.toml")
	fmt.Println("    gateway --config /path/to/config.toml")
	fmt.Println("    QUASAR_CONFIG_PATH=/etc/quasar-gateway/config.toml gateway")
	fmt.Println("    gateway --help                    # Show help")
	fmt.Println()
	fmt.Println("CONFIGURATION:")
	fmt.Println("    Create a TOML configuration file with server, rpc, and auth sections.")
	fmt.Println("    Configuration values can be overridden using environment variables:")
	fmt.Println()
	fmt.Println("    QUASAR_CONFIG_PATH         - Path to configuration file")
	fmt.Println("    QUASAR_SERVER_HOST         - Server host (e.g., 0.0.0.0)")
	fmt.Println("    QUASAR_SERVER_PORT         - Server port (e.g., 8080)")
	fmt.Println("    QUASAR_SERVER_HEALTH_PORT  - Health check server port (e.g., 8081)")
	fmt.Println("    QUASAR_SERVER_GRACEFUL_SHUTDOWN_SEC - Graceful shutdown wait time (e.g., 30)")
	fmt.Println("    QUASAR_SERVER_TYPE         - Gateway type (rpc or s3)")
	fmt.Println("    QUASAR_RPC_URL            - RPC server URL")
	fmt.Println("    QUASAR_S3_ENDPOINT        - S3 endpoint URL")
	fmt.Println("    QUASAR_S3_REGION          - S3 region")
	fmt.Println("    QUASAR_S3_BUCKET          - S3 bucket name")
	fmt.Println("    QUASAR_S3_ACCESS_KEY_ID   - S3 access key ID")
	fmt.Println("    QUASAR_S3_SECRET_KEY      - S3 secret access key")
	fmt.Println("    QUASAR_AUTH_SERVICE_URL   - Auth service URL")
	fmt.Println("    QUASAR_AUTH_SERVICE_TOKEN - Auth service token")
	fmt.Println("    QUASAR_AUTH_CACHE_EXPIRATION - Auth cache expiration (seconds)")
	fmt.Println("    QUASAR_AUTH_HTTP_TIMEOUT  - Auth HTTP timeout (seconds)")
	fmt.Println("    QUASAR_AUTH_CACHE_SIZE    - Auth cache size (max entries)")
	fmt.Println("    QUASAR_AUTH_FAIL_OPEN     - Allow requests when auth service is down (default: false)")
	fmt.Println()
	fmt.Println("    See README.md for detailed configuration options.")
}

func NewGateway(cfg *config.Config) (*Gateway, error) {
	// Create authenticator configuration
	authConfig := auth.AuthenticatorConfig{
		AuthServiceURL:   cfg.Auth.ServiceURL,
		AuthServiceToken: cfg.Auth.ServiceToken,
		CacheExpiration:  time.Duration(cfg.Auth.CacheExpiration) * time.Second,
		HTTPTimeout:      time.Duration(cfg.Auth.HTTPTimeout) * time.Second,
		CacheSize:        cfg.Auth.CacheSize,
		FailOpen:         cfg.Auth.FailOpen,
	}

	// Set defaults if not specified
	if authConfig.CacheExpiration == 0 {
		authConfig.CacheExpiration = 5 * time.Minute
	}
	if authConfig.HTTPTimeout == 0 {
		authConfig.HTTPTimeout = 5 * time.Second
	}
	if authConfig.CacheSize == 0 {
		authConfig.CacheSize = 10000
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

	// Set default gateway type
	gatewayType := cfg.Server.Type
	if gatewayType == "" {
		gatewayType = "rpc"
	}

	log.Printf("Gateway type: %s", gatewayType)

	// Create appropriate components based on gateway type
	var healthChecker health.HealthChecker
	var rpcProxy *rpc.RPCProxy
	var s3Proxy *s3.S3Proxy

	switch gatewayType {
	case "rpc":
		healthChecker = rpc.NewRPCHealthChecker(cfg.RPC.URL)
		var err error
		rpcProxy, err = rpc.NewRPCProxy(cfg.RPC.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to create RPC proxy: %v", err)
		}
		log.Printf("RPC proxy configured: %s", cfg.RPC.URL)

	case "s3":
		// Create S3 proxy and health checker
		s3Config := s3.S3Config{
			Endpoint:    cfg.S3.Endpoint,
			Region:      cfg.S3.Region,
			Bucket:      cfg.S3.Bucket,
			AccessKeyID: cfg.S3.AccessKeyID,
			SecretKey:   cfg.S3.SecretKey,
		}
		s3Proxy = s3.NewS3Proxy(s3Config)
		healthChecker = s3.NewS3HealthChecker(s3Proxy)

		log.Printf("S3 proxy configured: bucket=%s, endpoint=%s, region=%s", cfg.S3.Bucket, cfg.S3.Endpoint, cfg.S3.Region)

	default:
		return nil, fmt.Errorf("unsupported gateway type: %s (must be 'rpc' or 's3')", gatewayType)
	}

	gateway := &Gateway{
		config:        cfg,
		authenticator: authenticator,
		healthChecker: healthChecker,
		rpcProxy:      rpcProxy,
		s3Proxy:       s3Proxy,
		isHealthy:     true, // Start as healthy
	}

	// Main server
	mux := http.NewServeMux()

	// Configure routes based on gateway type
	switch gatewayType {
	case "rpc":
		// RPC proxy for all paths
		mux.HandleFunc("/", gateway.handleProxy)
		log.Println("RPC proxy routes registered at /*")

	case "s3":
		// S3 file access for all paths
		mux.HandleFunc("/", gateway.handleS3)
		log.Println("S3 proxy routes registered at /*")
	}

	gateway.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Health server (separate port)
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/health", gateway.handleHealth)

	// Set default health port if not specified
	healthPort := cfg.Server.HealthPort
	if healthPort == 0 {
		healthPort = cfg.Server.Port + 1 // Default to main port + 1
	}

	gateway.healthServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, healthPort),
		Handler:      healthMux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	return gateway, nil
}

func (g *Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Check if service is marked as unhealthy (shutting down)
	if !g.isHealthy {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"unhealthy","reason":"service shutting down"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// For RPC mode, check backend RPC health
	if g.healthChecker != nil {
		statusCode, body, err := g.healthChecker.CheckHealth()
		if err != nil {
			log.Printf("Health check failed: %v", err)
		}
		w.WriteHeader(statusCode)
		if body != nil {
			w.Write(body)
		}
		return
	}

	// For R2 mode, just return healthy (no backend to check)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy"}`))
}

func (g *Gateway) handleS3(w http.ResponseWriter, r *http.Request) {
	// Skip authentication for CORS preflight requests
	if r.Method == "OPTIONS" {
		g.s3Proxy.ServeHTTP(w, r)
		return
	}

	// Extract API key from Authorization header
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}

	apiKey := strings.TrimPrefix(auth, "Bearer ")
	if apiKey == "" {
		http.Error(w, "Empty API key", http.StatusUnauthorized)
		return
	}

	isAuthenticated, err := g.authenticator.ValidateAPIKey(r.Context(), apiKey)
	if err != nil {
		log.Printf("Authentication error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if !isAuthenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	g.s3Proxy.ServeHTTP(w, r)
}

func (g *Gateway) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Skip authentication for CORS preflight requests
	if r.Method == "OPTIONS" {
		g.rpcProxy.ServeHTTP(w, r)
		return
	}

	var apiKey string

	// Try to extract API key from URL path first (format: /token)
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path != "" && !strings.Contains(path, "/") {
		// Path contains only the token, no additional path segments
		apiKey = path
		// Modify the request path to root for the backend
		r.URL.Path = "/"
	} else {
		// Fall back to Authorization header
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "Missing or invalid Authorization header or token in URL path", http.StatusUnauthorized)
			return
		}
		apiKey = strings.TrimPrefix(auth, "Bearer ")
	}

	if apiKey == "" {
		http.Error(w, "Empty API key", http.StatusUnauthorized)
		return
	}

	isAuthenticated, err := g.authenticator.ValidateAPIKey(r.Context(), apiKey)
	if err != nil {
		log.Printf("Authentication error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if !isAuthenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	g.rpcProxy.ServeHTTP(w, r)
}

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
	g.isHealthy = false
	log.Println("Health check marked as unhealthy, load balancer will stop sending traffic")

	// Wait for configured time to allow existing requests to complete
	gracefulWait := time.Duration(g.config.Server.GracefulShutdownSec) * time.Second
	if gracefulWait == 0 {
		gracefulWait = 30 * time.Second // Default 30 seconds
	}

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
