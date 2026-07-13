package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"quasar-gateway/config"
	"quasar-gateway/internal/gateway"
)

func main() {
	var configPath string
	var showHelp bool

	flag.StringVar(&configPath, "config", getDefaultConfigPath(), "Path to configuration file")
	flag.BoolVar(&showHelp, "help", false, "Show help message")
	flag.Parse()

	if showHelp {
		showUsage()
		return
	}

	// LoadConfig also applies QUASAR_* environment overrides, defaults, and
	// validation.
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	gw, err := gateway.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create gateway: %v", err)
	}

	if err := gw.Start(); err != nil {
		log.Fatalf("Failed to start gateway: %v", err)
	}
}

func getDefaultConfigPath() string {
	if envPath := os.Getenv("QUASAR_CONFIG_PATH"); envPath != "" {
		return envPath
	}
	return "config.toml"
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
	fmt.Print(config.EnvUsage())
	fmt.Println()
	fmt.Println("    See README.md for detailed configuration options.")
}
