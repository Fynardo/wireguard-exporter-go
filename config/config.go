package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Configuration priority: CLI flags > ENV vars > config file
func LoadConfig() (*Config, error) {
	cfg := DefaultConfig()

	// Define all flags first
	var configFile string
	flag.StringVar(&configFile, "config", "", "Path to configuration file (JSON, YAML, or TOML)")
	
	var denylist string
	var listenAddr string
	var metricsPath string
	var wgCommandPath string
	var showEndpoints bool
	
	flag.StringVar(&denylist, "interfaces-denylist", "", "Comma-separated list of interfaces to exclude (overrides config file and env)")
	flag.StringVar(&listenAddr, "listen-address", "", "Address to listen on for metrics endpoint (overrides config file and env)")
	flag.StringVar(&metricsPath, "metrics-path", "", "Path for metrics endpoint (overrides config file and env)")
	flag.StringVar(&wgCommandPath, "wg-command-path", "", "Path to wg command (overrides config file and env)")
	flag.BoolVar(&showEndpoints, "show-endpoints", false, "Show peer endpoints in metrics (overrides config file and env)")

	flag.Parse()

	// 1: Load from config file (lowest priority)
	if configFile != "" {
		if err := loadConfigFile(cfg, configFile); err != nil {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
	}

	// 2: Load from environment variables (medium priority)
	loadFromEnv(cfg)

	// 3: Apply CLI flags (highest priority) - only if they were set
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "interfaces-denylist":
			cfg.InterfacesDenylist = strings.Split(denylist, ",")
			for i := range cfg.InterfacesDenylist {
				cfg.InterfacesDenylist[i] = strings.TrimSpace(cfg.InterfacesDenylist[i])
			}
		case "listen-address":
			cfg.ListenAddress = listenAddr
		case "metrics-path":
			cfg.MetricsPath = metricsPath
		case "wg-command-path":
			cfg.WGCommandPath = wgCommandPath
		case "show-endpoints":
			cfg.ShowEndpoints = showEndpoints
		}
	})

	slog.Info("Configuration loaded", "listen_address", cfg.ListenAddress, "metrics_path", cfg.MetricsPath)
	return cfg, nil
}

func loadConfigFile(cfg *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, cfg)
}

func loadFromEnv(cfg *Config) {
	if val := os.Getenv("WG_LISTEN_ADDRESS"); val != "" {
		cfg.ListenAddress = val
	}
	if val := os.Getenv("WG_METRICS_PATH"); val != "" {
		cfg.MetricsPath = val
	}
	if val := os.Getenv("WG_INTERFACES_DENYLIST"); val != "" {
		cfg.InterfacesDenylist = strings.Split(val, ",")
		for i := range cfg.InterfacesDenylist {
			cfg.InterfacesDenylist[i] = strings.TrimSpace(cfg.InterfacesDenylist[i])
		}
	}
	if val := os.Getenv("WG_COMMAND_PATH"); val != "" {
		cfg.WGCommandPath = val
	}
	if val := os.Getenv("WG_SHOW_ENDPOINTS"); val != "" {
		cfg.ShowEndpoints = strings.ToLower(val) == "true" || val == "1"
	}
	// Interface labels from env would need a specific format, skipping for now
}


