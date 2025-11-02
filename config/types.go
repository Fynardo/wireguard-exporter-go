package config

type Config struct {
	ListenAddress     string            `json:"listen_address"`
	MetricsPath       string            `json:"metrics_path"`
	InterfacesDenylist []string         `json:"interfaces_denylist"`
	WGCommandPath     string            `json:"wg_command_path"`
	ShowEndpoints     bool              `json:"show_endpoints"`
	ReadConfigFiles   bool              `json:"read_config_files"` // Enable reading WireGuard config files for display names
	ConfigFilePaths   map[string]string `json:"config_file_paths"` // Map of interface name to config file path
}

func DefaultConfig() *Config {
	return &Config{
		ListenAddress:     ":9586",
		MetricsPath:       "/metrics",
		InterfacesDenylist: []string{},
		WGCommandPath:     "wg",
		ShowEndpoints:     true,
		ReadConfigFiles:   true, // Enable by default
		ConfigFilePaths:   make(map[string]string),
	}
}

