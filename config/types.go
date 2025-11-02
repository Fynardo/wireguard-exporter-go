package config

type Config struct {
	ListenAddress     string            `json:"listen_address"`
	MetricsPath       string            `json:"metrics_path"`
	InterfacesDenylist []string         `json:"interfaces_denylist"`
	InterfaceLabels   map[string]map[string]string `json:"interface_labels"`
	WGCommandPath     string            `json:"wg_command_path"`
	ShowEndpoints     bool              `json:"show_endpoints"`
}

func DefaultConfig() *Config {
	return &Config{
		ListenAddress:     ":9586",
		MetricsPath:       "/metrics",
		InterfacesDenylist: []string{},
		InterfaceLabels:   make(map[string]map[string]string),
		WGCommandPath:     "wg",
		ShowEndpoints:     true,
	}
}

