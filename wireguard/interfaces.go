package wireguard

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// Discover all interfaces and filters them using the deny-list
func DiscoverInterfaces(wgCommandPath string, denylist []string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, wgCommandPath, "show", "interfaces")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute wg show interfaces: %w", err)
	}

	// Each line is an interface name
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var interfaces []string
	
	// Create a map for fast denylist lookup
	denyMap := make(map[string]bool)
	for _, denied := range denylist {
		denyMap[denied] = true
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// Validate interface name to prevent command injection
		if !isValidInterfaceName(line) {
			slog.Warn("Invalid interface name detected, skipping", "interface", line)
			continue
		}

		// Check if interface is in deny-list
		if !denyMap[line] {
			interfaces = append(interfaces, line)
		}
	}

	slog.Info("Discovered WireGuard interfaces", "count", len(interfaces), "filtered", len(lines)-len(interfaces))
	return interfaces, nil
}

// isValidInterfaceName validates interface name to prevent command injection
// Interface names should be alphanumeric with underscores and hyphens
func isValidInterfaceName(name string) bool {
	if len(name) == 0 || len(name) > 15 { // Linux interface name limit
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

