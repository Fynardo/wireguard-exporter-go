package wireguard

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func ParseInterfaceData(wgCommandPath, interfaceName string) (*Interface, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Validate interface name for security
	if !isValidInterfaceName(interfaceName) {
		return nil, fmt.Errorf("invalid interface name: %s", interfaceName)
	}

	cmd := exec.CommandContext(ctx, wgCommandPath, "show", interfaceName, "dump")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute wg show %s dump: %w", interfaceName, err)
	}

	outputStr := string(output)

	// Parse the dump format which is tab-separated
	// Format: <interface private key> <interface public key> <listening port> <fwmark>
	// Format per peer: <public key> "(none)" <endpoint> <allowed ips> <last handshake> <rx bytes> <tx bytes> <persistent keepalive>
	
	dumpLines := strings.Split(strings.TrimSpace(outputStr), "\n")
	if len(dumpLines) == 0 {
		return nil, fmt.Errorf("no data returned from wg show")
	}

	// First line is the interface
	interfaceParts := strings.Fields(dumpLines[0])
	if len(interfaceParts) < 4 {
		return nil, fmt.Errorf("invalid interface dump format")
	}

	iface := &Interface{
		Name:         interfaceName,
		PublicKey:    interfaceParts[1],
		ListeningPort: 0,
		Peers:        []Peer{},
	}

	// Parse listening port
	if len(interfaceParts) >= 2 {
		if port, err := strconv.Atoi(interfaceParts[2]); err == nil {
			iface.ListeningPort = port
		}
	}

	slog.Debug("Parsed listening port", "interface", interfaceName, "port", iface.ListeningPort)

	// Remaining lines are peers
	for i := 1; i < len(dumpLines); i++ {
		peerParts := strings.Fields(dumpLines[i])
		if len(peerParts) < 7 {
			continue
		}

		peer := Peer{
			PublicKey:      peerParts[0],
			Endpoint:       "",
			AllowedIPs:     []string{},
			LatestHandshake: time.Time{},
			BytesSent:      0,
			BytesReceived:  0,
		}

		// Parse endpoint (can be empty)
		if peerParts[2] != "(none)" {
			peer.Endpoint = peerParts[2]
		}

		// Parse allowed IPs
		allowedIPs := strings.Split(peerParts[3], ",")
		for _, ip := range allowedIPs {
			peer.AllowedIPs = append(peer.AllowedIPs, strings.TrimSpace(ip))
		}

		// Parse latest handshake (Unix timestamp)
		if peerParts[4] != "0" {
			if timestamp, err := strconv.ParseInt(peerParts[4], 10, 64); err == nil && timestamp > 0 {
				peer.LatestHandshake = time.Unix(timestamp, 0)
			}
		}

		// Parse received bytes
		if bytes, err := strconv.ParseUint(peerParts[5], 10, 64); err == nil {
			peer.BytesReceived = bytes
		}

		// Parse sent bytes
		if bytes, err := strconv.ParseUint(peerParts[6], 10, 64); err == nil {
			peer.BytesSent = bytes
		}

		slog.Debug("Parsed peer data", "interface", interfaceName, "peer", peer)
		iface.Peers = append(iface.Peers, peer)
	}

	slog.Debug("Parsed interface data", "interface", interfaceName, "peers", len(iface.Peers))
	return iface, nil
}

// ParseWireGuardConfigFile parses a WireGuard config file and extracts display names
// mapped by public key. Returns a map of public key -> display name.
func ParseWireGuardConfigFile(configPath string) (map[string]string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	displayNames := make(map[string]string)
	lines := strings.Split(string(data), "\n")
	
	var inPeerSection bool
	var currentPublicKey string
	var currentDisplayName string
	
	// Regex to match "# display-name = <value>" or "#display-name = <value>" (with or without space after #)
	// Supports both "display-name" and "display_name" formats
	displayNameRegex := regexp.MustCompile(`(?i)^\s*#\s*display[-_]name\s*=\s*(.+)$`)
	// Regex to match "PublicKey = <value>"
	publicKeyRegex := regexp.MustCompile(`(?i)^\s*PublicKey\s*=\s*(.+)$`)
	
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		
		// Check if we're entering a [Peer] section
		if strings.HasPrefix(trimmedLine, "[Peer]") {
			// If we were in a previous peer section and found a display name, save it
			if inPeerSection && currentPublicKey != "" && currentDisplayName != "" {
				displayNames[currentPublicKey] = currentDisplayName
			}
			
			inPeerSection = true
			currentPublicKey = ""
			currentDisplayName = ""
			continue
		}
		
		// Check if we're leaving the peer section (entering another section)
		if strings.HasPrefix(trimmedLine, "[") && trimmedLine != "[Peer]" {
			// Save any display name we found before leaving
			if currentPublicKey != "" && currentDisplayName != "" {
				displayNames[currentPublicKey] = currentDisplayName
			}
			inPeerSection = false
			currentPublicKey = ""
			currentDisplayName = ""
			continue
		}
		
		if inPeerSection {
			// Check for display-name comment
			if matches := displayNameRegex.FindStringSubmatch(trimmedLine); matches != nil {
				displayName := strings.TrimSpace(matches[1])
				if displayName != "" {
					currentDisplayName = displayName
					// If we already have the public key, save immediately
					if currentPublicKey != "" {
						displayNames[currentPublicKey] = displayName
					}
				}
			}
			
			// Check for PublicKey
			if matches := publicKeyRegex.FindStringSubmatch(trimmedLine); matches != nil {
				publicKey := strings.TrimSpace(matches[1])
				if publicKey != "" {
					currentPublicKey = publicKey
					// If we already have the display name, save immediately
					if currentDisplayName != "" {
						displayNames[publicKey] = currentDisplayName
					}
				}
			}
		}
	}
	
	// Handle the last peer section if we ended in one
	if inPeerSection && currentPublicKey != "" && currentDisplayName != "" {
		displayNames[currentPublicKey] = currentDisplayName
	}
	
	slog.Debug("Parsed config file", "path", configPath, "display_names_count", len(displayNames))
	return displayNames, nil
}
