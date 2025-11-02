package wireguard

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// Regex patterns for parsing wg show output
	interfacePattern = regexp.MustCompile(`^interface:\s+(.+)$`)
	listeningPortPattern = regexp.MustCompile(`^listening\s+port:\s+(\d+)$`)
	peerPattern = regexp.MustCompile(`^peer:\s+(.+)$`)
	endpointPattern = regexp.MustCompile(`^endpoint:\s+(.+)$`)
	allowedIPsPattern = regexp.MustCompile(`^allowed\s+ips:\s+(.+)$`)
	handshakePattern = regexp.MustCompile(`^latest\s+handshake:\s+(.+)$`)
	transferPattern = regexp.MustCompile(`^transfer:\s+(.+)$`)
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
	// Format: <interface public key> <listening port> <fwmark>
	// Format per peer: <public key> <endpoint> <allowed ips> <last handshake> <rx bytes> <tx bytes> <persistent keepalive>
	
	dumpLines := strings.Split(strings.TrimSpace(outputStr), "\n")
	if len(dumpLines) == 0 {
		return nil, fmt.Errorf("no data returned from wg show")
	}

	// First line is the interface
	interfaceParts := strings.Fields(dumpLines[0])
	if len(interfaceParts) < 2 {
		return nil, fmt.Errorf("invalid interface dump format")
	}

	iface := &Interface{
		Name:         interfaceName,
		PublicKey:    interfaceParts[0],
		ListeningPort: 0,
		Peers:        []Peer{},
	}

	// Parse listening port
	if len(interfaceParts) >= 2 {
		if port, err := strconv.Atoi(interfaceParts[1]); err == nil {
			iface.ListeningPort = port
		}
	}

	slog.Debug("Parsed listening port", "interface", interfaceName, "port", iface.ListeningPort)

	// Remaining lines are peers
	for i := 1; i < len(dumpLines); i++ {
		peerParts := strings.Fields(dumpLines[i])
		if len(peerParts) < 1 {
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
		if len(peerParts) >= 2 && peerParts[1] != "(none)" {
			peer.Endpoint = peerParts[1]
		}

		// Parse allowed IPs
		if len(peerParts) >= 3 {
			allowedIPs := strings.Split(peerParts[2], ",")
			for _, ip := range allowedIPs {
				peer.AllowedIPs = append(peer.AllowedIPs, strings.TrimSpace(ip))
			}
		}

		// Parse latest handshake (Unix timestamp)
		if len(peerParts) >= 4 && peerParts[3] != "0" {
			if timestamp, err := strconv.ParseInt(peerParts[3], 10, 64); err == nil && timestamp > 0 {
				peer.LatestHandshake = time.Unix(timestamp, 0)
			}
		}

		// Parse received bytes
		if len(peerParts) >= 5 {
			if bytes, err := strconv.ParseUint(peerParts[4], 10, 64); err == nil {
				peer.BytesReceived = bytes
			}
		}

		// Parse sent bytes
		if len(peerParts) >= 6 {
			if bytes, err := strconv.ParseUint(peerParts[5], 10, 64); err == nil {
				peer.BytesSent = bytes
			}
		}

		slog.Debug("Parsed peer data", "interface", interfaceName, "peer", peer)
		iface.Peers = append(iface.Peers, peer)
	}

	slog.Debug("Parsed interface data", "interface", interfaceName, "peers", len(iface.Peers))
	return iface, nil
}

func ParseHandshakeTime(timeStr string) (time.Time, int64, error) {
	// Remove "ago" suffix
	timeStr = strings.TrimSuffix(strings.ToLower(timeStr), " ago")
	timeStr = strings.TrimSpace(timeStr)

	var totalDuration time.Duration

	// Parse days
	if days := regexp.MustCompile(`(\d+)\s+day`).FindStringSubmatch(timeStr); days != nil {
		if d, err := strconv.Atoi(days[1]); err == nil {
			totalDuration += time.Duration(d) * 24 * time.Hour
		}
	}

	// Parse hours
	if hours := regexp.MustCompile(`(\d+)\s+hour`).FindStringSubmatch(timeStr); hours != nil {
		if h, err := strconv.Atoi(hours[1]); err == nil {
			totalDuration += time.Duration(h) * time.Hour
		}
	}

	// Parse minutes
	if minutes := regexp.MustCompile(`(\d+)\s+minute`).FindStringSubmatch(timeStr); minutes != nil {
		if m, err := strconv.Atoi(minutes[1]); err == nil {
			totalDuration += time.Duration(m) * time.Minute
		}
	}

	// Parse seconds
	if seconds := regexp.MustCompile(`(\d+)\s+second`).FindStringSubmatch(timeStr); seconds != nil {
		if s, err := strconv.Atoi(seconds[1]); err == nil {
			totalDuration += time.Duration(s) * time.Second
		}
	}

	handshakeTime := time.Now().Add(-totalDuration)
	ageSeconds := int64(totalDuration.Seconds())

	return handshakeTime, ageSeconds, nil
}

func ParseTransferStats(transferStr string) (uint64, uint64, error) {
	// This is a fallback for non-dump format. The dump format already provides bytes directly.
	// But we'll implement this in case we need to parse the human-readable format
	var received, sent uint64
	var err error

	receivedPattern := regexp.MustCompile(`([\d.]+)\s+([KMGT]?i?B)\s+received`)
	sentPattern := regexp.MustCompile(`([\d.]+)\s+([KMGT]?i?B)\s+sent`)

	if match := receivedPattern.FindStringSubmatch(strings.ToLower(transferStr)); match != nil {
		received, err = parseSize(match[1], match[2])
		if err != nil {
			return 0, 0, err
		}
	}

	if match := sentPattern.FindStringSubmatch(strings.ToLower(transferStr)); match != nil {
		sent, err = parseSize(match[1], match[2])
		if err != nil {
			return 0, 0, err
		}
	}

	return received, sent, nil
}

func parseSize(valueStr, unit string) (uint64, error) {
	value, err := strconv.ParseFloat(valueStr, 64)
	if err != nil {
		return 0, err
	}

	var multiplier uint64 = 1
	switch strings.ToUpper(unit) {
	case "B":
		multiplier = 1
	case "KB", "KIB":
		multiplier = 1024
	case "MB", "MIB":
		multiplier = 1024 * 1024
	case "GB", "GIB":
		multiplier = 1024 * 1024 * 1024
	case "TB", "TIB":
		multiplier = 1024 * 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("unknown unit: %s", unit)
	}

	return uint64(value * float64(multiplier)), nil
}

