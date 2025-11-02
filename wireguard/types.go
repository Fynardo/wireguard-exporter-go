package wireguard

import "time"

// Interface represents a WireGuard interface with its configuration and peers
type Interface struct {
	Name         string
	PublicKey    string
	ListeningPort int
	Peers        []Peer
}

// Peer represents a WireGuard peer connection
type Peer struct {
	PublicKey      string
	Endpoint       string // IP:port or empty if not connected
	AllowedIPs     []string
	LatestHandshake time.Time // Zero value if never connected
	BytesSent      uint64
	BytesReceived  uint64
}

