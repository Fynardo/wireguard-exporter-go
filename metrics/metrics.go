package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metric descriptors
var (
	PeersTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "wireguard_peers_total",
			Help: "Number of configured peers per WireGuard interface",
		},
		[]string{"interface"},
	)

	PeerLatestHandshakeSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "wireguard_peer_latest_handshake_seconds",
			Help: "Unix timestamp of the latest handshake per peer",
		},
		[]string{"interface", "peer"},
	)

	PeerHandshakeAgeSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "wireguard_peer_handshake_age_seconds",
			Help: "Age in seconds of the latest handshake per peer",
		},
		[]string{"interface", "peer"},
	)

	// Note: Using gauge instead of counter since WireGuard provides absolute values
	PeerBytesSent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "wireguard_peer_bytes_sent",
			Help: "Total bytes sent to peer",
		},
		[]string{"interface", "peer"},
	)

	// Note: Using gauge instead of counter since WireGuard provides absolute values
	PeerBytesReceived = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "wireguard_peer_bytes_received",
			Help: "Total bytes received from peer",
		},
		[]string{"interface", "peer"},
	)

	InterfaceListeningPort = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "wireguard_interface_listening_port",
			Help: "Listening port of the WireGuard interface",
		},
		[]string{"interface"},
	)

	PeerEndpoint = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "wireguard_peer_endpoint",
			Help: "Peer endpoint information (1 if endpoint exists, 0 otherwise)",
		},
		[]string{"interface", "peer", "endpoint"},
	)

	PeerAllowedIPsCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "wireguard_peer_allowed_ips_count",
			Help: "Number of allowed IPs per peer",
		},
		[]string{"interface", "peer"},
	)
)

func AllMetrics() []prometheus.Collector {
	return []prometheus.Collector{
		PeersTotal,
		PeerLatestHandshakeSeconds,
		PeerHandshakeAgeSeconds,
		PeerBytesSent,
		PeerBytesReceived,
		InterfaceListeningPort,
		PeerEndpoint,
		PeerAllowedIPsCount,
	}
}

