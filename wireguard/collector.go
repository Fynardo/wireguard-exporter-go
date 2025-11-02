package wireguard

import (
	"log/slog"
	"time"
	"wireguard-exporter-go/config"
	"wireguard-exporter-go/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

// Implementsprometheus.Collector interface
type Collector struct {
	cfg *config.Config
}

// Wireguard collector
func NewCollector(cfg *config.Config) *Collector {
	return &Collector{
		cfg: cfg,
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	metrics.PeersTotal.Describe(ch)
	metrics.PeerLatestHandshakeSeconds.Describe(ch)
	metrics.PeerHandshakeAgeSeconds.Describe(ch)
	metrics.PeerBytesSent.Describe(ch)
	metrics.PeerBytesReceived.Describe(ch)
	metrics.InterfaceListeningPort.Describe(ch)
	metrics.PeerEndpoint.Describe(ch)
	metrics.PeerAllowedIPsCount.Describe(ch)
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	// Discover interfaces
	interfaces, err := DiscoverInterfaces(c.cfg.WGCommandPath, c.cfg.InterfacesDenylist)
	if err != nil {
		slog.Error("Failed to discover interfaces", "error", err)
		// Return empty metrics instead of crashing
		return
	}

	// Reset all metrics before collecting new data
	// For gauges, we need to reset manually
	metrics.PeersTotal.Reset()
	metrics.PeerLatestHandshakeSeconds.Reset()
	metrics.PeerHandshakeAgeSeconds.Reset()
	metrics.PeerBytesSent.Reset()
	metrics.PeerBytesReceived.Reset()
	metrics.InterfaceListeningPort.Reset()
	metrics.PeerEndpoint.Reset()
	metrics.PeerAllowedIPsCount.Reset()

	// Collect data for each interface
	for _, ifaceName := range interfaces {
		iface, err := ParseInterfaceData(c.cfg.WGCommandPath, ifaceName)
		if err != nil {
			slog.Error("Failed to parse interface data", "interface", ifaceName, "error", err)
			continue
		}

		// Build label map for this interface
		labels := c.buildLabels(ifaceName)

		// Set interface-level metrics
		metrics.PeersTotal.With(labels).Set(float64(len(iface.Peers)))
		metrics.InterfaceListeningPort.With(labels).Set(float64(iface.ListeningPort))

		// Set peer-level metrics
		for _, peer := range iface.Peers {
			peerLabels := c.buildPeerLabels(ifaceName, peer)

			// Handshake metrics
			if !peer.LatestHandshake.IsZero() {
				metrics.PeerLatestHandshakeSeconds.With(peerLabels).Set(float64(peer.LatestHandshake.Unix()))
				
				// Calculate age in seconds
				ageSeconds := time.Since(peer.LatestHandshake).Seconds()
				metrics.PeerHandshakeAgeSeconds.With(peerLabels).Set(ageSeconds)
			} else {
				// Set to 0 if no handshake
				metrics.PeerLatestHandshakeSeconds.With(peerLabels).Set(0)
				metrics.PeerHandshakeAgeSeconds.With(peerLabels).Set(0)
			}

			// Transfer metrics (gauges - WireGuard provides absolute values)
			metrics.PeerBytesSent.With(peerLabels).Set(float64(peer.BytesSent))
			metrics.PeerBytesReceived.With(peerLabels).Set(float64(peer.BytesReceived))

			// Endpoint metric
			if c.cfg.ShowEndpoints && peer.Endpoint != "" {
				endpointLabels := make(map[string]string)
				for k, v := range peerLabels {
					endpointLabels[k] = v
				}
				endpointLabels["endpoint"] = peer.Endpoint
				metrics.PeerEndpoint.With(endpointLabels).Set(1)
			} else {
				// Set endpoint to empty if not showing or no endpoint
				endpointLabels := make(map[string]string)
				for k, v := range peerLabels {
					endpointLabels[k] = v
				}
				endpointLabels["endpoint"] = ""
				metrics.PeerEndpoint.With(endpointLabels).Set(0)
			}

			// Allowed IPs count
			metrics.PeerAllowedIPsCount.With(peerLabels).Set(float64(len(peer.AllowedIPs)))
		}
	}

	// Collect all metrics
	metrics.PeersTotal.Collect(ch)
	metrics.PeerLatestHandshakeSeconds.Collect(ch)
	metrics.PeerHandshakeAgeSeconds.Collect(ch)
	metrics.PeerBytesSent.Collect(ch)
	metrics.PeerBytesReceived.Collect(ch)
	metrics.InterfaceListeningPort.Collect(ch)
	metrics.PeerEndpoint.Collect(ch)
	metrics.PeerAllowedIPsCount.Collect(ch)
}

// Build a label map for interface-level metrics
func (c *Collector) buildLabels(ifaceName string) prometheus.Labels {
	labels := prometheus.Labels{
		"interface": ifaceName,
	}

	// Add custom labels from config
	if customLabels, exists := c.cfg.InterfaceLabels[ifaceName]; exists {
		for k, v := range customLabels {
			labels[k] = v
		}
	}

	return labels
}

// Build a label map for peer-level metrics
func (c *Collector) buildPeerLabels(ifaceName string, peer Peer) prometheus.Labels {
	labels := prometheus.Labels{
		"interface":       ifaceName,
		"peer_public_key": peer.PublicKey,
	}

	// Add custom labels from config
	if customLabels, exists := c.cfg.InterfaceLabels[ifaceName]; exists {
		for k, v := range customLabels {
			labels[k] = v
		}
	}

	return labels
}

