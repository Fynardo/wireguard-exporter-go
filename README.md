# WireGuard Prometheus Exporter

A Prometheus metrics exporter for WireGuard VPN interfaces, written in Go.

## Features

- Discovers all WireGuard interfaces automatically
- Filters interfaces using a deny-list
- Exports comprehensive metrics for interfaces and peers
- Supports configuration via CLI flags, environment variables, or config file (with priority: CLI > ENV > file)
- Secure by design - never exposes private keys or sensitive data

## Metrics

The exporter provides the following metrics:

- `wireguard_peers_total` - Number of configured peers per interface
- `wireguard_peer_latest_handshake_seconds` - Unix timestamp of the latest handshake per peer
- `wireguard_peer_handshake_age_seconds` - Age in seconds of the latest handshake per peer
- `wireguard_peer_bytes_sent` - Total bytes sent to peer
- `wireguard_peer_bytes_received` - Total bytes received from peer
- `wireguard_interface_listening_port` - Listening port of the WireGuard interface
- `wireguard_peer_endpoint` - Peer endpoint information (1 if endpoint exists, 0 otherwise)
- `wireguard_peer_allowed_ips_count` - Number of allowed IPs per peer

## Configuration

### Command-Line Flags

- `--listen-address` - Address to listen on (default: `:9586`)
- `--metrics-path` - Path for metrics endpoint (default: `/metrics`)
- `--wg-command-path` - Path to `wg` command (default: `wg`)
- `--interfaces-denylist` - Comma-separated list of interfaces to exclude
- `--show-endpoints` - Show peer endpoints in metrics (default: `true`)
- `--config` - Path to configuration file (JSON)

### Environment Variables

- `WG_LISTEN_ADDRESS` - Address to listen on
- `WG_METRICS_PATH` - Path for metrics endpoint
- `WG_COMMAND_PATH` - Path to `wg` command
- `WG_INTERFACES_DENYLIST` - Comma-separated list of interfaces to exclude
- `WG_SHOW_ENDPOINTS` - Show peer endpoints (`true` or `1`)

### Configuration File (JSON)

```json
{
  "listen_address": ":9586",
  "metrics_path": "/metrics",
  "interfaces_denylist": ["wg-example"],
  "wg_command_path": "wg",
  "show_endpoints": true,
  "interface_labels": {
    "wg0": {
      "location": "datacenter1",
      "environment": "production"
    }
  }
}
```

Configuration priority: CLI flags > Environment variables > Config file

## Usage

### Basic Usage

```bash
./wireguard-exporter-go
```

### With Custom Port

```bash
./wireguard-exporter-go --listen-address :9090
```

### Excluding Interfaces

```bash
./wireguard-exporter-go --interfaces-denylist "wg-test,wg-dev"
```

### Using Configuration File

```bash
./wireguard-exporter-go --config config.json
```

## Security Considerations

- Private keys are never parsed or exposed
- Interface names are validated to prevent command injection
- Command execution uses explicit paths with timeouts
- Sensitive data is filtered from logs
- Endpoint IPs can be hidden using `--show-endpoints=false`

## Building

```bash
go mod download
go build -o wireguard-exporter-go
```

## Requirements

- Go 1.21 or later
- WireGuard installed and `wg` command available in PATH
- Linux (currently only Linux is supported)

## License

MIT

## Creds

Co-authored by Claude via Cursor (I know you already noticed)