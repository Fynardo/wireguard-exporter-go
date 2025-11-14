# WireGuard Prometheus Exporter
![Build Status](https://github.com/Fynardo/wireguard-exporter-go/actions/workflows/ci.yml/badge.svg)
![Release](https://github.com/Fynardo/wireguard-exporter-go/actions/workflows/main.yml/badge.svg)

A Prometheus metrics exporter for WireGuard VPN interfaces, written in Go.

## Features

- Discovers all WireGuard interfaces automatically
- Filters interfaces using a deny-list
- Exports comprehensive metrics for interfaces and peers
- Human-friendly peer names - Uses display names from WireGuard config files instead of public keys in metrics labels
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

All peer-level metrics use a `peer` label that contains either:
- The display name from the WireGuard config file (if available and config file reading is enabled)
- The peer's public key (as fallback)

## Display Names

**Disclaimer**: I saw this technique in another repo that parsed the Wireguard config files but don't remember where exactly, so I'm sorry I cannot give proper kudos.

The exporter can read display names from WireGuard config files to use human-friendly names in metrics instead of public keys. To enable this, add a `# display-name = <name>` comment in each `[Peer]` block of your WireGuard config file:

```ini
[Peer]
# display-name = Mobile Phone
PublicKey = <whatever_public_key>
AllowedIPs = <whatever_ip_range>
```

You probably want to use a display name that is prometheus label friendly.

You can use either `display-name` or `display_name` format. The exporter will:
1. Read the config file at `/etc/wireguard/<interface>.conf` by default
2. Match peers by their public key
3. Use the display name in the `peer` label for all metrics

If config file reading is disabled or a display name is not found, the public key is used as the label value.

## Configuration

### Command-Line Flags

- `--listen-address` - Address to listen on (default: `:9586`)
- `--metrics-path` - Path for metrics endpoint (default: `/metrics`)
- `--wg-command-path` - Path to `wg` command (default: `wg`)
- `--interfaces-denylist` - Comma-separated list of interfaces to exclude
- `--show-endpoints` - Show peer endpoints in metrics (default: `true`)
- `--read-config-files` - Enable reading WireGuard config files for display names (default: `true`)
- `--config` - Path to configuration file (JSON)

### Environment Variables

- `WG_LISTEN_ADDRESS` - Address to listen on
- `WG_METRICS_PATH` - Path for metrics endpoint
- `WG_COMMAND_PATH` - Path to `wg` command
- `WG_INTERFACES_DENYLIST` - Comma-separated list of interfaces to exclude
- `WG_SHOW_ENDPOINTS` - Show peer endpoints (`true` or `1`)
- `WG_READ_CONFIG_FILES` - Enable reading WireGuard config files for display names (`true` or `1`)

### Configuration File (JSON)

```json
{
  "listen_address": ":9586",
  "metrics_path": "/metrics",
  "interfaces_denylist": ["wg-example"],
  "wg_command_path": "wg",
  "show_endpoints": true,
  "read_config_files": true,
  "config_file_paths": {
    "wg0": "/etc/wireguard/wg0.conf",
    "wg1": "/custom/path/to/wg1.conf"
  }
}
```

#### Configuration Options

- `read_config_files` - Enable reading WireGuard config files for display names (default: `true`). When disabled, the exporter will use public keys as peer labels.
- `config_file_paths` - Optional map of interface names to custom config file paths. If not specified, defaults to `/etc/wireguard/<interface>.conf`

Configuration priority: CLI flags > Environment variables > Config file

## Usage

**Note**: Running the `wg` command requires privileges, so you may need to run the app as `sudo`

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

### Disabling Config File Reading

If you want to prevent the exporter from reading your WireGuard config files (for privacy or security reasons), you can disable it:

```bash
./wireguard-exporter-go --read-config-files=false
```

In this case, the exporter will use public keys as peer labels in metrics.

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
- Config file reading can be disabled using `--read-config-files=false` to prevent the exporter from accessing your WireGuard configuration files

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

