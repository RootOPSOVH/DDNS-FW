# ddnsfw - DDNS Firewall Synchronizer

Ultra-lightweight, production-grade dynamic DNS firewall manager for Linux servers.

## Features

- **Zero Access Lockout** - New rules added before old ones removed
- **Single Static Binary** - No runtime dependencies, works on any x86_64 Linux
- **Crash-Safe** - Atomic state cache with automatic recovery
- **Minimal Footprint** - ~540KB binary, runs every 2 minutes via systemd
- **Multi-Entry Support** - Multiple DDNS hostnames and ports
- **Idempotent** - Same IP = zero operations, no micro-interruptions

## Use Case

Secure your server ports (SSH, MySQL, Redis, etc.) by allowing access only from your dynamic IP addresses. Perfect for:

- Remote teams with home connections
- Restricting database access to known IPs
- Any service that needs IP-based access control

## Quick Start

```bash
# Download and run
sudo ./ddnsfw
```

Interactive setup will guide you through configuration.

## Configuration

Config file location: `/etc/ddnsfw/conf.conf`

```
# Format: hostname:port
home.dyndns.org:22
office.ddns.net:22
remote.ddns.net:3306
```

## How It Works

1. Resolves DDNS hostnames to IPv4 addresses
2. Compares with existing iptables rules (tagged `DDNS-ACCESS`)
3. Adds new rules, then removes outdated ones
4. Never removes a rule without active replacement

## Safety Guarantees

| Scenario | Behavior |
|----------|----------|
| DNS resolution fails | Existing rules preserved |
| iptables command fails | Existing rules preserved |
| Service crashes mid-operation | Automatic recovery on next run |
| IP unchanged | Zero iptables operations |

## Installation Details

After running `./ddnsfw`, the following files are created:

| File | Description |
|------|-------------|
| `/etc/ddnsfw/run` | Binary |
| `/etc/ddnsfw/conf.conf` | Configuration |
| `/etc/ddnsfw/service.cache` | State cache |
| `/etc/systemd/system/ddnsfw.service` | Systemd service |
| `/etc/systemd/system/ddnsfw.timer` | Systemd timer (2 min) |

## Commands

```bash
# Check status
systemctl status ddnsfw.timer

# View logs
journalctl -u ddnsfw -f

# View iptables rules
iptables -L INPUT -n | grep DDNS

# Manual run
/etc/ddnsfw/run

# Uninstall
sudo rm -rf /etc/ddnsfw /etc/systemd/system/ddnsfw.*
sudo systemctl daemon-reload
```

## Building from Source

```bash
# Standard build
cargo build --release

# Universal static build (recommended)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Requirements

- Linux x86_64
- iptables
- systemd (for automatic sync)

## License

MIT
