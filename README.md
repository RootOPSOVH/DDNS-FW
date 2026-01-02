# ddnsfw - DDNS Firewall Synchronizer

Ultra-lightweight, production-grade dynamic DNS firewall manager for Linux servers.

## Features

- **Zero Access Lockout** - New rules added before old ones removed
- **Single Static Binary** - No runtime dependencies, works on any x86_64 Linux
- **Crash-Safe** - Atomic state cache with automatic recovery
- **Minimal Footprint** - ~550KB binary, runs every 2 minutes via systemd
- **Multi-Entry Support** - Multiple DDNS hostnames and ports
- **Idempotent** - Same IP = zero operations, no micro-interruptions
- **Concurrent Execution Protection** - File locking prevents race conditions
- **Strict Permissions** - All files root-only (700/600), prevents privilege escalation

## Use Case

Secure your server ports (SSH, MySQL, Redis, etc.) by allowing access only from your dynamic IP addresses. Perfect for:

- Remote teams with home connections
- Restricting database access to known IPs
- Any service that needs IP-based access control

## Installation

### One-Line Install

```bash
wget -O ddnsfw https://github.com/RootOPSOVH/DDNS-FW/releases/latest/download/ddnsfw-v2.2.1-linux-x86_64 && chmod +x ddnsfw && sudo ./ddnsfw
```

### Step-by-Step Install

```bash
# Download
wget https://github.com/RootOPSOVH/DDNS-FW/releases/latest/download/ddnsfw-v2.2.1-linux-x86_64

# Make executable
chmod +x ddnsfw-v2.2.1-linux-x86_64

# Run installer (interactive setup)
sudo ./ddnsfw-v2.2.1-linux-x86_64
```

The interactive setup will guide you through configuration.

## Configuration

Config file location: `/etc/ddnsfw/conf.conf`

```
# Format: hostname:port
home.dyndns.org:22
office.ddns.net:22
remote.ddns.net:3306
```

### Multiple Users Example

```
# Team SSH Access
alice.ddns.net:22
bob.ddns.net:22
charlie.ddns.net:22

# Database Access (only for specific users)
alice.ddns.net:3306
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
| Concurrent execution | File locking prevents conflicts |

## Security

### File Permissions

| File | Permission | Description |
|------|------------|-------------|
| `/etc/ddnsfw/` | 700 | Directory - root only |
| `/etc/ddnsfw/run` | 700 | Binary - root execute only |
| `/etc/ddnsfw/conf.conf` | 600 | Config - root read/write only |
| `/etc/ddnsfw/service.cache` | 600 | Cache - root read/write only |
| `/etc/ddnsfw/.lock` | 600 | Lock file - root only |

Non-root users cannot read, modify, or exploit any ddnsfw files.

### Resource Limits

| Limit | Value | Purpose |
|-------|-------|---------|
| Max config entries | 100 | Prevents memory bloat |
| Max iptables rules | 100 | Prevents rule explosion |
| Max loop iterations | 200 | Prevents infinite loops |

## Installation Details

After running `./ddnsfw`, the following files are created:

| File | Description |
|------|-------------|
| `/etc/ddnsfw/run` | Binary (700) |
| `/etc/ddnsfw/conf.conf` | Configuration (600) |
| `/etc/ddnsfw/service.cache` | State cache (600) |
| `/etc/ddnsfw/.lock` | Lock file (600) |
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
sudo /etc/ddnsfw/run

# Uninstall
sudo systemctl stop ddnsfw.timer
sudo systemctl disable ddnsfw.timer
sudo rm -rf /etc/ddnsfw /etc/systemd/system/ddnsfw.*
sudo systemctl daemon-reload
```

## Building from Source

```bash
# Clone repository
git clone https://github.com/RootOPSOVH/DDNS-FW.git
cd DDNS-FW

# Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build static binary (recommended)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# Binary location
./target/x86_64-unknown-linux-musl/release/ddnsfw
```

## Requirements

- Linux x86_64 (any distribution)
- iptables
- systemd (for automatic sync)
- Root access

## Compatibility

Works on all x86_64 Linux distributions:
- Ubuntu 14.04+
- Debian 8+
- CentOS 6/7/8/9
- RHEL 6+
- Alpine Linux
- Fedora
- Arch Linux
- Plesk/cPanel servers

## License

MIT
