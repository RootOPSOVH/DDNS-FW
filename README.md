# DDNS-FW

Dynamic DNS Firewall Synchronizer - Production-grade iptables manager for Linux servers.

Automatically updates firewall rules based on dynamic DNS hostnames. Designed for critical infrastructure with zero-downtime guarantees.

## Features

- **Zero Access Lockout** - New rules added before old ones removed, connection loss impossible
- **Cross-Platform Static Binaries** - x86_64, ARM64, ARMv7, i686 with no runtime dependencies
- **Crash Recovery** - Atomic state cache with automatic recovery on restart
- **Minimal Resource Usage** - Under 600KB binary, 2-3MB RAM during execution
- **Multi-Entry Support** - Unlimited DDNS hostnames and ports per configuration
- **Idempotent Execution** - Unchanged IPs trigger zero operations
- **Concurrent Execution Protection** - Kernel-level file locking (flock)
- **Strict Permission Model** - All files restricted to root (700/600)

## Supported Architectures

| Architecture | Binary | Size | Target Systems |
|-------------|--------|------|----------------|
| x86_64 | `ddnsfw-v2.2.1-linux-x86_64` | 549 KB | Most servers, VPS, cloud instances |
| ARM64 | `ddnsfw-v2.2.1-linux-aarch64` | 517 KB | AWS Graviton, Oracle ARM, Apple Silicon VMs |
| ARMv7 | `ddnsfw-v2.2.1-linux-armv7` | 451 KB | Raspberry Pi, embedded systems |
| i686 | `ddnsfw-v2.2.1-linux-i686` | 539 KB | Legacy 32-bit systems |

All binaries are statically linked (musl libc) with zero external dependencies.

## Installation

### Quick Install (x86_64)

```bash
wget https://github.com/RootOPSOVH/DDNS-FW/releases/latest/download/ddnsfw-v2.2.1-linux-x86_64 -O ddnsfw
chmod +x ddnsfw
sudo ./ddnsfw
```

### Quick Install (ARM64)

```bash
wget https://github.com/RootOPSOVH/DDNS-FW/releases/latest/download/ddnsfw-v2.2.1-linux-aarch64 -O ddnsfw
chmod +x ddnsfw
sudo ./ddnsfw
```

The interactive installer will prompt for DDNS hostnames and ports, then configure systemd automatically.

## Configuration

Configuration file: `/etc/ddnsfw/conf.conf`

```
# Format: hostname:port
home.dyndns.org:22
office.ddns.net:22
database.ddns.net:3306
redis.ddns.net:6379
```

### Team Access Example

```
# SSH Access - Development Team
alice.ddns.net:22
bob.ddns.net:22
charlie.ddns.net:22

# Database Access - DBA Only
alice.ddns.net:3306
alice.ddns.net:5432
```

Multiple entries resolving to the same IP are automatically deduplicated.

## Operation

### Sync Algorithm

1. Resolve all DDNS hostnames to IPv4 addresses
2. Compare against existing iptables rules tagged `DDNS-ACCESS`
3. Add new rules for changed IPs
4. Remove obsolete rules only after replacements are active

### Safety Guarantees

| Scenario | Behavior |
|----------|----------|
| DNS resolution failure | Existing rules preserved |
| iptables command failure | Existing rules preserved |
| Process crash during sync | Automatic recovery via state cache |
| Unchanged IP address | Zero iptables operations |
| Concurrent execution attempt | Second instance waits or exits |
| System reboot | Rules restored on first sync |

## Security Model

### File Permissions

| Path | Mode | Access |
|------|------|--------|
| `/etc/ddnsfw/` | 700 | Root only |
| `/etc/ddnsfw/run` | 700 | Root execute |
| `/etc/ddnsfw/conf.conf` | 600 | Root read/write |
| `/etc/ddnsfw/service.cache` | 600 | Root read/write |
| `/etc/ddnsfw/.lock` | 600 | Root only |

Non-root users have no access to configuration, cache, or binary.

### Resource Limits

| Parameter | Limit | Purpose |
|-----------|-------|---------|
| Config entries | 100 | Memory bounds |
| iptables rules | 100 | Rule explosion prevention |
| Loop iterations | 200 | Infinite loop protection |
| DNS timeout | 10 sec | Hang prevention |
| Lock timeout | 30 sec | Deadlock prevention |

## Installed Components

| File | Description |
|------|-------------|
| `/etc/ddnsfw/run` | Executable binary |
| `/etc/ddnsfw/conf.conf` | DDNS configuration |
| `/etc/ddnsfw/service.cache` | Crash recovery state |
| `/etc/ddnsfw/.lock` | Execution lock file |
| `/etc/systemd/system/ddnsfw.service` | Oneshot service unit |
| `/etc/systemd/system/ddnsfw.timer` | 2-minute interval timer |

## Management Commands

```bash
# Service status
systemctl status ddnsfw.timer

# Real-time logs
journalctl -u ddnsfw -f

# Current firewall rules
iptables -L INPUT -n | grep DDNS-ACCESS

# Manual synchronization
sudo /etc/ddnsfw/run

# Complete removal
sudo systemctl stop ddnsfw.timer
sudo systemctl disable ddnsfw.timer
sudo rm -rf /etc/ddnsfw /etc/systemd/system/ddnsfw.*
sudo systemctl daemon-reload
```

## Building from Source

```bash
git clone https://github.com/RootOPSOVH/DDNS-FW.git
cd DDNS-FW

# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add cross-compilation targets
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-musl
rustup target add armv7-unknown-linux-musleabihf
rustup target add i686-unknown-linux-musl

# Build for current architecture
cargo build --release --target x86_64-unknown-linux-musl

# Output binary
./target/x86_64-unknown-linux-musl/release/ddnsfw
```

Cross-compilation requires appropriate linkers (gcc-aarch64-linux-gnu, etc.).

## System Requirements

- Linux kernel 2.6.32 or later
- iptables with comment module
- systemd (for automatic synchronization)
- Root privileges

## Compatibility

Tested distributions:

- Ubuntu 14.04, 16.04, 18.04, 20.04, 22.04, 24.04
- Debian 8, 9, 10, 11, 12
- CentOS 6, 7, 8, 9
- RHEL 6, 7, 8, 9
- Alpine Linux 3.x
- Fedora 30+
- Arch Linux
- Rocky Linux 8, 9
- AlmaLinux 8, 9

Control panel compatibility: Plesk, cPanel, DirectAdmin, Virtualmin.

## License

MIT License. See [LICENSE](LICENSE) for details.
