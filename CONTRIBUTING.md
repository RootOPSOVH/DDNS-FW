# Contributing to DDNS-FW

Thank you for your interest in contributing to DDNS-FW! This document provides guidelines for contributing.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/RootOPSOVH/DDNS-FW/issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - System information (OS, iptables version)
   - Logs (`journalctl -u ddnsfw -n 50`)

### Suggesting Features

1. Check existing issues for similar suggestions
2. Create a new issue with:
   - Clear description of the feature
   - Use case / why it's needed
   - Proposed implementation (if any)

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Test thoroughly
5. Commit with clear messages
6. Push to your fork
7. Open a Pull Request

## Development Setup

```bash
# Clone
git clone https://github.com/RootOPSOVH/DDNS-FW.git
cd DDNS-FW

# Build
cargo build

# Build release (static)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# Test (requires root and iptables)
sudo ./target/release/ddnsfw
```

## Code Guidelines

### Safety First

DDNS-FW runs on critical production servers. All changes must:

- Never risk SSH/service lockout
- Handle all error cases gracefully
- Fail safe (preserve existing rules on error)
- Be idempotent

### Code Style

- Follow Rust conventions
- Use meaningful variable names
- Add comments for complex logic
- Keep functions focused and small

### Testing

Before submitting:

1. Test on a non-production server
2. Verify no existing rules are disrupted
3. Test DNS failure scenarios
4. Test with multiple entries
5. Verify crash recovery works

## Commit Messages

Format:
```
Short summary (50 chars or less)

Detailed explanation if needed. Wrap at 72 characters.
Explain what and why, not how.
```

Examples:
- `Fix DNS timeout not being applied`
- `Add support for custom iptables path`
- `Improve error message for missing config`

## Questions?

Open an issue with the "question" label or start a discussion.

Thank you for contributing!
