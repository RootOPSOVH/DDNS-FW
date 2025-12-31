# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in DDNS-FW, please report it responsibly:

### Do NOT

- Open a public GitHub issue for security vulnerabilities
- Disclose the vulnerability publicly before it's fixed

### Do

1. **Email**: Send details to the repository owner via GitHub private message
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Critical issues within 14 days

### After Fix

- Security advisory will be published
- Credit will be given (unless you prefer anonymity)
- Fixed version will be released

## Security Considerations

DDNS-FW is designed for critical server security. Key security features:

### Access Control
- Runs as root (required for iptables)
- Config file permissions: 600 (owner only)
- Binary permissions: 700 (owner only)

### Fail-Safe Design
- DNS failure = keep existing rules
- iptables failure = keep existing rules
- Crash = automatic recovery

### No External Dependencies
- Static binary (no shared libraries)
- Uses system DNS resolver only
- No network connections except DNS

### Input Validation
- Hostname length limited
- Port range validated (1-65535)
- Max entries limited (100)

## Best Practices

1. **Keep Updated**: Use the latest version
2. **Secure DNS**: Use trusted DNS servers
3. **Monitor Logs**: Check `journalctl -u ddnsfw` regularly
4. **Backup Config**: Keep a copy of `/etc/ddnsfw/conf.conf`
5. **Test Changes**: Test config changes on non-production first
