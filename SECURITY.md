# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in Hyperweaver Agent, please report it responsibly:

### Preferred Method: Security Advisory

1. Go to the [GitHub Security Advisory page](https://github.com/Makr91/hyperweaver-agent/security/advisories)
2. Click "Report a vulnerability"
3. Fill out the advisory form with detailed information
4. Submit the advisory

### What to Include

Please provide as much information as possible:

- **Description** of the vulnerability
- **Steps to reproduce** the issue
- **Potential impact** of the vulnerability
- **Affected versions** (if known)
- **Suggested fix** (if you have one)
- **Your contact information** for follow-up questions

## Response Process

Due to limited development resources, please understand that:

- **Initial Response**: We aim to acknowledge receipt within 48-72 hours
- **Assessment**: Initial assessment will be completed within 1 week
- **Resolution**: Timeline depends on severity and complexity, typically 1-4 weeks
- **Disclosure**: Coordinated disclosure after fix is available

### Severity Levels

- **Critical**: Immediate attention (RCE, privilege escalation)
- **High**: Quick response needed (authentication bypass, data exposure)
- **Medium**: Standard timeline (DoS, information disclosure)
- **Low**: Lower priority (minor information leaks)

## Security Considerations for Hyperweaver Agent

Hyperweaver Agent runs on end-user machines and orchestrates hypervisor tooling, so please pay special attention to:

### High-Risk Areas

- **Local web server exposure**: The agent binds to loopback by default — anything weakening that boundary
- **Subprocess execution**: The agent will drive `vagrant`, `VBoxManage`, and `git` — any potential for command or argument injection
- **File system operations**: Path traversal or unauthorized file access (config, logs, future file cache)
- **Authentication**: API-key handling and the future tray token handoff
- **Served UI integrity**: Tampering with the embedded or on-disk UI artifact

### Configuration Security

- **Default configurations**: Insecure defaults
- **Bind address**: Exposure beyond 127.0.0.1
- **CORS/origin handling**: Once cross-origin consumers exist

## Best Practices for Users

To maintain security:

1. **Keep Updated**: Always run the latest release
2. **Keep loopback binding** unless you understand the exposure of a LAN-reachable agent
3. **Protect your config directory**: It will hold credentials in future releases
4. **Monitor Logs**: Watch for suspicious activity in the agent log file

## Security Tooling in CI

Every change runs through:

- **gosec** (via golangci-lint) — Go security static analysis
- **govulncheck** — known-vulnerability scanning with call-graph reachability, on PRs and weekly
- **CodeQL** — GitHub code scanning for Go and workflow files
- **Dependabot** — dependency update automation

## Acknowledgments

We appreciate the security research community's efforts in making Hyperweaver Agent more secure. Responsible disclosure helps protect all users.

### Hall of Fame

Contributors who responsibly report security vulnerabilities will be acknowledged here (with their permission):

- *No vulnerabilities reported yet*

## Updates to This Policy

This security policy may be updated as the project evolves. Check back periodically for changes.

---

**Remember**: Security is a shared responsibility. Your vigilance and responsible reporting help keep the entire Hyperweaver community safe.
