# Contributing to Hyperweaver Agent

Thank you for your interest in contributing to Hyperweaver Agent! We welcome contributions from the community as they are essential for the project's continued growth and development.

## Important Note on Resources

Hyperweaver Agent is maintained with limited development resources. **Community contributions directly impact the pace of feature development and bug fixes.** The more the community contributes, the faster the project can grow and improve.

## How to Contribute

### Reporting Issues

Before creating an issue, please:

1. **Search existing issues** to avoid duplicates
2. **Use the appropriate issue template** (bug report, feature request, etc.)
3. **Provide detailed information** to help us understand and prioritize the issue
4. **Include system information** (OS and version, agent version, VirtualBox/Vagrant versions)

### Submitting Pull Requests

We appreciate all pull requests! To ensure smooth collaboration:

1. **Fork the repository** and create your feature branch from `main`
2. **Follow the existing code style** — `golangci-lint` (with gofumpt formatting) is the arbiter and runs in CI
3. **Update documentation** if your changes affect the API or configuration
4. **Use conventional commit messages** (`fix: ...`) — releases are automated from them
5. **Fill out the pull request template** completely

### Development Setup

1. Install Go 1.24 or newer
2. Clone your fork of the repository
3. Copy the tray icon assets from the UI project (see README "Building from source")
4. Fetch dependencies: `go mod tidy`
5. Build and run: `go build -o hyperweaver-agent . && ./hyperweaver-agent`
6. The web UI is served at `http://127.0.0.1:9420/ui/` (placeholder page unless a UI artifact is unpacked into `internal/webui/dist/`)

Platform notes:

- Windows and Linux build pure Go; the Windows binary cross-compiles from any OS with `GOOS=windows CGO_ENABLED=0`.
- macOS builds require a Mac (the tray uses Cocoa via cgo).

### Code Style Guidelines

- `golangci-lint run` must pass — the configuration in `.golangci.yml` is strict on purpose
- Format with gofumpt/goimports (both enforced by the linter)
- Never write to stdout/stderr for diagnostics — use `log/slog` (the Windows GUI build has no console)
- Keep dependencies minimal; prefer the standard library

### What We're Looking For

**High Impact Contributions:**

- Bug fixes (especially those affecting system stability)
- Security improvements
- Performance optimizations
- Documentation improvements

**Feature Contributions:**

- Provisioning engine features (Vagrant/VirtualBox orchestration)
- Platform integration improvements (Windows/macOS/Linux quirks)
- API improvements
- Better error handling

## Response Times and Review Process

Due to limited development resources:

- **Issue responses**: We aim to acknowledge new issues within a few days
- **Pull request reviews**: Reviews may take weeks depending on complexity and current workload
- **Feature requests**: Prioritized based on community needs and available resources
- **Documentation updates**: Generally reviewed quickly as they're high-impact, low-risk

## Getting Help

If you need help with contributing:

- **GitHub Discussions**: Ask questions about development
- **Issues**: Use the "question" template for specific inquiries

## Recognition

All contributors are recognized in our [AUTHORS.md](AUTHORS.md) file. We appreciate every contribution, from small bug fixes to major features!

## Code of Conduct

Please note that this project follows our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to abide by its terms.

## License

By contributing to Hyperweaver Agent, you agree that your contributions will be licensed under the [GPL-3.0 License](LICENSE.md).

---

**Remember**: Your contributions directly influence the project's development speed and capabilities. Thank you for helping make Hyperweaver Agent better for everyone!
