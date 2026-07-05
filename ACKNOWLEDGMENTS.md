# Acknowledgments

Hyperweaver Agent is built using many excellent open-source projects and tools. We are grateful to the developers and communities behind these projects.

## Core Dependencies

### Runtime Dependencies

**fyne.io/systray** - Cross-platform system tray library (maintained by the Fyne team)

- Repository: [github.com/fyne-io/systray](https://github.com/fyne-io/systray)
- License: Apache-2.0
- Usage: The native tray icon and menu on Windows, macOS, and Linux

**cli/browser** - Open URLs in the user's default browser (maintained fork of pkg/browser by the GitHub CLI team)

- Repository: [github.com/cli/browser](https://github.com/cli/browser)
- License: BSD-2-Clause
- Usage: The tray "Open" action

**goccy/go-yaml** - Pure-Go YAML parser and emitter

- Repository: [github.com/goccy/go-yaml](https://github.com/goccy/go-yaml)
- License: MIT
- Usage: Configuration file parsing (and future Hosts.yml generation)

**golang.org/x/image** - Supplementary Go image libraries

- Repository: [golang.org/x/image](https://pkg.go.dev/golang.org/x/image)
- License: BSD-3-Clause
- Usage: Tray icon scaling for the macOS menu bar

**lumberjack** - Rolling log file writer

- Repository: [github.com/natefinch/lumberjack](https://github.com/natefinch/lumberjack)
- License: MIT
- Usage: Log file rotation

### Development and Release Tooling

**golangci-lint** - Go linter aggregator

- Website: [golangci-lint.run](https://golangci-lint.run/)
- License: GPL-3.0
- Usage: Static analysis and formatting enforcement

**govulncheck** - Go vulnerability scanner

- Repository: [golang.org/x/vuln](https://pkg.go.dev/golang.org/x/vuln)
- License: BSD-3-Clause
- Usage: Dependency vulnerability scanning in CI

**goversioninfo** - Windows resource embedding

- Repository: [github.com/josephspurrier/goversioninfo](https://github.com/josephspurrier/goversioninfo)
- License: MIT
- Usage: Icon, version info, and manifest for the Windows executable

**release-please** - Automated releases from conventional commits

- Repository: [github.com/googleapis/release-please](https://github.com/googleapis/release-please)
- License: Apache-2.0
- Usage: Versioning, changelog, and GitHub releases

**Inno Setup** - Windows installer builder

- Website: [jrsoftware.org/isinfo.php](https://jrsoftware.org/isinfo.php)
- Usage: The Windows setup executable

## Platform and Ecosystem

**Go** - The programming language and standard library

- Website: [go.dev](https://go.dev/)
- License: BSD-3-Clause
- Usage: Core language and runtime (net/http, log/slog, embed, and more)

**Hyperweaver UI** - The shared React web interface served by this agent

- Repository: [github.com/MarkProminic/hyperweaver-ui](https://github.com/MarkProminic/hyperweaver-ui)
- Usage: The management UI embedded in release builds; the tray icon reuses its favicon artwork

**VirtualBox** and **Vagrant** - The hypervisor and VM lifecycle engine this agent manages

- Websites: [virtualbox.org](https://www.virtualbox.org/), [vagrantup.com](https://developer.hashicorp.com/vagrant)

**GitHub** - Code hosting, issue tracking, CI/CD

- Website: [github.com](https://github.com/)

## Community and Inspiration

**LedFx** - The tray + local web server + "opens your own browser" model this agent follows

- Repository: [github.com/LedFx/LedFx](https://github.com/LedFx/LedFx)

**Super.Human.Installer** - The predecessor application this agent replaces; its provisioner design informs the roadmap

- Repository: [github.com/Moonshine-IDE/Super.Human.Installer](https://github.com/Moonshine-IDE/Super.Human.Installer)

**Zoneweaver Agent** - The reference implementation of the Agent API contract

- Repository: [github.com/Makr91/zoneweaver-agent](https://github.com/Makr91/zoneweaver-agent)

---

## Disclaimer

This acknowledgment file may not be exhaustive. If you believe a project or individual should be acknowledged here, please let us know by opening an issue or contributing to this file.

All trademarks and registered trademarks mentioned herein are the property of their respective owners.
