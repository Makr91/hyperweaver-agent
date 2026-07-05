# Building Hyperweaver Agent Debian Packages

Production-ready Debian package build for the Hyperweaver Agent, with automated CI/CD via Release Please (`.github/workflows/build-packages.yml`, `build-linux` job).

The web UI is **not** built here — it is consumed as the published
[hyperweaver-ui](https://github.com/MarkProminic/hyperweaver-ui) release artifact and baked into the
binary via `go:embed` before compilation.

## What the package installs

- `/usr/bin/hyperweaver-agent` — the single static binary (pure Go on Linux, no runtime deps)
- `/etc/hyperweaver-agent/config.yaml` — service-mode configuration (from `packaging/config/production-config.yaml`)
- `/etc/systemd/system/hyperweaver-agent.service` — headless service unit
- `/usr/share/applications/hyperweaver-agent.desktop` — desktop launcher for tray mode
- `/usr/share/icons/hicolor/192x192/apps/hyperweaver-agent.png` — launcher/tray icon

Two ways to run it:

- **Desktop (tray) mode**: launch "Hyperweaver Agent" from the application menu — tray icon, Open opens your browser. Stock GNOME needs the AppIndicator extension to display tray icons.
- **Headless service mode**: `systemctl enable --now hyperweaver-agent` — runs as the `hyperweaver-agent` system user with `--headless`, config from `/etc/hyperweaver-agent/config.yaml`, logs to the journal and `/var/log/hyperweaver-agent/`.

## Manual build

```bash
# Bake the UI artifact (CI does the same)
UI_VERSION=$(tr -d ' \r\n' < .ui-version)
rm -rf internal/webui/dist && mkdir -p internal/webui/dist
curl -fsSL "https://github.com/MarkProminic/hyperweaver-ui/releases/download/v${UI_VERSION}/hyperweaver-ui-${UI_VERSION}.tar.gz" | tar -xz -C internal/webui/dist

# Build the binary
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/hyperweaver-agent .

# Assemble the package tree
export VERSION=0.1.0 ARCH=amd64 PKG=hyperweaver-agent
STAGE="${PKG}_${VERSION}_${ARCH}"
mkdir -p "$STAGE"/{usr/bin,etc/hyperweaver-agent,etc/systemd/system,usr/share/applications,usr/share/icons/hicolor/192x192/apps,DEBIAN}
cp bin/hyperweaver-agent "$STAGE/usr/bin/"
cp packaging/config/production-config.yaml "$STAGE/etc/hyperweaver-agent/config.yaml"
cp packaging/DEBIAN/systemd/hyperweaver-agent.service "$STAGE/etc/systemd/system/"
cp packaging/linux/hyperweaver-agent.desktop "$STAGE/usr/share/applications/"
cp internal/tray/assets/icon.png "$STAGE/usr/share/icons/hicolor/192x192/apps/hyperweaver-agent.png"
cp packaging/DEBIAN/postinst packaging/DEBIAN/prerm packaging/DEBIAN/postrm "$STAGE/DEBIAN/"

cat > "$STAGE/DEBIAN/control" << EOF
Package: hyperweaver-agent
Version: ${VERSION}
Section: misc
Priority: optional
Architecture: ${ARCH}
Maintainer: Makr91 <makr91@users.noreply.github.com>
Description: Hyperweaver Agent - VirtualBox/Vagrant host-agent
 Single-binary host-agent with a system-tray icon that serves the
 Hyperweaver web UI to the user's own browser. Runs headless as a
 systemd service or as a desktop tray application.
Homepage: https://github.com/Makr91/hyperweaver-agent
EOF

find "$STAGE" -type d -exec chmod 755 {} \;
find "$STAGE" -type f -exec chmod 644 {} \;
chmod 755 "$STAGE/usr/bin/hyperweaver-agent" "$STAGE/DEBIAN"/{postinst,prerm,postrm}

dpkg-deb --build --root-owner-group "$STAGE" "${STAGE}.deb"
```

## Service management

```bash
sudo systemctl enable --now hyperweaver-agent
sudo systemctl status hyperweaver-agent
sudo journalctl -fu hyperweaver-agent
```

## Uninstall

```bash
sudo apt remove hyperweaver-agent   # keeps config + data
sudo apt purge hyperweaver-agent    # removes everything
```
