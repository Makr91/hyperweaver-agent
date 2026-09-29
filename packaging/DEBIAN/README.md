# Building Hyperweaver Agent Debian Packages

Production-ready Debian package build for the Hyperweaver Agent, with automated CI/CD via Release Please (`.github/workflows/build-packages.yml`, `build-linux` job).

The web UI is **not** built here — it is consumed as the published
[hyperweaver-ui](https://github.com/MarkProminic/hyperweaver-ui) release artifact and baked into the
binary via `go:embed` before compilation.

## What the package installs

- `/usr/bin/hyperweaver-agent` — the single static binary (pure Go on Linux, no runtime deps)
- `/usr/share/hyperweaver-agent/config/{app,auth,db,machines,storage}.config.yaml` — the seed configuration files (from `internal/config/seed/`); `postinst` copies each to `/etc/hyperweaver-agent/<name>.config.yaml` when absent and creates `/etc/hyperweaver-agent/setup.token`
- `/etc/hyperweaver-agent/ssl/root-ca.crt`, `ca.crt`, `ca.key` — the STARTcloud PKI fetched from the `core_provisioner` release pinned in `driver.version`; `postinst` plants `root-ca.crt` under `/usr/local/share/ca-certificates/hyperweaver/` and runs `update-ca-certificates`
- `/etc/systemd/system/hyperweaver-agent.service` — headless service unit
- `/usr/share/applications/hyperweaver-agent.desktop` — desktop launcher for tray mode
- `/usr/share/icons/hicolor/192x192/apps/hyperweaver-agent.png` — launcher/tray icon
- `/usr/share/man/man8/hyperweaver-agent.8.gz`, `/usr/share/man/man5/hyperweaver-agent.yaml.5.gz` — manual pages
- `/usr/share/hyperweaver-agent/provisioners-seed/*.tar.gz` — provisioner seed archives when the release assets were fetched; extracted by the agent on startup

Two ways to run it:

- **Desktop (tray) mode**: launch "Hyperweaver Agent" from the application menu — tray icon, Open opens your browser. Stock GNOME needs the AppIndicator extension to display tray icons.
- **Headless service mode**: `systemctl enable --now hyperweaver-agent` — runs as the `hyperweaver-agent` system user with `--headless --config /etc/hyperweaver-agent`, logs to the journal and `/var/log/hyperweaver-agent/`.

## Manual build

Bake the UI artifact:

```bash
UI_VERSION=$(tr -d ' \r\n' < .ui-version)
rm -rf internal/webui/dist && mkdir -p internal/webui/dist
curl -fsSL "https://github.com/MarkProminic/hyperweaver-ui/releases/download/v${UI_VERSION}/hyperweaver-ui-${UI_VERSION}.tar.gz" | tar -xz -C internal/webui/dist
```

Stage the provisioner seed archives (a missing asset is tolerated; the build proceeds without it):

```bash
mkdir -p packaging/provisioners-seed
for repo in STARTcloud/startcloud_generic_provisioner STARTcloud/hcl_domino_standalone_provisioner STARTcloud/hcl_domino_additional_provisioner; do
  asset="${repo##*/}.tar.gz"
  gh release download --repo "$repo" --pattern "$asset" --dir packaging/provisioners-seed || echo "WARNING: no seed archive from $repo"
done
```

Stage the STARTcloud PKI from the `core_provisioner` release pinned in `driver.version` (`packaging/ssl` is gitignored and only ever populated this way):

```bash
TAG="$(tr -d '[:space:]' < driver.version)"
VERSION="${TAG#v}"
ARCHIVE="core_provisioner-${VERSION}.tar.gz"
BASE="https://github.com/STARTcloud/core_provisioner/releases/download/${TAG}"
curl -fsSL -o "/tmp/$ARCHIVE" "$BASE/$ARCHIVE"
curl -fsSL -o "/tmp/$ARCHIVE.sha256" "$BASE/$ARCHIVE.sha256"
EXPECTED="$(awk '{print $1}' "/tmp/$ARCHIVE.sha256")"
ACTUAL="$(openssl dgst -sha256 -r "/tmp/$ARCHIVE" | awk '{print $1}')"
[ "$EXPECTED" = "$ACTUAL" ] || { echo "Checksum mismatch for $ARCHIVE" >&2; exit 1; }
mkdir -p /tmp/core-driver
(cd /tmp && tar -xzf "$ARCHIVE" -C core-driver)
CA=/tmp/core-driver/driver/ssls/ca
mkdir -p packaging/ssl
cp "$CA/root-ca.crt" packaging/ssl/root-ca.crt
cp "$CA/ca-certificate.crt" packaging/ssl/ca-certificate.crt
openssl pkey -in "$CA/ca-certificate.key" -out packaging/ssl/ca-certificate.key -passin 'pass:STARTcloud24@!'
```

Build the binary and assemble the package tree:

```bash
export VERSION=0.1.0 ARCH=amd64 PKG=hyperweaver-agent
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/Makr91/hyperweaver-agent/internal/version.Version=${VERSION}" -o bin/hyperweaver-agent .

STAGE="${PKG}_${VERSION}_${ARCH}"
mkdir -p "$STAGE"/usr/bin \
         "$STAGE"/etc/hyperweaver-agent/ssl \
         "$STAGE"/etc/systemd/system \
         "$STAGE"/usr/share/applications \
         "$STAGE"/usr/share/icons/hicolor/192x192/apps \
         "$STAGE"/usr/share/man/man8 \
         "$STAGE"/usr/share/man/man5 \
         "$STAGE"/usr/share/hyperweaver-agent/config \
         "$STAGE"/DEBIAN
cp bin/hyperweaver-agent "$STAGE/usr/bin/"
cp internal/config/seed/*.config.yaml "$STAGE/usr/share/hyperweaver-agent/config/"
cp packaging/ssl/root-ca.crt "$STAGE/etc/hyperweaver-agent/ssl/root-ca.crt"
cp packaging/ssl/ca-certificate.crt "$STAGE/etc/hyperweaver-agent/ssl/ca.crt"
cp packaging/ssl/ca-certificate.key "$STAGE/etc/hyperweaver-agent/ssl/ca.key"
cp packaging/DEBIAN/systemd/hyperweaver-agent.service "$STAGE/etc/systemd/system/"
cp packaging/linux/hyperweaver-agent.desktop "$STAGE/usr/share/applications/"
cp internal/tray/assets/icon.png "$STAGE/usr/share/icons/hicolor/192x192/apps/hyperweaver-agent.png"
gzip -9 -c packaging/DEBIAN/man/hyperweaver-agent.8 > "$STAGE/usr/share/man/man8/hyperweaver-agent.8.gz"
gzip -9 -c packaging/DEBIAN/man/hyperweaver-agent.yaml.5 > "$STAGE/usr/share/man/man5/hyperweaver-agent.yaml.5.gz"
if compgen -G "packaging/provisioners-seed/*" > /dev/null; then
  mkdir -p "$STAGE/usr/share/hyperweaver-agent/provisioners-seed"
  cp packaging/provisioners-seed/* "$STAGE/usr/share/hyperweaver-agent/provisioners-seed/"
fi
cp packaging/DEBIAN/postinst packaging/DEBIAN/prerm packaging/DEBIAN/postrm "$STAGE/DEBIAN/"

cat > "$STAGE/DEBIAN/control" << EOF
Package: hyperweaver-agent
Version: ${VERSION}
Section: misc
Priority: optional
Architecture: ${ARCH}
Depends: adduser, ca-certificates
Maintainer: Makr91 <makr91@users.noreply.github.com>
Description: Hyperweaver Agent - VirtualBox host-agent
 Single-binary host-agent with a system-tray icon that serves the
 Hyperweaver web UI to the user's own browser. Runs headless as a
 systemd service or as a desktop tray application.
Homepage: https://github.com/Makr91/hyperweaver-agent
EOF

find "$STAGE" -type d -exec chmod 755 {} \;
find "$STAGE" -type f -exec chmod 644 {} \;
chmod 755 "$STAGE/usr/bin/hyperweaver-agent" "$STAGE/DEBIAN"/postinst "$STAGE/DEBIAN"/prerm "$STAGE/DEBIAN"/postrm

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
