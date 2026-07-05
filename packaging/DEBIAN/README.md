# Building Hyperweaver Server Debian Packages

Production-ready Debian package build for the Hyperweaver Server, with automated CI/CD via Release Please.

The web UI is **not** built here — it is consumed as the published
[hyperweaver-ui](https://github.com/MarkProminic/hyperweaver-ui) release artifact and unpacked into `./ui`.

## Prerequisites

```bash
sudo apt update
sudo apt install nodejs npm dpkg-dev gdebi-core
```

## Quick Build Commands

### 1. Prepare Application

```bash
# Sync version into swagger/config/manifest
npm run sync-versions

# Install dependencies
npm ci

# Fetch the pinned Hyperweaver UI artifact into ./ui
UI_VERSION=$(node -p "require('./package.json').hyperweaverUiVersion")
mkdir -p ui
curl -fsSL "https://github.com/MarkProminic/hyperweaver-ui/releases/download/v${UI_VERSION}/hyperweaver-ui-${UI_VERSION}.tar.gz" | tar -xz -C ui

# Generate OpenAPI documentation
npm run generate-docs

# Install production dependencies only
npm ci --omit=dev
```

### 2. Create Package Structure

```bash
# Extract version from package.json
export VERSION=$(node -p "require('./package.json').version")
export PACKAGE_NAME="hyperweaver-server"
export ARCH="amd64"

# Create directory structure
mkdir -p "${PACKAGE_NAME}_${VERSION}_${ARCH}"/{opt/hyperweaver-server,etc/hyperweaver-server,etc/systemd/system,var/lib/hyperweaver-server,var/log/hyperweaver-server,usr/share/man/man8,usr/share/man/man5,DEBIAN}
```

### 3. Copy Application Files

```bash
# Application files to /opt/hyperweaver-server (IMPORTANT: include utils and scripts!)
cp -r controllers models routes auth config utils scripts index.js package.json "${PACKAGE_NAME}_${VERSION}_${ARCH}/opt/hyperweaver-server/"
cp -r node_modules "${PACKAGE_NAME}_${VERSION}_${ARCH}/opt/hyperweaver-server/"
cp -r ui "${PACKAGE_NAME}_${VERSION}_${ARCH}/opt/hyperweaver-server/ui"

# Configuration file
cp packaging/config/production-config.yaml "${PACKAGE_NAME}_${VERSION}_${ARCH}/etc/hyperweaver-server/config.yaml"

# Systemd service (with privileged port capabilities)
cp packaging/DEBIAN/systemd/hyperweaver-server.service "${PACKAGE_NAME}_${VERSION}_${ARCH}/etc/systemd/system/"

# DEBIAN control files
cp packaging/DEBIAN/postinst packaging/DEBIAN/prerm packaging/DEBIAN/postrm "${PACKAGE_NAME}_${VERSION}_${ARCH}/DEBIAN/"

# Man pages (compress following Debian Policy)
gzip -9 -c packaging/DEBIAN/man/hyperweaver-server.8 > "${PACKAGE_NAME}_${VERSION}_${ARCH}/usr/share/man/man8/hyperweaver-server.8.gz"
gzip -9 -c packaging/DEBIAN/man/hyperweaver-server.yaml.5 > "${PACKAGE_NAME}_${VERSION}_${ARCH}/usr/share/man/man5/hyperweaver-server.yaml.5.gz"
```

### 4. Generate Control File

```bash
cat > "${PACKAGE_NAME}_${VERSION}_${ARCH}/DEBIAN/control" << EOF
Package: hyperweaver-server
Version: ${VERSION}
Section: misc
Priority: optional
Architecture: ${ARCH}
Maintainer: Makr91 <makr91@users.noreply.github.com>
Depends: nodejs (>= 22.0.0), sqlite3, openssl
Description: Hyperweaver Server - hypervisor control-plane web interface
 Aggregates and proxies host agents (Zoneweaver Agent for Bhyve/OmniOS,
 Hyperweaver Agent for VirtualBox) and serves the Hyperweaver UI.
Homepage: https://github.com/Makr91/hyperweaver-server
EOF
```

### 5. Set Permissions

```bash
find "${PACKAGE_NAME}_${VERSION}_${ARCH}" -type d -exec chmod 755 {} \;
find "${PACKAGE_NAME}_${VERSION}_${ARCH}" -type f -exec chmod 644 {} \;
chmod 755 "${PACKAGE_NAME}_${VERSION}_${ARCH}/DEBIAN"/{postinst,prerm,postrm}
```

### 6. Build & Install Package

```bash
# Build .deb package
dpkg-deb --build "${PACKAGE_NAME}_${VERSION}_${ARCH}" "${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"

# Install package
sudo gdebi -n "${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"

# Start service
sudo systemctl enable --now hyperweaver-server

# Check status
sudo systemctl status hyperweaver-server
```

## Critical Build Notes

### ⚠️ Required Directories

**Must include these directories in the copy command or the package will fail:**

- `utils/` - Contains config loading utilities
- `scripts/` - Contains version synchronization tools
- `ui/` - The fetched Hyperweaver UI artifact (see step 1)

### ✅ Single Source of Truth Versioning

**Root `package.json` is the ONLY place to change the Server version.**

`npm run sync-versions` synchronizes the version to:

- ✅ `config/swagger.js` - API documentation version
- ✅ `packaging/config/production-config.yaml` - Production config version
- ✅ `.release-please-manifest.json` - Release automation tracking

The consumed UI version is pinned separately by `hyperweaverUiVersion` in `package.json`.

### 🔧 Systemd Service

The service includes:

- **Privileged port capabilities** (`CAP_NET_BIND_SERVICE`) for ports 80/443
- **Environment variables** (`CONFIG_PATH=/etc/hyperweaver-server/config.yaml`)
- **Security restrictions** (NoNewPrivileges, ProtectSystem, etc.)

## Automated CI/CD

### Release Please Integration

Every push to main triggers Release Please:

1. **Creates release PR** with version bumps and changelog
2. **Merges PR** → triggers package build (`.github/workflows/prod-build.yml`)
3. **Creates GitHub release** with `.deb` package attached
4. **Uses semantic versioning** based on conventional commits

### Manual Release Trigger

```bash
gh workflow run release-please.yml
```

## Package Information

- **Service User**: `hyperweaver-server` (created during installation)
- **Configuration**: `/etc/hyperweaver-server/config.yaml`
- **Data Directory**: `/var/lib/hyperweaver-server/`
- **Log Directory**: `/var/log/hyperweaver-server/`
- **SSL Certificates**: `/etc/hyperweaver-server/ssl/` (auto-generated)
- **JWT Secret**: `/etc/hyperweaver-server/.jwt-secret` (auto-generated)
- **Service**: `systemctl {start|stop|status|restart} hyperweaver-server`
- **Default Access**: `https://localhost:3443`
- **Manual Pages**: `man hyperweaver-server` and `man hyperweaver-server.yaml`

## Troubleshooting

### Common Build Errors

1. **Cannot find module '/opt/hyperweaver-server/utils/config.js'**
   - ❌ Missing `utils` in copy command
   - ✅ Fix: Add `utils` to the cp command

2. **Blank page / UI not found**
   - ❌ `ui/` not fetched before packaging
   - ✅ Fix: Run the UI fetch in step 1 before copying `ui`

3. **Version shows as unknown in frontend**
   - ❌ Version sync issue
   - ✅ Fix: Run `npm run sync-versions`

### Service Issues

```bash
# Check logs
sudo journalctl -fu hyperweaver-server

# Check config
sudo cat /etc/hyperweaver-server/config.yaml

# Restart service
sudo systemctl restart hyperweaver-server
```

### Uninstall

```bash
sudo systemctl stop hyperweaver-server

sudo apt remove hyperweaver-server

sudo apt autoremove

# Purge DB and Configs
sudo apt purge hyperweaver-server
```
