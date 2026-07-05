# Tray icon assets

The tray icon reuses the Hyperweaver UI's favicon artwork so the tray matches
what users see in their browser tab. Two binary files live here (committed to
git, embedded into the binary at build time):

- `icon.ico` — copy of `hyperweaver-ui/public/favicon.ico` (Windows tray + exe icon)
- `icon.png` — copy of `hyperweaver-ui/public/images/logo192.png` (macOS/Linux tray)

When the UI project's artwork changes, re-copy both files.
