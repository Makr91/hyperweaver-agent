# Notifications from the STARTcloud UI estate

Estate-wide tracking is `../authorization-server-private/priorities.yaml`,
read-only from this repository. The contracts are
`../startcloud-ui/docs/guides/universal-*.md` and
`../startcloud-ui/docs/guides/preferences-and-branding.md`, with the
ordered UI work in `../startcloud-ui/docs/guides/UI-GROWTH-GUIDE.md`; the
copies under `../authorization-server-private/docs/guides/` are pointer
stubs and are never cited. The governing rules and the D-ledger for the
hyperweaver family are `../hyperweaver-docs/docs/roadmap.md`. In the
contracts "UI backend" is the application, in any language, that serves the
shared build and answers `GET /api/status`; this agent is one. Every item
below is open until the code shows it closed; an item is deleted when it is
done. Read every file named here in full before acting on any of it.

## 1. The rule

Why: a UI backend that keeps its API at the root cannot serve the one shared
UI, so every estate page, deep link and notification link into this agent
lands on a 302 or a 404 instead of the page.

The SPA owns `/`. Everything a program calls lives under `/api`, plus the
paths a client protocol dictates (Vagrant's box shapes on BoxVault, the
catalog's `/catalog.json`). A machine and a browser asking for the same
root URL are told apart by the client's own signal, `Accept` or user
agent, the way Vagrant Cloud answers `/myuser/test` with JSON for `vagrant
box add` and a page for a person. No UI backend redirects, and no UI backend
puts a reverse proxy in front of itself to do so. The UI build is
`base: '/'`, the router owns `/`, and a UI backend's fallback for a browser
page request is `index.html`, tried after every API and protocol route, in
any language.

It is written in `universal-navbar.md:535-576` under Where the UI is
served, which names hyperweaver-ui's `/ui/` as the one fact that separates
the two families until the agents move, and in
`universal-pages.md:625-633` under Hosting notes.

## 2. Why

Why: without the reasoning recorded, the next session reads `/ui/` as a
choice worth keeping and re-argues a settled rule instead of moving the
routes.

This agent, zoneweaver-agent and hyperweaver-server mount their API at
the origin root, so hyperweaver-ui could not own `/` and took `/ui/`,
while BoxVault and the catalog keep their machine surface under `/api`
and their UI at `/`. The industry splits the same way: Vagrant Cloud,
GitLab, Gitea, Grafana, Proxmox, Portainer, Home Assistant, Harbor, Nexus
and Jenkins serve the UI at `/` with the API under a prefix; Vault,
Consul, Nomad, Artifactory 7 and Cockpit put the UI under a prefix
because the API owns their root. The STARTcloud UI backends cannot take a
redirect (GitHub Pages issues none, and BoxVault's root links are in
emails, notifications and badges), so `/` won.

## 4. What joining the rule means here, in order

Why: the steps depend on each other in this order; serving the SPA at `/`
before the routes move makes the file server shadow the API, and consuming
a `base: '/'` build before either breaks every asset path.

1. Consume a hyperweaver-ui build made with `base: '/'` (that repository's
   `notifications.md` section 6 lists its side). Open:
   `G:\Projects\hyperweaver-ui\vite.config.js:53`; `.ui-version:1`.

The agents move first because the UI cannot own `/` while the API does.

## 5. Where the contracts live

Why: a change made from memory of a contract drifts from the other UI
backends; the contract text is the only thing every backend is checked
against.

- `../startcloud-ui/docs/guides/universal-navbar.md` (the status payload
  `:578-688`, the sidebar `:358-475`, where the UI is served `:535-576`,
  the footer `:795-910`), `universal-pages.md` (reserved segments
  `:136-153`, hosting notes `:625-647`), `universal-session.md` (backends
  `:403-422`), `universal-events.md`, `universal-validation.md`,
  `universal-config.md`, `preferences-and-branding.md`,
  `universal-identity.md` (decision 40 at `:2076-2077`),
  `UI-GROWTH-GUIDE.md` (decisions e at `:56` and ab at `:62`)
- `../authorization-server-private/priorities.yaml`: `:107-114` (the
  family briefs), `:180-188` (validation), `:189-198` (config; `:194`
  names this repository), `:199-203` (health), `:276-281` (testing),
  `:293-300` (license)
- `G:\Projects\startcloud-ui\README.md`: Hosting the UI
- `G:\Projects\hyperweaver-ui\notifications.md`: the UI side of the same
  rule and the feature-first tree

## 6. Stale documentation

Why: the README roadmap hides shipped work and advertises Vagrant
orchestration that never runs, the wrong Go version and the incomplete
sample config fail a first build or a first boot, and the packaging README
stages a package missing the PKI, man pages and seeds the workflow ships.

| File:line | What it says | What is true | Required change |
| --- | --- | --- | --- |
| `README.md:20-22` | Roadmap: provisioning engine, API-key auth with tray handoff, VNC over WebSocket, BoxVault integration, OIDC federation | all shipped: `internal/provisioner/generate.go:138-163`, `server_routes.go:299-301,339-353`; `internal/auth/middleware.go:128-182`, `internal/auth/traytoken.go:36-83`, `internal/server/trayclaim.go:63-110`; `internal/server/vnc.go:199-288`, `server_routes.go:263-265`; `internal/server/templates_remote.go:240-334`, `config.go:172-177`; `internal/server/oidc_login.go:93-139`, `oidc_silent.go:131-190`, `server_routes.go:26-29` | rewrite the section as Current features, or delete it |
| `README.md:22`, `README.md:115` | `vagrant`/`VBoxManage` orchestration; the agent manages VMs "via Vagrant" | `main.go:26` and `internal/machines/create_exec.go:14-20`: native VBoxManage orchestration, vagrant is never executed, vagrant projects are discovered read-only | say VBoxManage; remove the Vagrant claims |
| `README.md:75`, `CONTRIBUTING.md:32` | Requires Go 1.24+ | `go.mod:3` is `go 1.25.0` | state the version `go.mod` states, and keep them equal |
| `README.md:51-69` | the sample `config.yaml` | `internal/config/defaults.go:14-471` carries `https_port`, `ssl`, `cors`, `api_keys`, `oidc`, `logging.compression`, `logging.categories` and every later section | replace the sample with the shape `defaults.go` writes, or point at it |
| `README.md:15` | tray = app name + version, Open, Quit | `internal/tray/tray.go:76-83` adds a Troubleshooting submenu (log, config folder, data folder, restart) | list the submenu |
| `README.md:75-80`, `internal/tray/assets/README.md:4-10` | copy `icon.ico` and `icon.png` from hyperweaver-ui before building | both files are committed and embedded (`internal/tray/icon.go:17-21`; `.gitignore` excludes neither) | drop the copy step from README; keep the assets README as the re-copy instruction only |
| `packaging/DEBIAN/README.md:11-15,36-42` | installed file list and the manual stage tree | `.github/workflows/build-packages.yml:449-477` also installs `/etc/hyperweaver-agent/ssl/{root-ca.crt,ca.crt,ca.key}`, the man5 and man8 pages and `/usr/share/hyperweaver-agent/provisioners-seed`, and needs the PKI fetch of `:402-435` first | list every installed file; add the PKI and seed steps |
| `packaging/DEBIAN/README.md:31` | the build command | `build-packages.yml:440-442` also passes `-X github.com/Makr91/hyperweaver-agent/internal/version.Version=` | add the ldflag |
| `packaging/DEBIAN/man/hyperweaver-agent.yaml.5:669-688` | "the packaged default" example | `packaging/config/production-config.yaml:7-427` carries `https_port`, `ssl`, `cors`, `api_keys` and every other section | replace the example with the packaged file's shape |

## 7. Code gaps against the contracts

Why: `GET /settings` hands the registry token to any admin session in the
clear, the environment handshake breaks a restart under any process manager
that scrubs the environment, the shared UI cannot draw the admin, setup,
health, footer or event surfaces from a status payload and schema it does
not recognise, a refused write paints as a generic card instead of at the
field, a bound IdP token presented as `Bearer` is accepted, and the
catalog's Open-in-Hyperweaver button and the platform-wide `device` removal
both stay blocked on this repository.

Each row: what the code does → required change → deciding source.

| Code file:line | What is | Required change | Deciding source |
| --- | --- | --- | --- |
| `internal/server/server_lifecycle.go:175`; `agent_setup.go:83`; `internal/server/settings.go:236` | the restart-spawned successor learns it is a successor from `HYPERWEAVER_RESTART=1` in its environment | replace the parent-to-child environment handshake with the existing local duplicate-launch handoff channel (`main.go:262-268`, `agent_startup.go:56-73`) or a child flag on `restartArgs` (`main.go:208`) | `universal-config.md:57-60,70`; `priorities.yaml:194` |
| `internal/config/paths.go:123`; `internal/loginitem/loginitem_linux.go:17`; `internal/server/hostsfile.go:28`; `internal/prereqs/prereqs.go:153-154`; `internal/sshrun/sync.go:60`; `internal/hostshell/hostshell_unix.go:27`; `internal/server/settings.go:224` | reads of `XDG_DATA_HOME`, `XDG_CONFIG_HOME`, `SystemRoot`, `VBOX_MSI_INSTALL_PATH`, `VBOX_INSTALL_PATH`, `PATH`, `SHELL`, `INVOCATION_ID` | tolerated as operating-system facts; none may become a configuration setting, and a value the file can carry must come from the file | `universal-config.md:70` |
| `server_routes.go:11-445` | no `GET /api/rules` | a UI backend that accepts writes answers `GET /api/rules` with its forms as JSON Schema 2020-12 and the estate's `$defs` | `universal-validation.md:72-162` |
| `internal/server/status.go:21-40` | no `analytics` member | optional: `{ script_url, attribute, value }` only when an estate-run collector is configured and its hostname is one this agent's configuration names; absent otherwise, and absent today is correct | `universal-navbar.md:623`; `universal-identity.md:261` |
| `internal/server/status.go:21-40`; `server_routes.go:11-445` | the payload carries no sidebar member, and none is wanted: sidebar entries come only from a feature's `sidebar(status, account)` export, and the `actionMenu` swap that moves the user menu to the sidebar's foot is a feature export too | nothing for this agent to add; hyperweaver is named the first fit for the `actionMenu` swap and is not being changed now, so when hyperweaver-ui converges on the shared build its feature owns that export, and no field for it ever lands in `/api/status` | `universal-navbar.md:358-475` (`:434-435`, `:463-468`); `UI-GROWTH-GUIDE.md:56` |
| `internal/auth/middleware.go:101-116`; `internal/server/apikeys.go:73,153` | refused writes answer `{"msg"}` or `{ error, details }`; a bad body answers 400 through the same shapes | every refused write answers `application/problem+json` with `type`, `title`, `status`, `errors[]`; 422 for a rule failure, 409 for `unique`, 400 only for an unreadable request | `universal-validation.md:60-63,357-418,463-464` |
| `internal/server/oidc_jwt.go:32-98`; `internal/auth/middleware.go:94-96,139-145` | an IdP access token is accepted as `Bearer` after signature, `iss`, `aud` and `exp` checks; no `cnf.jkt`, no DPoP proof, the `Authorization` scheme is not read | a key-bound token (`cnf.jkt`) only with the `DPoP` scheme and a proof (`htm`, `htu`, `iat` within 60 s, `ath`, thumbprint equal to `cnf.jkt`, `jti` unseen for 300 s); a bound token presented as `Bearer` refused, an unbound token presented as `DPoP` refused; CORS admitting `Authorization` and `DPoP` | `universal-session.md:403-422`; `universal-events.md:285-293` |
| `internal/keys/keys.go:143`; `middleware.go:140`; `apidocs.go:214` | the API-key prefix is `hw_` | keep `hw_`; a `wh_` anywhere is a defect | this repository's own rule |
| `internal/protocol/protocol.go:34,36-38,64-80`; `internal/server/server_routes.go:32`; `internal/server/trayclaim.go:139-157`; `main.go:132-142,368-374` | the `hwa` scheme is registered and kept; its vocabulary is `open` alone: `ParseAction` refuses any other URL authority or path, the handoff forwards only `POST /protocol/open`, and no URL parameters are read | `hwa://` stays as the desktop hand-off scheme, the reverse-domain form a recorded deviation, so the import action extends it and never replaces it: parse and validate its parameters, forward them through the handoff and the in-process handler, import through the existing import-upload wire (`server_routes.go:341`) with the sha256 verified before the package lands. Two decisions are open in this repository and unset: (a) the action and parameter vocabulary — the straw-man is `hwa://provisioner/import?url=&sha256=&name=&version=`, nothing is fixed; (b) private-artifact handling when the tar.gz needs GitHub auth the agent lacks — refuse with the reason, prompt, or a token the configuration carries, nothing is fixed. The catalog's Open-in-Hyperweaver button is blocked until both are set here | `universal-identity.md:1178-1186,2076-2077`; `C:\Users\Mark\Desktop\hyperweaver-ai-sync.md:91-100`; `internal/server/provisioners.go` (the import-upload handler) |

## 8. Packaging and workflows

Why: on a minimal Debian without `adduser` or `ca-certificates` the
`postinst` fails and the package is left unconfigured, two start-at-login
mechanisms launch two agents or leave a stale shortcut after the setting is
turned off, and a workflow that grows a hand-written smoke script diverges
from every sibling repository the moment the testing contract lands.

| File:line | What is | Required change | Deciding source |
| --- | --- | --- | --- |
| `.github/workflows/build-packages.yml:479-491`; `packaging/DEBIAN/README.md:44-56` | the control block carries no `Depends` | `Depends: adduser, ca-certificates` for `postinst:6` (`adduser`) and `postinst:34` (`update-ca-certificates`) | `packaging/DEBIAN/postinst:5-9,30-35` |
| `packaging/windows/hyperweaver-agent.iss:39,69`; `main.go:216`; `internal/config/config_agent.go:19-24` | two start-at-login mechanisms: the installer's `{userstartup}` shortcut task and the agent's own `startup.start_at_login` convergence | one mechanism: the agent's `startup.start_at_login` owns the registration; the installer task is removed or seeds the configuration value instead of a shortcut | `internal/loginitem/loginitem.go`; `config_agent.go:19-24` |
| `.github/workflows/ci.yml:18-74`; `build-packages.yml:1-554` | the workflows carry lint, build, vet, govulncheck, CodeQL and the packaging steps, and no hand-written smoke script | keep it so: a check that must survive becomes a proper tool in a reusable workflow, never an ad-hoc script; when the Universal Testing Contract is written the browser test tool joins `ci.yml` as a normal step, the same shape as every repository of this class | `priorities.yaml:71-74,276-281`; `universal-identity.md:309-318,2030-2033`; `UI-GROWTH-GUIDE.md:62` |
| `README.md:127`; `LICENSE.md`; `versioninfo.json:26`; `packaging/macos/Info.plist:43` | GPL-3.0 stated in every place this repository names a license | nothing here until the estate picks one license; when it does, every place above changes together | `priorities.yaml:293-300` |

## 9. Hardening items

Why: clock drift against the identity provider rejects valid tokens
outright, any `Authorization` scheme passes as a credential, a flood of
unknown `kid` values turns into a JWKS fetch each, a requested claim is
thrown away, and the namespace split sends a release, an installer and a
module path to three different owners.

| # | Code file:line | What is | Required change |
| --- | --- | --- | --- |
| 1 | `internal/server/oidc_jwt.go:68-76,86` | expiry is a bare `exp <= now`; `nbf` and `iat` are not read; no clock-skew leeway | validate `nbf` and `iat` when present with a small leeway |
| 2 | `internal/auth/middleware.go:94-96` | `ExtractKey` takes the second half of any `Authorization` value regardless of scheme | read the scheme: `Bearer` for keys and unbound tokens, `DPoP` for bound tokens, anything else refused |
| 3 | `internal/server/oidc_flow.go:148-169,181-184` | an unknown `kid` forces a JWKS refetch on every request | a refresh cooldown and a negative cache for unknown `kid` values |
| 4 | `internal/server/oidc_flow.go:199,361-362` | every OIDC identity is `admin` | keep for the bound single-user desktop model; any multi-user use maps the role from claims |
| 5 | `internal/config/config.go:77`; `defaults.go:124-129`; `settings_schema_core.go:246-247`; `oidc_jwt.go:68-76` | the `organizations` scope is requested and the claim is never parsed | parse it (organization display, future ACLs) or stop requesting it |
| 6 | `internal/server/oidc_flow.go:1`, `oidc_jwt.go:1`, `oidc_silent.go:1`, `oidc_provider.go:1`, `oidc_state.go:1`, `oidc_refresh.go:1`, `oidc_login.go:1` | the OIDC files live in `package server` with no dependency on it | move them to `internal/oidc/` |
| 7 | `internal/server/oidc_flow.go:45-76,117-124,171-200,202-238`; `server.go:85` | one `oidcManager` is the resource-server validator, the OAuth client (device, silent, refresh) and the outbound token source | split the three roles when next touched |
| 8 | `go.mod:1`; `.github/workflows/build-packages.yml:47,64,92`; `.golangci.yml:70`; `packaging/macos/Info.plist:10,43`; `packaging/windows/hyperweaver-agent.iss:11-12`; `README.md:16,26,89` | three namespaces: the `Makr91` module path and release URLs, the `MarkProminic` UI artifact, the `STARTcloud` seeds, PKI, publisher and bundle id | consolidate under one namespace in a quiet window; import-path churn |
| 9 | `.github/workflows/build-packages.yml:40-116,201-262,374-435` | the UI bake, seed and PKI steps are repeated across the three OS jobs | a composite action, or the duplication kept knowingly |
| 10 | `.golangci.yml:26-35,47-54` | `gosec` excludes G204 file-wide; `forbidigo` bans `fmt.Print*` | keep both scoped and intentional |
| 11 | `README.md:75`; `CONTRIBUTING.md:32`; `go.mod:3` | Go 1.24+ in the docs, `go 1.25.0` in `go.mod` | the docs state the `go.mod` version |
