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
| `internal/config/paths.go:123`; `internal/loginitem/loginitem_linux.go:17`; `internal/server/hostsfile.go:28`; `internal/prereqs/prereqs.go:153-154`; `internal/sshrun/sync.go:60`; `internal/hostshell/hostshell_unix.go:27`; `internal/server/settings.go:224` | reads of `XDG_DATA_HOME`, `XDG_CONFIG_HOME`, `SystemRoot`, `VBOX_MSI_INSTALL_PATH`, `VBOX_INSTALL_PATH`, `PATH`, `SHELL`, `INVOCATION_ID` | tolerated as operating-system facts; none may become a configuration setting, and a value the file can carry must come from the file | `universal-config.md:70` |
| `internal/server/status.go:21-40` | no `analytics` member | optional: `{ script_url, attribute, value }` only when an estate-run collector is configured and its hostname is one this agent's configuration names; absent otherwise, and absent today is correct | `universal-navbar.md:623`; `universal-identity.md:261` |
| `internal/server/status.go:21-40`; `server_routes.go:11-445` | the payload carries no sidebar member, and none is wanted: sidebar entries come only from a feature's `sidebar(status, account)` export, and the `actionMenu` swap that moves the user menu to the sidebar's foot is a feature export too | nothing for this agent to add; hyperweaver is named the first fit for the `actionMenu` swap and is not being changed now, so when hyperweaver-ui converges on the shared build its feature owns that export, and no field for it ever lands in `/api/status` | `universal-navbar.md:358-475` (`:434-435`, `:463-468`); `UI-GROWTH-GUIDE.md:56` |
| `internal/keys/keys.go:143`; `middleware.go:140`; `apidocs.go:214` | the API-key prefix is `hw_` | keep `hw_`; a `wh_` anywhere is a defect | this repository's own rule |

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

Why: a requested claim is thrown away, and the namespace split sends a
release, an installer and a module path to three different owners.

| # | Code file:line | What is | Required change |
| --- | --- | --- | --- |
| 1 | `internal/server/oidc_flow.go:199,361-362` | every OIDC identity is `admin` | keep for the bound single-user desktop model; any multi-user use maps the role from claims |
| 2 | `internal/config/config.go:77`; `defaults.go:124-129`; `settings_schema_core.go:246-247`; `oidc_jwt.go:68-76` | the `organizations` scope is requested and the claim is never parsed | parse it (organization display, future ACLs) or stop requesting it |
| 3 | `internal/server/oidc_flow.go:1`, `oidc_jwt.go:1`, `oidc_silent.go:1`, `oidc_provider.go:1`, `oidc_state.go:1`, `oidc_refresh.go:1`, `oidc_login.go:1` | the OIDC files live in `package server` with no dependency on it | move them to `internal/oidc/` |
| 4 | `internal/server/oidc_flow.go:45-76,117-124,171-200,202-238`; `server.go:85` | one `oidcManager` is the resource-server validator, the OAuth client (device, silent, refresh) and the outbound token source | split the three roles when next touched |
| 5 | `go.mod:1`; `.github/workflows/build-packages.yml:47,64,92`; `.golangci.yml:70`; `packaging/macos/Info.plist:10,43`; `packaging/windows/hyperweaver-agent.iss:11-12`; `README.md:16,26,89` | three namespaces: the `Makr91` module path and release URLs, the `MarkProminic` UI artifact, the `STARTcloud` seeds, PKI, publisher and bundle id | consolidate under one namespace in a quiet window; import-path churn |
| 6 | `.github/workflows/build-packages.yml:40-116,201-262,374-435` | the UI bake, seed and PKI steps are repeated across the three OS jobs | a composite action, or the duplication kept knowingly |
| 7 | `.golangci.yml:26-35,47-54` | `gosec` excludes G204 file-wide; `forbidigo` bans `fmt.Print*` | keep both scoped and intentional |
| 8 | `README.md:75`; `CONTRIBUTING.md:32`; `go.mod:3` | Go 1.24+ in the docs, `go 1.25.0` in `go.mod` | the docs state the `go.mod` version |

## 10. What the shared UI asks of this agent for the local user

Why: the person at a desktop agent is its owner, not a guest; they sign
in once by the tray and expect the same Profile page every other host of
the estate draws, their preferences kept for them, and no timer anywhere
in the shared UI. In Mark's words: "THIS IS NOT A WEB SITE FOR THE
PUBLIC ... A LOCAL USER RUNNING HYPERWEAVER AGENT ON THEIR LOCAL
MACHINE, THEY ARE NOT A GUEST, AND SINCE THEY HAVE LOCAL ACCESS THEY
NEED NO LOGINS, SURE WE CAN MAKE A USER PROFILE END POINT SO WE CAN
TRACK THE DETAILS FOR THE USER".

| Code file:line | What is | Required change | Deciding source |
| --- | --- | --- | --- |
| `internal/server/apikeys.go` (`GET /api/api-keys/info`), `server_routes.go` | the key's profile alone; no `/api/user`, no preferences | `GET /api/user` answering the signed-in person in the identity provider's profile shape the shared UI reads (`id`, `username`, `name`, `email`, `role`, `preferred_language`, `preferred_mode`, `preferred_theme`, `preferred_motion`, `preferred_timezone`), the identity the key was minted with and the preferences stored beside it; `PATCH /api/user/preferences` with the branding contract's write path (`language`, `mode`, `theme`, `motion`, `timezone`, an omitted key unchanged, `null` clearing, a `422` problem body per failing member), stored on this agent for its local user; `profile-updated` on the `profile` topic of the stream when a write changed a column | `preferences-and-branding.md` (Write path; "the account value is authoritative ... a local account with preference columns counts"); `universal-session.md` (the session's `load` reads `/api/user`) |
| `internal/server/oidc_login.go` (`GET /api/auth/oidc/device-status`) | answers the handle's status at once, `pending` while nothing changed | the brief's own offer, taken: the request stays open until the status leaves `pending` or a wait the agent bounds ends (the RFC's `interval` is a fine bound), then answers the same body; `?wait=0` for the immediate answer; the approved answer still delivered once | `agent-signin-brief.md:229-234`; `universal-session.md` (no timer in the UI); RFC 8628 §3.5 |
| `internal/server/events.go` (`GET /api/events`) | the `admin` topic answers 403 to a non-admin key | the shared UI opens the one stream with every topic `status.events.topics` lists, so a viewer or operator key gets no stream at all; answer the stream with the topics the key's role may read and leave the others out, 403 only when it may read none | `universal-events.md` (one stream, the topics the status advertises); `src/lib/runtime.js` `connectEventStream` |

## 11. What the shared UI reads from `GET /api/status` and the host's own row

Why: the shared UI builds every surface from the status payload and from
the host's own row, and asks nothing of a route whose token the row does
not list; a token this agent leaves out draws nothing, and a member it
leaves out is read as absent, so the payload is the one list of what the
UI shows here. On this agent's role the host's own row is the status
payload itself (`../startcloud-ui/src/features/hosts/utils/hosts.js:76-81`),
so `features`, `console`, `hypervisors` and `platform` are read from one
document for the shell and for every host surface alike.

Every file below is under `../startcloud-ui/src/`.

### The top-level members

| Member | Read by | Present | Absent | Deciding source |
| --- | --- | --- | --- | --- |
| `role` | `features/hosts/utils/hosts.js:12,25-26`; `app/router.jsx:700,1436`; `hooks/useTicketUrl.js:12`; `features/about/hasAbout.js:10`; `features/search/hooks/useAppSearch.js:20`; `app/index.jsx:41` | `hyperweaver-server` addresses every agent read at `/api/agents/{id}/…`, `/` draws the hosts page and the organization filter; any other role addresses `/api/…` and `/` draws the dashboard; `zoneweaver-agent` opens `/setup/zone`; the update command and the `about.<role>.*` keys follow it | required, `statusShape` | `universal-navbar.md:1503` |
| `version` | `components/layout/AppShell.jsx:87,282,577`; `features/about/components/AboutRoute.jsx:173`; `hooks/useTicketUrl.js:30` | the footer's `v<version>`, the About chip, the ticket `context`, the user menu's version while `footer` is not listed | required | `universal-navbar.md:1503,1824-1833` |
| `brand { name, logo_url, repo, changelog, theme, themes }` | `lib/runtime.js:79-94,203`; `contexts/StatusContext.jsx:77-88`; `app/App.jsx:198-199,218-219,275`; `components/layout/AppShell.jsx:86,281,570,576`; `config/brand.js:9,18`; `components/common/BrandLogo.jsx:12-13`; `features/about/components/AboutRoute.jsx:70-71,82,159`; `features/hosts/components/InactiveConsoleDisplay.jsx:324`, `VncConsoleDisplay.jsx:133`; `components/layout/SearchPanel.jsx:246`, `Search.jsx:305`; `features/search/components/SearchPage.jsx:200`; `features/notifications/api/adapters.js:66` | `name` names the app everywhere, `logo_url` is the mark, the favicon and the console placeholder, `repo` and `changelog` the About links, `theme` the pack stamped as `data-brand`, `themes` the Theme picker completed from the build's manifest | `name` and `logo_url` required, `brand.logo_url.replace` throws without them | `universal-navbar.md:1504` |
| `auth` | `utils/capabilities.js:49-55` through `lib/createSession.js:50-97`, `lib/runtime.js:212`, `app/router.jsx:333,443,623,744,1537-1539`, `app/App.jsx:170-171`, `components/layout/AppShell.jsx:47,478-479`, `app/index.jsx:39`, `features/auth/utils/agentSignIns.js:17-23`, `features/hosts/sidebar.js:97`, `features/vdi/sidebar.js:118`, `features/profile/sidebar.js:85`, `components/common/SignInPlacard.jsx:51`, `features/notifications/api/adapters.js:48,63` | the first word picks the provider: `apikey` is `createApiKeySession`, `/login` drawing `AgentSignIns` (`features/auth/components/AgentSignIns.jsx`), the second word `oidc` the device flow and the loopback silent probe; `none` no session; `backend`, `idp`, `cookie` their providers | `backend`; an empty list is `none` | `universal-session.md:22,307-332`; `universal-navbar.md:1505` |
| `bootstrapAvailable` | `features/auth/utils/agentSignIns.js:23` | the first-boot form on `/login`, `POST /api/api-keys/bootstrap` | no form | `universal-session.md:307-332` |
| `hostname` | `features/hosts/utils/hosts.js:78`; `features/auth/components/AgentSignIns.jsx:303` | the one host's row is named by it; the key form's hidden username | `window.location.hostname` | `universal-navbar.md:1555` |
| `features` | `utils/capabilities.js:11-28`; `features/hosts/utils/capabilities.js:13-14` | the gate of every surface below | no array: `hasFeature` answers true for every shell token, `hasFeatureStrict` false, so `hosts` and `fleet` never draw, and `hostHasFeature` false, so no host surface draws | `universal-navbar.md:1511` |
| `events { path, topics }` | `lib/runtime.js:166-177`; `hooks/useSessionKeepalive.js:41-50`; `components/layout/AppShell.jsx:286`; `hooks/useSidebarBadges.js:44`; `components/layout/NotificationsItem.jsx:20`; `features/hosts/utils/machineTools.js:113-131` | with the `events` token one stream at `path` with every topic of `topics`, a same-origin path alone; a topic a host lists in `events.topics` is followed instead of a read | no stream; every page reads on open, on Refresh and after the person's own action | `universal-events.md:68-88`; `universal-navbar.md:1514` |
| `config` | `hooks/useConfigTree.js:31`; `app/router.jsx:440,730`; `features/setup/components/SetupPage.jsx:66`; `features/admin/components/AdminConfig.jsx:104`; `features/admin/sidebar.js:34`; `features/identity/sidebar.js:48` | one route per name at `/admin/config/<name>`, the Configuration row while one name and the tree while more, the setup page's tabs | the empty state `configManager.noFiles`, no `config` adapter | `universal-navbar.md:1515` |
| `links { docs, contact, api, community }` | `components/layout/AppShell.jsx:337-352,561`; `app/App.jsx:91-92,100`; `features/hosts/apiReference.js:27`; `features/about/components/AboutRoute.jsx:50,72,76`; `features/onboarding/components/PhoneStep.jsx:100` | Docs, Contact and API reference rows of the user menu's app section, the About page's links | `links` itself required, `status.links.api` is read unguarded at `app/App.jsx:92`; each member absent draws no row | `universal-navbar.md:1512` |
| `ticket` | `hooks/useTicketUrl.js:10,27-30` | the Help row and the cluster's ticket icon from its members | `null` or absent reads `GET /api/config/ticket` | `universal-navbar.md:1513` |
| `analytics` | `lib/runtime.js:96-104,202` | one script tag with the data attribute | nothing | `universal-navbar.md:1506` |
| `idp` | `lib/createSession.js:60-65`; `lib/runtime.js:214-215`; `hooks/useTicketUrl.js:12` | the browser OIDC provider, only while `auth` begins `idp` | nothing on any other `auth` | `universal-navbar.md:1507` |
| `collections` | `utils/capabilities.js:37-38`; `features/collections/registry.js:25-28` | the collections mounted, in order | none mounted | `universal-navbar.md:1508` |
| `organization` | `components/layout/AppShell.jsx:503` | the one organization's crumb is left out | nothing | `universal-navbar.md:1509` |
| `sorts`, `groups` | `utils/capabilities.js:68-87` | a collection level's default sort and grouping | the page's own defaults | `universal-navbar.md:1510` |
| `agent`, `arch`, `platform`, `hypervisors`, `console`, `shi_mode`, `uptime` | nothing reads them at the top level; `platform`, `hypervisors` and `console` are read on the host's row alone (the capabilities table below) | — | — | `hosts.js:76-81` |

### The feature tokens

Shell tokens are read from the status payload; host tokens from the host's own row, which on this agent's role is the same document.

| Token | Surface | Gate | Emitted today (`internal/server/status.go`) | Deciding source |
| --- | --- | --- | --- | --- |
| `hosts` | the thirteen `/hosts/*` routes and `/` as the dashboard; the Hosts group and tree; the Controls menu; the footer's pane; the API reference rows on the server role | `app/router.jsx:448,1338-1413,1476-1482,1541`; `features/hosts/sidebar.js:97`; `features/hosts/actionMenu.js:21`; `features/hosts/footerPane.js:105`; `features/hosts/apiReference.js:28`; `features/hosts/utils/organizations.js:18` | yes | `universal-navbar.md:1555` |
| `sidebar` | the whole sidebar column; without it `sidebarEntries` answers nothing and no feature's group draws, the Hosts group included | `app/router.jsx:620` | no | `universal-navbar.md:369-372,1550` |
| `admin` | `/admin`, `/admin/config/*`, `/admin/system`; the Admin menu row; the Admin sidebar group for `ROLE_ADMIN` | `app/router.jsx:690,717,746`; `app/App.jsx:128`; `features/admin/sidebar.js:31`; `features/identity/sidebar.js:45`; `features/catalog/sidebar.js:30` | yes | `universal-navbar.md:1538` |
| `setup` | `/setup` and the setup gate before every route | `app/router.jsx:1429,1436,1545`; `app/App.jsx:205` | yes | `universal-navbar.md:1537` |
| `health` | the footer's heart over `GET /api/health` | `app/App.jsx:133`; `components/layout/Footer.jsx:33-106` | yes | `universal-navbar.md:1549` |
| `events` | the one stream | `components/layout/AppShell.jsx:286`; `hooks/useSessionKeepalive.js:41`; `hooks/useSidebarBadges.js:44`; `components/layout/NotificationsItem.jsx:20`; `features/hosts/utils/machineTools.js:115` | yes | `universal-navbar.md:1553` |
| `footer` | the footer row; without it the version moves to the user menu | `components/layout/AppShell.jsx:87,276` | yes | `universal-navbar.md:1556` |
| `search` | the navbar search box, its panel and `/search` over `GET /api/search` | `app/router.jsx:1588`; `components/layout/SearchPanel.jsx:288`; `components/layout/Search.jsx:234` | no | `universal-navbar.md:1552` |
| `notifications` | the Notifications menu row and the inbox adapter | `app/App.jsx:85` | no | `universal-navbar.md:1548` |
| `favorites` | the Add to Favorites toggle on About | `features/about/components/AboutRoute.jsx:157` | no | `universal-navbar.md:1547` |
| `local-accounts` | `/register`, `/registration`, `/passwordRecovery`, `/passwordReset`; the profile's password, email and delete sections; the setup page's sign-in link | `app/router.jsx:340,1029,1152,1641`; `features/setup/components/SetupPage.jsx:164` | no | `universal-navbar.md:1536` |
| `discover` | `/organizations/discover` and the cluster's compass | `app/router.jsx:1598`; `components/layout/AppShell.jsx:545`; `features/organizations/components/OrganizationsPage.jsx:396` | no | `universal-navbar.md:1540` |
| `org-console` | `/org-console`, `/user/organizations`; the Organization console menu row and sidebar row | `app/router.jsx:1103,1220,1233,1239`; `app/App.jsx:130`; `features/profile/sidebar.js:96` | no | `universal-navbar.md:1539` |
| `invitations` | the Invitations tab of the organization console; `/org/invite` | `app/router.jsx:1245`; `features/organizations/components/IssuerOrgConsole.jsx:1025`, `OrgConsolePage.jsx:598` | no | `universal-navbar.md:1541` |
| `tfa`, `onboarding`, `interstitials`, `inbox`, `integrations`, `policies` | the identity provider's pages, under the `cookie` auth token alone | `app/router.jsx:1028-1133,1259-1271`; `features/identity/sidebar.js:124`; `features/profile/sidebar.js:110-128`; `components/layout/AppShell.jsx:56` | no | `universal-navbar.md:1566` |
| `fleet` | `/` as the fleet page, `/vm/:instance`, the Fleet group | `app/router.jsx:1540,1576`; `features/vdi/sidebar.js:118` | no | `universal-navbar.md:1554` |
| `uploads` | every write control of the boxes, ISOs and downloads collections | `utils/permissions.js:104`; `features/collections/boxes/components/BoxList.jsx:129`, `BoxItem.jsx:497,719,820`, `BoxVersion.jsx:134,288,401,588,626`, `BoxProvider.jsx:120,550,589`; `isos/components/Iso.jsx:149,329,482,583`, `IsoVersion.jsx:118,260,373,506,572`; `downloads/components/Download.jsx:79,307,398`, `DownloadRelease.jsx:127,303,340,379`, `DownloadPatch.jsx:109,292,466` | no | `universal-navbar.md:1542` |
| `watches` | the watch stars and the Watched filter | `features/collections/registry.js:28` | no | `universal-navbar.md:1544` |
| `deploy` | the Deploy glyph and column | `features/deploy/components/DeployControls.jsx:86,122` | no | `universal-navbar.md:1545` |
| `rebuild` | the Rebuild catalog data menu row | `app/App.jsx:132` | no | `universal-navbar.md:1546` |
| `private-catalogs` | the memberships handed to the catalog adapter | `app/App.jsx:183` | no | `universal-navbar.md:1543` |
| `browse` | the catalog's Browse group for every visitor | `features/catalog/sidebar.js:30` | no | `universal-navbar.md:1551` |
| `machines` | the Machines page and tab, the tree's machine rows, the machine page's row and detail, the bulk rows, New machine, Import, the orchestration section, the dashboard's counts | `features/hosts/pages.js:48`; `components/HostPage.jsx:120`; `components/MachinesPage.jsx:376`; `hooks/useHostMachines.js:130`; `hooks/useMachineDetail.js:38`; `components/HostControls.jsx:75,94`; `utils/machineCreate.js:111`; `utils/machineTools.js:157`; `components/NetworkingPage.jsx:125`; `components/ManagePage.jsx:420`; `components/NetworkTopology/useTopologyFeed.js:87`; `components/Dashboard/Dashboard.jsx:180-181`, `DashboardServerCards.jsx:48`, `DashboardQuickActions.jsx:120`, `DashboardSummaryCards.jsx:66`; `utils/manage.js:45,237` | yes | `universal-navbar.md:1559,1564` |
| `machine-create` | New machine and the create wizard, Clone, the provisioning editor and Hosts.yml | `utils/machineCreate.js:112`; `utils/machineTools.js:107`; `utils/provisioning.js:77` | yes | `universal-navbar.md:1562` |
| `machine-modify` | the Settings page and tab, the retention policy, a topology rewire | `machinePages.js:36`; `components/MachineSettingsView.jsx:34`; `utils/machineTools.js:102`; `components/NetworkTopology/TopologyPanel.jsx:471` | yes | `universal-navbar.md:1562` |
| `machine-snapshots` | the Snapshots page and tab, the Snapshot row, the clone's snapshot picker | `machinePages.js:44`; `hooks/useMachineSnapshots.js:44`; `utils/machineTools.js:60,93,237` | yes | `universal-navbar.md:1562` |
| `machine-screenshot` | the Screen card and the console's frame of a running machine | `components/MachineScreenshotCard.jsx:87`; `components/InactiveConsoleDisplay.jsx:149`; `components/VncConsoleDisplay.jsx:67` | yes | `universal-navbar.md:1561` |
| `machine-suspend` | Suspend, and Resume of a paused machine | `utils/capabilities.js:55,83` | yes | `universal-navbar.md:1559` |
| `machine-resume-suspended` | Resume of a machine whose row reads `suspended` | `utils/capabilities.js:57` | no | `universal-navbar.md:1559,2155-2160` |
| `host-power` | Restart host and Power off host, the tree's host rows, the Runlevel section | `components/HostControls.jsx:74`; `hooks/useTreeMenu.js:180`; `utils/manage.js:245` | while `host_power.enabled` | `universal-navbar.md:1559,1564` |
| `host-fast-reboot` | the fast reboot among the restart's options | `components/HostRows.jsx:111`; `components/TreeDialogs.jsx:42` | no | `universal-navbar.md:1559,2155-2160` |
| `host-launchers` | the Open in application rows, the console's launchers, the Applications tab of Agent settings | `components/ApplicationRows.jsx:24`; `components/ConsoleLaunchers.jsx:18`; `components/InactiveConsoleDisplay.jsx:154`; `components/AgentSettings.jsx:423` | yes | `universal-navbar.md:1559` |
| `host-terminal` | the footer's Shell view | `footerPane.js:85` | yes | `universal-navbar.md:1558` |
| `tasks` | the footer's Tasks view, the task queue row, View task on every queued notice, the task dialog | `footerPane.js:86`; `hooks/useFocus.js:49`; `utils/monitoring.js:25`; `hooks/useHostManage.js:112`; `hooks/useMachineTools.js:18`; `hooks/useZfsTools.js:57`; `hooks/useSettingsApply.js:56`; `hooks/useNetworkingTools.js:20`; `components/MachineProvisioning.jsx:215` | yes | `universal-navbar.md:1557,1560` |
| `monitoring` | the monitoring service and health rows, the interfaces, the storage summary, the performance charts, the monitoring database, the networking page's tables and charts, the machine's charts | `utils/monitoring.js:16-39,70-119`; `utils/machineTools.js:176`; `components/NetworkStorageSummary.jsx:156`; `components/PerformanceCharts.jsx:39` | yes | `universal-navbar.md:1560,1563` |
| `zfs` | the Storage page and tab, the ZFS management, the storage summary, the Storage I/O and ARC charts, the holds, the rollback wording, the ZFS placement of the create wizard, the Storage and ARC sections | `pages.js:76`; `utils/StorageUtils.js:57`; `utils/machineTools.js:60,94,236`; `utils/monitoring.js:22-23,101,109,117`; `components/MachineCreateModal.jsx:155`; `components/MachineSettings.jsx:569`; `utils/manage.js:122,129` | no | `universal-navbar.md:1560,1562` |
| `swap` | the swap bar | `utils/monitoring.js:26` | yes | `universal-navbar.md:1560` |
| `provisioning` | the pipeline rows, the Provisioning status card, the provisioning tools row, the Provisioning network and Recipes sections | `utils/provisioning.js:73`; `components/MachineProvisioning.jsx:170`; `utils/monitoring.js:27`; `hooks/useManageCatalogData.js:145`; `utils/manage.js:212,220` | yes | `universal-navbar.md:1560` |
| `provisioner-registry` | the roles catalog of the editor, the Provisioners section, with `artifacts` the Installer files section | `utils/provisioning.js:78`; `components/ProvisioningEditor.jsx:306`; `hooks/useManageCatalogData.js:144,147`; `utils/manage.js:204,253` | yes | `universal-navbar.md:1560,1310` |
| `templates` | Convert to template, the template of a snapshot, the wizard's box catalogs, the Templates section | `utils/machineTools.js:95`; `components/MachineCreateModal.jsx:157`; `hooks/useManageCatalogData.js:146`; `utils/manage.js:229` | yes | `universal-navbar.md:1562` |
| `artifacts` | the ISO and artifacts section, the wizard's cached ISOs, the unattended install's cached ISO, with `provisioner-registry` the Installer files section | `hooks/useArtifactStorage.js:46`; `components/MachineCreateModal.jsx:158`; `components/UnattendedInstallModal.jsx:153`; `hooks/useManageCatalogData.js:144`; `utils/manage.js:137,253` | while `artifact_storage.enabled` | `universal-navbar.md:1310` |
| `secrets` | the Global secrets tab of Agent settings | `components/AgentSettings.jsx:422` | yes | `universal-navbar.md:807` |
| `ssh` | the SSH console door and start button | `utils/consoles.js:31-36,57`; `components/InactiveConsoleDisplay.jsx:152` | yes | `universal-navbar.md:1565` |
| `guest-agent` | Guest shutdown and reboot on a bhyve host, the guest agent card's requests, the `qga` wire of Run in guest | `utils/capabilities.js:86`; `utils/guestTools.js:29`; `components/MachineGuestAgentCard.jsx:208` | while `guest_agent.enabled` | `universal-navbar.md:1559,1561` |
| `file-browser` | the Browse button of every path field, the File manager section | `components/PathPicker.jsx:244`; `utils/manage.js:188` | while `file_browser.enabled` | `universal-navbar.md:1302` |
| `vnics` | the Networking page (either of two), the VNIC, VLAN, etherstub, bridge and aggregate sections, the routing table, the Network section, the settings page's VNIC feed | `utils/networking.js:8,46`; `utils/networkingManagement.js:80-104`; `utils/monitoring.js:21,28-38`; `components/MachineSettings.jsx:568`; `utils/manage.js:80` | no | `universal-navbar.md:1563,1294` |
| `network-spaces` | the Networking page (either of two), the network spaces section, the topology's VirtualBox shape and the machines usage read | `utils/networking.js:8,46`; `utils/networkingManagement.js:76`; `utils/monitoring.js:34,39`; `components/NetworkTopology/TopologyPanel.jsx:62`, `useTopologyFeed.js:78` | yes | `universal-navbar.md:1563` |
| `ip-addresses` | the addresses section of the networking page | `utils/networkingManagement.js:80`; `utils/monitoring.js:28` | yes | `universal-navbar.md:1125` |
| `hostname` | the hostname section | `utils/networkingManagement.js:102`; `utils/monitoring.js:35` | yes | `universal-navbar.md:1125` |
| `dns` | the DNS section | `utils/networkingManagement.js:104`; `utils/monitoring.js:36` | yes | `universal-navbar.md:1125` |
| `hosts-file` | the hosts file section, with `vnics` the Manage page's Network section | `utils/networkingManagement.js:105`; `utils/monitoring.js:37`; `utils/manage.js:80` | yes | `universal-navbar.md:1125,1294` |
| `devices` | the Devices page and tab | `pages.js:69`; `components/DevicesPage.jsx:212` | no | `universal-navbar.md:802` |
| `services` | the Services section | `hooks/useHostManageData.js:58`; `components/ManagePage.jsx:481`; `utils/manage.js:72` | no | `universal-navbar.md:1293,1564` |
| `processes` | the Processes section | `hooks/useHostManageData.js:59`; `components/ManagePage.jsx:491`; `utils/manage.js:153` | yes | `universal-navbar.md:1300,1564` |
| `system-users` | the Users and groups section | `hooks/useHostManageData.js:60`; `components/ManagePage.jsx:469`; `utils/manage.js:196` | no | `universal-navbar.md:1303,1564` |
| `time-sync` | the Time and NTP section | `hooks/useHostManageData.js:61`; `components/ManagePage.jsx:561`; `utils/manage.js:145` | no | `universal-navbar.md:1299,1564` |
| `packages` | the Packages and System updates sections, with `repositories` the Repositories section | `hooks/useHostManageData.js:62`; `hooks/useManageSectionsData.js:59`; `hooks/useManageCatalogData.js:143`; `components/ManagePage.jsx:571`; `utils/manage.js:87,95,103` | no | `universal-navbar.md:1295-1296,1564` |
| `repositories` | with `packages` the Repositories section | `hooks/useManageSectionsData.js:59`; `utils/manage.js:95` | no | none names it |
| `boot-environments` | the Boot environments section | `hooks/useManageSectionsData.js:56`; `utils/manage.js:114` | no | `universal-navbar.md:1297` |
| `fault-management` | the Fault management section, with `syslog` and `log-streaming` the two log sections | `hooks/useManageSectionsData.js:52`; `utils/manage.js:164,172,180` | no | `universal-navbar.md:1301` |
| `syslog` | with `fault-management` the Syslog section | `hooks/useManageSectionsData.js:54`; `utils/manage.js:180` | no | none names it |
| `log-streaming` | with `fault-management` the System logs section | `hooks/useManageSectionsData.js:55`; `utils/manage.js:172` | no | none names it |

The Manage page draws behind any token of `MANAGE_TOKENS`
(`utils/manage.js:32-47`): `services`, `vnics`, `packages`,
`boot-environments`, `zfs`, `time-sync`, `processes`, `fault-management`,
`file-browser`, `system-users`, `provisioner-registry`, `templates`,
`machines`, `provisioning`. The Agent settings page draws for any row
that names a hypervisor (`utils/agentSettings.js:12`). `system-updates`
and `runlevel` are section keys, gated by `packages` and `host-power`;
no token of those names is read.

### The members of the host's row

| Member | Values read | Read by | Deciding source |
| --- | --- | --- | --- |
| `capabilities.features` | the host tokens above | `utils/capabilities.js:13-14`; `hooks/useFocus.js:11-14`; `hooks/useHostManage.js:111-113`; `utils/machineTools.js:113-117` | `universal-navbar.md:520-530` |
| `capabilities.console` | `vnc`, `zlogin`, `rdp` | `utils/capabilities.js:26-27`; `utils/consoles.js:15-44,57`; `components/InactiveConsoleDisplay.jsx:150-153`; `components/MachineConsolePanel.jsx:93-94`; `components/StandaloneConsole.jsx:47`; `components/StandaloneRdpConsole.jsx:79` | `universal-navbar.md:863,1565` |
| `capabilities.hypervisors` | `virtualbox`, `utm`, `bhyve` | `utils/capabilities.js:38-39,79,86`; `utils/hosts.js:62-66`; `utils/agentSettings.js:12`; `utils/machineTools.js:108-109,158,178-183`; `utils/guestTools.js:26`; `utils/machineSettings.js:669,672,693`; `utils/settingsForm.js:222`; `utils/networkingManagement.js:137`; `hooks/useManageCatalogData.js:145`; `components/MachineCreateModal.jsx:156,695-697`; `components/MachineSettings.jsx:113,400,567`; `components/GeneralSettingsTab.jsx:677`; `components/MachineGuestInfoCard.jsx:96`; `components/ZoneRows.jsx:109`; `components/ManagePage.jsx:457`; `utils/manage.js:278` | `universal-navbar.md:534-567,1562` |
| `capabilities.platform` | `windows`, `darwin` | `utils/manage.js:437`; `utils/networkingManagement.js:150,947` | `universal-navbar.md:1300` |
| `capabilities.role` | `agent` | `sidebar.js:40` | `universal-navbar.md:1555` |
| `capabilities.events.topics` with `capabilities.features` listing `events` | the topics below | `utils/machineTools.js:113-131` | `universal-events.md:68-88` |
| `id`, `hostname`, `entity_name`, `port`, `org_uuids` | the row's name and identity, the organization filter | `utils/hosts.js:49-51`; `components/Dashboard/DashboardServerCards.jsx:93-94`; `utils/organizations.js:31-35` | `universal-navbar.md:1875-1931` |

### The topics the UI subscribes to

| Topic | Event | Fed surfaces | Deciding source |
| --- | --- | --- | --- |
| `health` | `health` | the footer's heart (`components/layout/Footer.jsx:59`) | `universal-events.md:180-201` |
| `tasks` | `task-updated` | the tasks pane (`hooks/useTasks.js:207`), the task dialog (`components/TaskDialog.jsx:372`), the task queue row and the networking answers (`components/HostReadingsProvider.jsx:106`), a machine's detail and snapshots at a task's end (`components/MachineDetailProvider.jsx:144`, `MachineSnapshotsProvider.jsx:139`), the start after a restore (`components/MachineRestoreProvider.jsx:133`), the Manage page's follow (`hooks/useHostManage.js:166`), the ZFS writes (`hooks/useZfsTools.js:43`), the settings apply (`hooks/useSettingsApply.js:214`), the artifact transfers (`hooks/useArtifactDownloads.js:39`), the holds (`components/SnapshotHoldsDialog.jsx:220`), the provisioning status (`components/MachineProvisioning.jsx:185`) | `universal-events.md:254` |
| `hosts` | `stats-updated` | the stats, the machine rows and the details of a host (`components/HostStatsProvider.jsx:127`, `HostMachinesProvider.jsx:137`, `MachineDetailProvider.jsx:139`), the settings apply's stop step (`hooks/useSettingsApply.js:203`); `servers-updated` is the server role's alone (`components/ServersProvider.jsx:111`) | `universal-events.md:255-256` |
| `monitoring` | `cpu-sample`, `memory-sample`, `network-sample`, `pool-io-sample`, `arc-sample`, `disk-io-sample` | the host's series (`components/HostSeriesProvider.jsx:195-205`), a machine's link series on `network-sample` (`components/MachineSeriesProvider.jsx:186`) | `universal-events.md:257-262` |
| `admin` | `restart-required` | the restart card of the configuration page (`components/common/RestartCard.jsx:66`); `blocked-count` is the identity provider's badge (`hooks/useSidebarBadges.js:101`) | `universal-events.md:221-240` |
| `notifications`, `session`, `profile`, `fleet` | `unread-count`, `session-terminated`, `profile-updated`, the fleet events | `components/layout/NotificationsItem.jsx:55`; `hooks/useSessionKeepalive.js:52-58`; `features/vdi/hooks/useFleet.js:77-94`; none of them read from this agent | `universal-events.md:180-219` |

Every subscriber reads again when the stream opens fresh and on `reset`
(`hooks/useEventStream.js`, the `ready` and `reset` handlers of every
provider above).

A token absent from `features` draws nothing and asks nothing of its
routes: no tab, no row, no panel, no request. A token present must have
every route its surface reads answering, because the surface draws and
sends as soon as the row lists it. The sidebar's Hosts group draws only
while `features` lists `sidebar` and `hosts` and a person is signed in
(`app/router.jsx:620`; `features/hosts/sidebar.js:97`).

## 12. Routes the shared UI reads that this agent answers 404 today

Why: the Agent settings page at `/hosts/self/settings` draws "Failed to
load settings: Not found" on the live agent 0.1.4, so the settings, the
API keys and the backups cannot be reached from the shared UI, and the
key a person needs to sign in from another tab cannot be minted there.
Seen live 2026-09-29 against `https://127.0.0.1:9421`.

Every route below is hyperweaver-ui's own call, carried into the shared
UI as it was and prefixed `/api` under section 1's rule; the page reads
each once as it draws and again on Refresh.

| Route the UI sends | Answer today | Read by | Required change |
| --- | --- | --- | --- |
| `GET /api/settings` | 404 | `features/hosts/api/manage.js` (`fetchSettings`), `components/AgentSettings.jsx` | serve the settings document under `/api`, the route `internal/server/settings.go` serves at the root today |
| `GET /api/settings/schema` | 404 | `api/agentSettings.js` (`fetchSettingsSchema`) | serve the schema under `/api` |
| `GET /api/settings/backups` | 404 | `api/agentSettings.js` (`fetchSettingsBackups`) | serve the backups list under `/api`; with it `POST /api/settings/restore/{file}`, `DELETE /api/settings/backups/{file}`, `PUT /api/settings`, `POST /api/server/restart` |
| `GET /api/app/updates/check` | 500 "Failed to check for updates: versioninfo fetch returned 404 Not Found" | `api/agentSettings.js` (`checkAgentUpdate`) | answer `{ update_available: false }` with the reason when the version source cannot be reached, never 500; the page draws no Update button either way |
| `GET /api/api-keys`, `POST /api/api-keys/generate`, `POST /api/api-keys/bootstrap`, `DELETE /api/api-keys/{id}` | unproven, the page never reached them | `api/apiKeyAPI.js`, `components/ApiKeysTab.jsx` | serve under `/api`, the API management tab of the same page |
