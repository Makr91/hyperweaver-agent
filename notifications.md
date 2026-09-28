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

## 0. 2026-09-27: hyperweaver-ui merges into startcloud-ui, and the agents move first

Why, in Mark's words: "its a new merge project, its merging hyperweaver-ui into startcloud-ui, and I want this for alot of reasons"; the Direct-versus-Aggregated mode "is more of a add these options to the system" and "is the first thing we should grow"; the polling "needs to be done for correctness", and the backends update before the port so the UI is ported once and never patched twice.

hyperweaver-ui does not change again. Its pages become features of startcloud-ui reading the status payload and the one event stream, so the port reads the shape below from its first day. Section 7 already lists every gap; this section names the order and the two things the port cannot start without.

1. `GET /api/status` in the shared shape now, `internal/server/status.go:193-240`: `role` is the package name, `hyperweaver-agent`, the way BoxVault answers `boxvault` (the shared UI builds the update command from it; `agent`, `hypervisors`, `platform`, `arch`, `console`, `features` stay as they are, the shared UI's `hasFeature` reads the same tokens); `version`; `brand { name, logo_url: "/brand/hyperweaver/mark.svg", repo }`; `auth` in the estate vocabulary; `features` gaining `footer`, `health` once `/api/health` answers the contract shape, and `events` once the stream exists; `links { docs, contact }`; `ticket` or `null`; `config`. The shared UI tells Direct from Aggregated by `role` alone and addresses this agent at the origin root under `/api` on this role. Deciding source: `universal-navbar.md:578-688`; `universal-events.md:68-88`.
2. `GET /api/events` carrying what the ported pages read instead of polling: the tasks pane (`hyperweaver-ui/src/contexts/FooterContext.jsx:173-206`, every second), the sidebar tree's machine list and running dots (`SidebarTree.jsx:104-142`, every 10 s). Task output is not among them: it stays on the WebSocket it has today (`internal/server/ws.go:172-274`, a WebSocket per task), moved under `/api` with item 3 and otherwise untouched, in Mark's words "for task output speed and reliability is the key", "it'll be used for things like ansible streaming stuff from spinning up VMs", "I just don't want a feature to stop working or degrade in quality". What the stream carries of a task is its row: created, its status, and the `progress_percent` and `progress_info` the playbook's `PROGRESS::` scanner already writes on it (`internal/machines/progress_scan.go:72-99`, `internal/tasks/store_status.go:44-53`), so the progress bar and the step name arrive by push and "generally all timers should go". The names are registered, in Mark's words "if we need event stream then create a fucking event stream", "just do it and make it right": `universal-events.md`, Hyperweaver family, fixes topic `tasks` with the event `task-updated`, one task row as `GET /api/tasks` answers it, sent when a task is created and on every change of its `status`, `progress_percent`, `progress_info` or `error_message`, and topic `hosts` with `stats-updated`, the `GET /api/stats` shape, sent when a machine is created or removed and when one starts or stops; neither topic has a snapshot, and this agent's events carry no `agent_id`, hyperweaver-server adding it as it relays. The shared UI already reads both. The wire can be watched before it is built here: `npm run mock -- agent` in `../startcloud-ui` (`scripts/mock-hyperweaver.js`) streams it. Deciding source: `universal-events.md:40-64,171-271`.
3. The `/api` route move of section 4, unchanged in order.
4. `features` lists `hosts` once items 1 and 3 are in: the token the shared UI's hosts feature is gated by (`universal-navbar.md`, the feature-token table), its pages reading `GET /api/stats` and `GET /api/machines` at this origin; the `machines` rows are read by `name`, `status` and `hypervisor`, this agent's own members, `hypervisor` the engine under that one machine (`virtualbox`, `utm`), read to tell a UTM machine, which has no reset, no pause apart from its suspend and no guest reboot (`../startcloud-ui/src/features/hosts/components/MachineRows.jsx`, `gatesOf`). An earlier text of this item said `brand`; that was wrong. `brand` is zoneweaver-agent's word for a zone's brand and is a different thing, in Mark's words "zoneweaver literally only runs on OmniOS and runs zones, so bhyve, lxc, native etc, so it's not a 1:1 comparison"; nothing is renamed on either agent.
5. The footer's pane, written in `universal-navbar.md` under Footer status, The pane, and drawn live in `../startcloud-ui/docs/guides/universal-footer.html`. Why, in Mark's words: the two footers "converge into one footer", "the existing footer system we have, plus sub configs like we do for health, ie tasks, host-shell or footer shell", the shell "a dynamic thing to be more than just the host shell or host terminal like it is in hyperweaver currently". No new token: the shared UI draws the Tasks toggle behind `tasks` and the footer's one Shell behind `host-terminal`, the names this agent lists today (`internal/server/status.go:97-104`); the footer, in Mark's words, "when a backend app supports it, may offer a Shell, this may be a shell via a pty, a shell via ssh, a shell via some other mechanism", and a terminal per machine behind `ssh` is later work with "a tabbed shell per vm". What it calls, every path under `/api` once item 3 lands: `GET /api/tasks` with `min_priority` and `limit`, `GET /api/tasks/{id}`, `GET /api/tasks/{id}/output`, `DELETE /api/tasks/{id}` (`internal/server/tasks.go:63,161,193,246`); `POST /api/term/start`, `DELETE /api/term/sessions/{id}/stop` and the `/api/term/{id}` upgrade (`internal/server/host_terminal.go:108,166,205`); `GET /api/ws-ticket` and the `/api/tasks/{id}/stream` upgrade (`internal/server/ws.go:90,172`), the terminals staying WebSocket. What is owed beyond the move: within item 2, a topic for the tasks pane, one event whenever a task is created or changes, carrying the row `GET /tasks` answers for it, no snapshot event, the pane reading `GET /api/tasks` when the stream opens fresh and on `reset`; the names are yours to propose, the same as zoneweaver-agent's. hyperweaver-ui asked for the list every second and the open task every two (`hyperweaver-ui/src/contexts/FooterContext.jsx:173-206`, `src/components/TaskDetailModal.jsx:277-290`); the shared UI runs no timer, so until the topic streams the pane reads on open, on Refresh and after the person's own action, and the open task follows `/tasks/{id}/stream`.
6. `GET /api/config/ticket` in plain values. `internal/server/ticket.go:12-37,50-57` wraps every leaf as `{ value }` and answers no `fallback_customer_id`. The shared UI reads the section's leaves plain, `enabled`, `base_url`, `req_type`, `fallback_customer_id` and `context` (`../startcloud-ui/src/hooks/useTicketUrl.js:14-25`), so against this answer `enabled` is an object, which reads as on whatever its value, and `base_url` an object where the link needs a string. Required change: `{ "ticket_system": { "enabled", "base_url", "req_type", "fallback_customer_id", "context" } }` with plain values, or `ticket` in `/api/status` and no route. Deciding source: `universal-navbar.md`, the status payload's `ticket` row and Help ticket.
7. `links.api` in `/api/status`. Why, in Mark's words: "the api docs can be the startcloud-ui way", and of how the reference is drawn: "if we get the API swagger into the react app itself, then as a page section with no navigation if possible, but if we don't have that, then I guess new tab". The shared UI's account menu draws an API reference row from `links.api` of the status payload, after Docs, and draws none while the member is empty or absent (`../startcloud-ui/src/components/layout/AppShell.jsx:345-352`). This agent serves the Swagger page at `/api-docs/` and the public document at `/api-docs/swagger.json` (`internal/apidocs/apidocs.go:58-62`). Required change: `links` in the status payload of item 1 carries `api`, the path the reference answers at, `/api-docs`, which section 4 step 1 keeps where it is; the document stays public at that path plus `/swagger.json`, which is what a reference drawn inside the shared UI reads and what hyperweaver-server already fetches. The row opens in a new tab. Deciding source: `universal-navbar.md`, the status payload's `links` row and decision 6.
8. Two feature tokens this agent does not list. Why, in Mark's words, of what one agent can do and the other cannot: "then these should be features or something, right? The agent doesn't expose them, done, the end". The shared UI draws the Resume of a machine whose row reads `suspended` only while the host lists `machine-resume-suspended`, and the fast reboot among the host restart's options only while it lists `host-fast-reboot` (`universal-navbar.md`, the feature-token table and decision 7). This agent lists neither and that is right as the code stands: `POST /machines/{name}/resume` takes a paused machine alone (`internal/server/machines_lifecycle.go:354-365`), a suspended one brought back by `POST /machines/{name}/start`, and the host power routes are shutdown, restart, poweroff and halt, no fast reboot (`internal/server/hostpower.go:259-313`). Nothing is required now; the day either route exists here its token joins `platformFeatures` (`internal/server/status.go:97-104`) in the same change, and never before.
9. `nat_forwards` in the machine's detail. Why: the machine page of the shared UI draws the NAT port forwards of a machine in its hardware card, hyperweaver-ui's list carried over, and reads them where hyperweaver-ui read them, from the detail's `configuration.nat_forwards` (`../startcloud-ui/src/features/hosts/utils/machines.js`, `natForwardsOf`; hyperweaver-ui `src/components/Machine/MachineHardware.jsx`). This agent answers the forwards at `GET /machines/{name}/config` alone, at the top level of that answer (`internal/server/machines_config.go:36-40`), and the detail of `GET /machines/{name}` carries none (`internal/server/machines.go:258-267`), so the list never drew in hyperweaver-ui and does not draw in the shared UI. Required change, one of two, yours to choose: the detail's `configuration` carries `nat_forwards`, the rows `{ name, protocol, host_ip, host_port, guest_ip, guest_port, adapter }` as the config route answers them, so the page draws them from the one read it already makes; or say here that the config route is where they stay, and the shared UI reads that route on a host of this agent. Until one is chosen the shared UI asks for nothing more and draws no forwards. Deciding source: `universal-navbar.md`, Machine page, What waits on an agent.

Deletion of this section is the confirmation, the way every other item here works.

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

## 3. What this repository does today

Why: every location listed here is a place the move must touch; one missed
`/ui/` string leaves a redirect, a schema hint or an installer message
pointing at a path that no longer exists.

`internal/server/server_ui.go:31` mounts the SPA at `GET /ui/` with the
client-route fallback confined to that prefix; `:49` answers `GET /{$}`
with a 302 to `/ui/` when the UI is enabled, and
`server_routes.go:442` with a JSON info document when it is not; docs
mount at `/docs/` (`server_ui.go:79`). `server_routes.go:24-416` registers
`/api-keys/*`, `/auth/*`, `/protocol/open`, `/version`, `/app/*`,
`/system/*`, `/monitoring/*`, `/network/*`, `/database/*`, `/stats`,
`/ws-ticket`, `/tasks/*`, `/term/*`, `/ssh/*`, `/machines/*` (with the
VNC and RDP WebSocket upgrades at `:265` and `:286`), `/templates/*`,
`/media`, `/applications`, `/provisioning/*`, `/artifacts/*`,
`/filesystem/*`, `/secrets`, `/settings/*` and `/server/restart` at the
root; only `/api/status` (`:15`) and `/api/config/ticket` (`:18`) sit
under `/api`; `/api-docs` mounts at `internal/apidocs/apidocs.go:58-62`.
`internal/server/oidc_silent.go:159,189` redirect to
`/ui/login?sso=unavailable` and `/ui/#tray=`. `internal/config/config.go:338`
makes the tray Open target the base URL plus `/ui/`. The `/ui/` string
also sits in `internal/server/settings_schema_core.go:95`,
`internal/config/defaults.go:59`, `packaging/DEBIAN/postinst:54`,
`packaging/DEBIAN/man/hyperweaver-agent.8:69`,
`packaging/DEBIAN/man/hyperweaver-agent.yaml.5:99`,
`packaging/config/production-config.yaml:45`, `README.md:16` and
`CONTRIBUTING.md:37`. The UI build this agent bakes is
`G:\Projects\hyperweaver-ui\vite.config.js:53` with `base: '/ui/'`.

## 4. What joining the rule means here, in order

Why: the steps depend on each other in this order; serving the SPA at `/`
before the routes move makes the file server shadow the API, and consuming
a `base: '/'` build before either breaks every asset path.

1. Move every root API route under `/api` (the list above), keeping
   `/docs/` and `/api-docs` where they are; the machine noun is
   `/api/machines/*` only. Open: `server_routes.go:24-416`.
2. Serve the SPA at `/`: the file server at the root, the fallback to
   `index.html` after every API route, no `/ui/` prefix, no 302 from `/`.
   Open: `server_ui.go:31,49`.
3. Land the OIDC redirects on `/auth/callback` and `/login`, and make
   the tray Open target the origin. Open: `oidc_silent.go:159,189`;
   `config.go:338`.
4. Drop the `/ui/` strings from the schema description, defaults,
   packaging and docs. Open: the eight locations in section 3.
5. Consume a hyperweaver-ui build made with `base: '/'` (that repository's
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
| `notifications.md` section 3 (this file, earlier text) | route list | omitted `/protocol/open`, `/app/*`, `/monitoring/*`, `/database/*`, `/media`, `/applications`, `/server/restart` | corrected above |

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
| `main.go:96`; `internal/config/config.go:271-292` | the configuration file comes from the `--config` flag or the per-user default; no `CONFIG_DIR`; there is no production-versus-development switch of any kind | `CONFIG_DIR` is the one environment variable a backend may read and names the configuration directory; the flag may remain as its override; production versus development is chosen by which config directory exists, never by a second variable | `universal-config.md:57-60,66-70`; `priorities.yaml:193` |
| `internal/server/server_lifecycle.go:175`; `agent_setup.go:83`; `internal/server/settings.go:236` | the restart-spawned successor learns it is a successor from `HYPERWEAVER_RESTART=1` in its environment | replace the parent-to-child environment handshake with the existing local duplicate-launch handoff channel (`main.go:262-268`, `agent_startup.go:56-73`) or a child flag on `restartArgs` (`main.go:208`) | `universal-config.md:57-60,70`; `priorities.yaml:194` |
| `internal/config/paths.go:123`; `internal/loginitem/loginitem_linux.go:17`; `internal/server/hostsfile.go:28`; `internal/prereqs/prereqs.go:153-154`; `internal/sshrun/sync.go:60`; `internal/hostshell/hostshell_unix.go:27`; `internal/server/settings.go:224` | reads of `XDG_DATA_HOME`, `XDG_CONFIG_HOME`, `SystemRoot`, `VBOX_MSI_INSTALL_PATH`, `VBOX_INSTALL_PATH`, `PATH`, `SHELL`, `INVOCATION_ID` | tolerated as operating-system facts; none may become a configuration setting, and a value the file can carry must come from the file | `universal-config.md:70` |
| `internal/server/server_routes.go:411`; `internal/server/settings_schema.go:6-35`; `settings_schema_core.go:16-17,80-86,177-184` | `GET /settings/schema` serves a hand-written map with `min`, `max`, `items`, `keys`/`values` | one JSON Schema 2020-12 document per configuration file, shipped with the code, served at `GET /api/config/<name>/schema`, `minimum`/`maximum`/`enum`/`additionalProperties`, `section`/`subsection`/`order`, `requiresRestart`, `writeOnly` | `universal-config.md:157-188,197,295-296,314,325` |
| `server_routes.go:11-445` | no `GET /api/rules` | a UI backend that accepts writes answers `GET /api/rules` with its forms as JSON Schema 2020-12 and the estate's `$defs` | `universal-validation.md:72-162` |
| `server_routes.go:166-167,180,186`; `internal/server/status.go:97-104` | live data streams over WebSocket upgrades authenticated by `/ws-ticket`; no `events` token, no `events` object | one server-sent stream at `events.path` (`/api/events`), the `events` token and `{ path, topics }` in `/api/status`, the frame grammar, `Last-Event-ID` resume and the ring; the `tasks` topic, a task's row alone, registered in the contract before it streams; task output keeps its WebSocket (`internal/server/ws.go:172-274`) and the terminals theirs, moved under `/api` | `universal-events.md:40-88,120-167,242-248` |
| `internal/server/status.go:21-40,97-104,209-234` | `/api/status` answers `role`, `agent`, `hypervisors`, `platform`, `arch`, `version`, `hostname`, `auth`, `bootstrapAvailable`, `console`, `features`, `shi_mode`, `uptime`; feature tokens are `tasks`, `machines`, `machine-suspend`, … | add `brand`, `collections`, `links`, `ticket` (`null`, since `/api/config/ticket` exists), `config`, `events`; feature tokens drawn from the contract's table where the surface matches (`admin`, `setup`, `health`, `search`, `events`, `footer`) | `universal-navbar.md:578-688` |
| `internal/server/status.go:97-125` | no `footer` token; the payload names no footer at all | list `footer` on a payload that wants the chrome's footer, and `health` beside it only once `GET /api/health` answers the contract shape; without `footer` the chrome draws no footer and shows the version beside `brand.name` in the user menu instead | `universal-navbar.md:666,673,795-910`; checklist `:1189` |
| `internal/server/status.go:21-40` | no `analytics` member | optional: `{ script_url, attribute, value }` only when an estate-run collector is configured and its hostname is one this agent's configuration names; absent otherwise, and absent today is correct | `universal-navbar.md:623`; `universal-identity.md:261` |
| `internal/server/status.go:21-40`; `server_routes.go:11-445` | the payload carries no sidebar member, and none is wanted: sidebar entries come only from a feature's `sidebar(status, account)` export, and the `actionMenu` swap that moves the user menu to the sidebar's foot is a feature export too | nothing for this agent to add; hyperweaver is named the first fit for the `actionMenu` swap and is not being changed now, so when hyperweaver-ui converges on the shared build its feature owns that export, and no field for it ever lands in `/api/status` | `universal-navbar.md:358-475` (`:434-435`, `:463-468`); `UI-GROWTH-GUIDE.md:56` |
| `server_routes.go:11-445`; `server_ui.go:31,79` | no API route sits under the build folders `assets`, `brand`, `locales`, `fonts` or `themes`, and `/docs/` is served by the agent itself | when the SPA moves to `/` (section 4, step 2) the static file server answers those five folders and every other file before the `index.html` fallback, and no route is ever registered under them; `docs` is a reserved segment the router never claims, so `/docs/` may stay where it is; the root routes of section 3 that would shadow the fallback move under `/api` first | `universal-pages.md:136-153`; `universal-navbar.md:535-576` |
| `internal/server/settings.go:30-34`; `internal/config/config_sources.go:15` | `GET /settings` writes the whole configuration unmasked; `template_sources.sources[].auth_token` is a secret | mark secrets `writeOnly` in the schema; mask them as `********` on read; a write carrying the mask or blank keeps the stored value | `universal-config.md:52-53,169,236-245,326` |
| `internal/server/settings.go:61-79`; `internal/config/persist.go:83-84` | `PUT /settings` validates the merged document and answers 500 `{ error, details }` on a bad value | validate against the schema before writing and answer 422 `application/problem+json` with one `errors[]` entry per failing value (`pointer`, `rule`, `params`, `detail`); 200 carries `requires_restart` when a changed key says so | `universal-config.md:49-51,198,205-232,300,327`; `universal-validation.md:357-418` |
| `internal/config/config.go:300`; `persist.go:22` | `yaml.Strict()` refuses an unknown key at boot and on save | log an unknown key as a warning with its pointer and keep it; a migration alone removes it | `universal-config.md:254-255,266,328` |
| `internal/config/validate.go:22-202` | boot validation returns the first failing value | fill defaults, evaluate the whole document against the schema, stop on failure with every failing pointer logged through the `app` category | `universal-config.md:251-253,328` |
| `internal/config/defaults.go:14-471`; `packaging/config/production-config.yaml:1-427`; `packaging/DEBIAN/postinst:1-58` | no `schemaVersion` in the file or a schema; no migration list; `postinst` runs no migration | `schemaVersion` at the file root and in the schema; a migration list, one function per release, run by `postinst` from the file's version to the schema's; a missing file created from defaults in `postinst`, never at boot | `universal-config.md:54-56,256-257,261-274,329` |
| `internal/auth/middleware.go:101-116`; `internal/server/apikeys.go:73,153`; `settings.go:64` | refused writes answer `{"msg"}` or `{ error, details }`; a bad body answers 400 through the same shapes | every refused write answers `application/problem+json` with `type`, `title`, `status`, `errors[]`; 422 for a rule failure, 409 for `unique`, 400 only for an unreadable request | `universal-validation.md:60-63,357-418,463-464` |
| `internal/server/apikeys.go:40` | the bootstrap body reads `setupToken` | request-body members are `snake_case`: `setup_token` | `universal-validation.md:145-153` |
| `internal/server/oidc_jwt.go:32-98`; `internal/auth/middleware.go:94-96,139-145` | an IdP access token is accepted as `Bearer` after signature, `iss`, `aud` and `exp` checks; no `cnf.jkt`, no DPoP proof, the `Authorization` scheme is not read | a key-bound token (`cnf.jkt`) only with the `DPoP` scheme and a proof (`htm`, `htu`, `iat` within 60 s, `ath`, thumbprint equal to `cnf.jkt`, `jti` unseen for 300 s); a bound token presented as `Bearer` refused, an unbound token presented as `DPoP` refused; CORS admitting `Authorization` and `DPoP` | `universal-session.md:403-422`; `universal-events.md:285-293` |
| `server_routes.go:61`; `internal/server/monitoring_service.go:156-197` | health answers at `/monitoring/health` as `{ status, uptime, version, service, lastUpdate }` | `GET /api/health` answering `{ status, timestamp, services }` with `status` ok / warning / error and one coarse word per service; the `health` token in `/api/status`, drawn as the footer's heart only beside `footer` | `universal-navbar.md:666,673,795-899`; `priorities.yaml:199-203` |
| `internal/keys/keys.go:143`; `middleware.go:140`; `apidocs.go:214` | the API-key prefix is `hw_` | keep `hw_`; a `wh_` anywhere is a defect | this repository's own rule |
| `internal/protocol/protocol.go:34,36-38,64-80`; `internal/server/server_routes.go:32`; `internal/server/trayclaim.go:139-157`; `main.go:132-142,368-374` | the `hwa` scheme is registered and kept; its vocabulary is `open` alone: `ParseAction` refuses any other URL authority or path, the handoff forwards only `POST /protocol/open`, and no URL parameters are read | `hwa://` stays as the desktop hand-off scheme, the reverse-domain form a recorded deviation, so the import action extends it and never replaces it: parse and validate its parameters, forward them through the handoff and the in-process handler, import through the existing import-upload wire (`server_routes.go:341`) with the sha256 verified before the package lands. Two decisions are open in this repository and unset: (a) the action and parameter vocabulary — the straw-man is `hwa://provisioner/import?url=&sha256=&name=&version=`, nothing is fixed; (b) private-artifact handling when the tar.gz needs GitHub auth the agent lacks — refuse with the reason, prompt, or a token the configuration carries, nothing is fixed. The catalog's Open-in-Hyperweaver button is blocked until both are set here | `universal-identity.md:1178-1186,2076-2077`; `C:\Users\Mark\Desktop\hyperweaver-ai-sync.md:91-100`; `internal/server/provisioners.go` (the import-upload handler) |
| `internal/machines/create_exec_controllers.go:162,200,224`; `internal/machines/modify_exec_storage.go:66,143,198`; `internal/machines/knob_current_devices.go:71` | disk placement reads `disks.boot.device`, `additional_disks[].device`, `cdroms[].device`, `add_disks[].device`, `add_cdroms[].device` and `remove_*[].device` as the storageattach device slot (default 0), and the current-devices knob emits `device` on every attachment row | own the device slot as an agent-internal detail (the default 0 already covers every entry): stop reading the `device` key on the create, modify and remove paths, stop emitting it from the current-devices knob, and drop it from the swagger placement descriptions; the parallel-port `device` (`hardware.go:418`, `knob_current_ports.go:71`), the USB `device` (`machines_usb.go:55,60`) and the NIC `device` (`machines_metrics.go:52`) are different keys and stay | `C:\Users\Mark\Desktop\hyperweaver-ai-sync.md:102-115` |

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
