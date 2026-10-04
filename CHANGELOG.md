# Changelog

## [0.2.0](https://github.com/Makr91/hyperweaver-agent/compare/v0.1.4...v0.2.0) (2026-10-04)


### Features

* config contract wire — five schema-backed configuration files under /api/config with setup routes, problem bodies, JSON Schema validation, merge-patch saves, restart list and timestamped backups; sources, catalogs, artifact paths and applications keyed by id; CONFIG_DIR and --config name the folder; Debian package ships seeds and the setup token ([fc3e640](https://github.com/Makr91/hyperweaver-agent/commit/fc3e64029c83c49823b3bfec02b1508c7c5e10b4))
* DPoP resource-server side — the Authorization scheme read, key-bound tokens only under DPoP with an RFC 9449 proof, bound-as-Bearer and unbound-as-DPoP refused, WWW-Authenticate on every 401 and exposed to CORS, RS256 and PS256 tokens with nbf, iat and a 60 s leeway, unknown kid refetched once; the event stream answers the topics the key's role may read; device-status held open until the flow changes ([9a58a35](https://github.com/Makr91/hyperweaver-agent/commit/9a58a35074bac54264e8be98d5b0c3aaca6b2f52))
* restart through the protocol handoff channel — the successor asks the running agent to release its port and databases and is answered once they are closed; HYPERWEAVER_RESTART, the bind and database retry loops and the browser poll removed ([aa36d60](https://github.com/Makr91/hyperweaver-agent/commit/aa36d606f27fba65c8b8ce8c1d1ddc1c3a53f2cf))
* search over machines, tasks, configuration files, templates and artifacts at GET /api/search with the OpenSearch description, the search status member and the update and search tokens, no preference store on the agent with the browser keeping a person's theme, mode, language and timezone, and the tray icon following ui.shi_mode live ([cae2ed1](https://github.com/Makr91/hyperweaver-agent/commit/cae2ed16bd3621e46cbe0f89c934e15e0d02206a))
* storage paths for machines, provisioners and templates, any number per kind with one default, a machine keeps the folder it was created in, storage_path_id on create and clone, /api/storage/paths routes, CONFIG_DIR honoured, Windows defaults for machines and provisioners under Roaming ([355cda0](https://github.com/Makr91/hyperweaver-agent/commit/355cda0039fe8a1b6bb10c788a6589539e05d61f))
* stream topics admin and monitoring — restart-required on every configuration save, restore and restart, admin-only with 403; cpu-sample, memory-sample and network-sample pushed when the collector takes them ([923c40b](https://github.com/Makr91/hyperweaver-agent/commit/923c40bb84c9fd61f0500ccea5b7a930590741cc))
* the family's release pipeline: the startcloud-ui pin in packaging/config/ui-version.yaml, the dependency-bump workflow, the bot token on release-please, prod-build and dev-build ([d9568d6](https://github.com/Makr91/hyperweaver-agent/commit/d9568d6de5e9959b5d7f8ad7f0a8005105ed79b4))
* utm support ([f564106](https://github.com/Makr91/hyperweaver-agent/commit/f564106e96277ffce9f5a1a7face4dd4c6593139))


### Bug Fixes

* a snapshot taken or deleted is written to the person's inbox like the other notable task ends ([578ab78](https://github.com/Makr91/hyperweaver-agent/commit/578ab78ab5a563ed229c717b6bfc99978c0a9eee))
* adding metrics ([4f01a3b](https://github.com/Makr91/hyperweaver-agent/commit/4f01a3b8d728379f9f66fbf5e85d68db9198d45c))
* dependency bumps, setup-go v7, zip-slip IsLocal barrier, provably-literal ORDER BY whitelist ([775fc84](https://github.com/Makr91/hyperweaver-agent/commit/775fc84683e0acc651efe80d6c71a868a4f3a83a))
* device sign-in slows its polling after a failed request and oidc.issuer must be https, finished items removed from the brief ([def1ed3](https://github.com/Makr91/hyperweaver-agent/commit/def1ed3c7eefb0e513bcb97782324c5eec2e4f39))
* every linter finding corrected in code, file reads through safepath, the refresh token in its own file, the deprecated curve check replaced, and golang.org/x/crypto raised past the ssh advisory ([64042d8](https://github.com/Makr91/hyperweaver-agent/commit/64042d85a3ffb5d72b0426d0fe50ca0e0cba9374))
* every plain comment naming an API route says its /api path, the secrets store's doc lines name the config routes in place of the retired settings surface ([33f8f30](https://github.com/Makr91/hyperweaver-agent/commit/33f8f30ac71fa66d5700cf295dda4db6417e9136))
* favorites and the notification inbox relay to the identity provider under the bound account's token with unread-count on the stream, the refresh token persists across restarts, a finished task with the notify flag is written to the person's inbox, key info and the profile carry issuer and subject, the brief loses its record-only sections ([8c1c51d](https://github.com/Makr91/hyperweaver-agent/commit/8c1c51dfe152cdeb05143dd427600518692d743d))
* final 500-line splits — settings schema literal extracted to section vars, server route table extracted to registerRoutes ([b82283d](https://github.com/Makr91/hyperweaver-agent/commit/b82283d678322c9ef6dff65cfb4fc932503568f3))
* GET /api/user in the identity provider's profile shape, GET and PATCH /api/user/preferences stored per person beside the config, profile-updated on the profile topic to that person alone, integrations in the scopes default ([ca12cfd](https://github.com/Makr91/hyperweaver-agent/commit/ca12cfd7d1b4e66ab68f7caab9065c8cc22fdd10))
* Hosts.yml Editor ([9b7fcc5](https://github.com/Makr91/hyperweaver-agent/commit/9b7fcc5c8794d162c53bbdde8fbc3b542116e4b7))
* hwa open carries the deploy query (create=machine with box or provisioner members) through to the signed-in UI, any other key refused ([ebc81d9](https://github.com/Makr91/hyperweaver-agent/commit/ebc81d9a322b8542d7924d2622a026454bd2a0a8))
* hyperweaver-agent and com.startcloud.hyperweaver-agent URL schemes beside hwa, on Windows, Linux and macOS ([e4fe3a2](https://github.com/Makr91/hyperweaver-agent/commit/e4fe3a2eb24bcb8f189e69ee045a4a04f2a172cc))
* machine-scoped WebSocket tickets — frozen cross-agent shape enforced on all five upgrade endpoints ([be2a4f7](https://github.com/Makr91/hyperweaver-agent/commit/be2a4f748aae4086525e36b96ecfe37929fe1fad))
* NAT forwards in the machine detail, setup_token in the bootstrap body, full paths in three API descriptions ([3530cb7](https://github.com/Makr91/hyperweaver-agent/commit/3530cb7110407daddec12e01ca474dcb4ea7c5e6))
* network-spaces surface, per-adapter VM traffic, NIC re-attachment, host address mutations, io_delay_pct, tray-key pruning, darwin-only utm prereq ([4a372d7](https://github.com/Makr91/hyperweaver-agent/commit/4a372d7cf3217198f54c70c4d8e686553702ee3f))
* OIDC client, validator and token source move to internal/oidc with the four handlers left in the server, Debian control depends on adduser and ca-certificates, the Windows installer drops its startup shortcut, README, CONTRIBUTING, Debian README and man5 describe the five configuration files, VBoxManage and Go 1.25.0, the brief loses its done rows ([a4ce4e6](https://github.com/Makr91/hyperweaver-agent/commit/a4ce4e6ce59bff186af03bbd6218c6da67466e43))
* OIDC device-flow login — RFC 8628 device grant, JWKS validation, TOFU account binding, admin-key mint, in-memory token refresh ([acf7b4c](https://github.com/Makr91/hyperweaver-agent/commit/acf7b4ca8d7725013a56b042a6399bdccc7dd373))
* OIDC manager split into binding, provider, validator, token source and client, 42 Swagger annotations name the structs the handlers write, man pages and CONTRIBUTING describe the five configuration files and VBoxManage, the brief loses its done rows ([c52f096](https://github.com/Makr91/hyperweaver-agent/commit/c52f096dcfb1117b294f6d127a670bd6545df5af))
* OIDC resource server — bearer access-token auth on the Agent API, JWKS cache with rotation retry, TOFU subject gate ([67b2d83](https://github.com/Makr91/hyperweaver-agent/commit/67b2d838da7e696f054659a6303959b93e5b431e))
* oidc scopes default drops organizations, the update check answers 200 with the reason, last_modified_by is the OIDC key's email, config wire fixtures and the agent's section 9 record in the brief ([2e1f39a](https://github.com/Makr91/hyperweaver-agent/commit/2e1f39ac2544f7ea5da2e0e74e85108534fe1fc6))
* OIDC UUID-first account binding with sub fallback, allowed_users matches UUIDs, device-start errors name the endpoint ([a66de3b](https://github.com/Makr91/hyperweaver-agent/commit/a66de3ba5fb0c3789f2508647e7a39c12ec272dd))
* RDP, API Shaping, General Improvments ([d6c1101](https://github.com/Makr91/hyperweaver-agent/commit/d6c1101156d305728a67dd1e91069bf7dbcd9146))
* RDP, API Shaping, General Improvments ([6a0f180](https://github.com/Makr91/hyperweaver-agent/commit/6a0f180a710050b8b8062c352654ef245f68659a))
* RDP, API Shaping, General Improvments ([fbb4213](https://github.com/Makr91/hyperweaver-agent/commit/fbb4213e4c50e85d24e7de7f465211159eb025cd))
* round-4 swaggo migration — machines, artifacts, provisioners, monitoring, terminals migrate to inline annotations; fragment keys deleted ([6137b15](https://github.com/Makr91/hyperweaver-agent/commit/6137b15c1eec49df40121db3dc19914920b3a13e))
* sidebar token and links.community in the status payload so the shared UI draws its shell in agent mode ([5150f80](https://github.com/Makr91/hyperweaver-agent/commit/5150f80cd70907518d1690f7ee97f6609d8800b2))
* silent SSO pre-check — loopback auth-code PKCE with prompt=none, tray-grant handoff carrying the OIDC key, refresh family split ([b231bac](https://github.com/Makr91/hyperweaver-agent/commit/b231bacdb1a8146f038b9e6e0fb43cf551cf8dc3))
* silent SSO pre-check with PKCE loopback callback, tray-grant handoff, SSO key identity on key-info via the customer_id claim ([461d10b](https://github.com/Makr91/hyperweaver-agent/commit/461d10b2af2d05cb6014b505644196d29f765ef3))
* some stuff ([e528b70](https://github.com/Makr91/hyperweaver-agent/commit/e528b70e5147012e9743e5fd1f559872f9f50479))
* split 14 oversized Go files into ≤500-line siblings (config, assets, monitoring, provisioners, provision/modify/hostdoc/knob/executors execs, fielddsl, netconfig, filesystem_mutate, server, main) — pure mechanical moves ([3566708](https://github.com/Makr91/hyperweaver-agent/commit/3566708c246d9970f22463a225d44d12b47bbcd4))
* split final 14 oversized Go files into ≤500-line siblings (assets ops, snapshot/reconcile/templates/store execs, tasks store, guest_agent, rdp_bridge, provisioner import, network_spaces, dnsfile, processes, machines_modify, filesystem_archive) — pure mechanical moves ([7d4f5c7](https://github.com/Makr91/hyperweaver-agent/commit/7d4f5c77c5771b5874f7fd9265f9e6436aa2d446))
* structured-JSON convergence — task metadata real JSON with output nulled to its channels, byte/second/ms/day numerics on converged field names, open_files_sample array, nat_forwards derived view, os_languages array ([179c4ac](https://github.com/Makr91/hyperweaver-agent/commit/179c4acdf9fccdc61aa0acd54e8bb8cf72a22cf6))
* supporting more vbox networking features ([3f256fe](https://github.com/Makr91/hyperweaver-agent/commit/3f256fe5529f3b677f32df3385d07fd1de2fae41))
* swagger doc fully code-generated (hand spec removed) + structured-JSON conversions — loopback mappings and video mode structured, schema contracts on structs ([6acbee3](https://github.com/Makr91/hyperweaver-agent/commit/6acbee3d35fd31a790ecaa38e28c8bfd765ad043))
* swaggo round 2 — 33 paths moved inline (api-keys, tray/protocol, swap, orchestration, host-power, database + explorer, secrets, hosts, dns, media, notes/tags), responses typed on the real wire ([32db3ca](https://github.com/Makr91/hyperweaver-agent/commit/32db3ca84e5663cb974995dbc394499094448eec))
* swaggo round 3 — 76 paths moved inline (tasks, processes, machine ops/bulk/usb/nvram/ids/defaults/hosts-yml, guest agent, launchers, rdp, vnc state, remote templates, settings, hostname/addresses/nat, filesystem+archives, machine metrics, status), taskError failures typed, queuedOperation wired ([8a43acd](https://github.com/Makr91/hyperweaver-agent/commit/8a43acdf99f1426128de1e10ac85153b6dd998c7))
* swaggo round 5 — WS upgrades, network spaces list, filesystem move/copy migrate inline; fragment paths emptied ([6e38cdf](https://github.com/Makr91/hyperweaver-agent/commit/6e38cdfaea4b9101ccd1b68137b6522c03116497))
* the device grant sends the scopes without openid, which Spring refuses on device authorization, the silent probe keeps the full list ([27fa8e0](https://github.com/Makr91/hyperweaver-agent/commit/27fa8e0c4f2e09077c137967dbc4225bd50c6ec7))
* the oidc scopes default requests notifications:read and notifications:write, the estate's one shape for the inbox scopes ([671d398](https://github.com/Makr91/hyperweaver-agent/commit/671d39879de42926dcf07669fbc280e1e1d1bf9d))
* the release pipeline bakes the startcloud-ui artifact pinned by .ui-version in place of hyperweaver-ui, and the docs say so ([564b209](https://github.com/Makr91/hyperweaver-agent/commit/564b2098528c14b95b16ccfc052537ab14808e52))
* WSL control-node reachability, swaggo merge scaffold + pilot endpoints, macOS hostonlynet platform split, answer-migrations Go half, bridged-ifs picker fields ([9a7cedb](https://github.com/Makr91/hyperweaver-agent/commit/9a7cedb38c6d8a05a1d67a0dfeb78f3b69468202))

## [0.1.4](https://github.com/Makr91/hyperweaver-agent/compare/v0.1.3...v0.1.4) (2026-07-17)


### Bug Fixes

* add SHI mode ([f5a9645](https://github.com/Makr91/hyperweaver-agent/commit/f5a9645ea95e96907a0a17e6befbb146ce45b3ec))
* **deps:** bump the minor-and-patch group with 4 updates ([c5679e9](https://github.com/Makr91/hyperweaver-agent/commit/c5679e90b8973a7fe46975fbd3a8ce85de09fd2d))
* **deps:** bump the minor-and-patch group with 4 updates ([ec3a8ef](https://github.com/Makr91/hyperweaver-agent/commit/ec3a8eff74a89735f1f0693338e34b450241422e))
* implemening more ([2684919](https://github.com/Makr91/hyperweaver-agent/commit/268491955f87177436d0a924556c67b5a7d002cd))
* parity with zoneweaver and implementing as many features as possible ([bd93683](https://github.com/Makr91/hyperweaver-agent/commit/bd93683fc0ddde26d016a61facf546773a4c5e37))
* provisioning pipeline end-to-end - stamp-at-completion (final playbook only), provisioning NIC architecture (NAT adapter 1 + ssh port-forward transport), live MAC resolution into extra_vars, DHCP server restart + delete-time lease cleanup, Forwarding(N) parser fix, remote_collections honored ([4c529bf](https://github.com/Makr91/hyperweaver-agent/commit/4c529bf6ef07011a6ef13c7e9cd00d1f364e78f9))
* provisioning pipeline end-to-end proven - stamp-at-completion, provisioning NIC architecture (NAT adapter 1 + ssh port-forward transport), live MAC resolution into extra_vars, DHCP server restart + lease cleanup, Forwarding(N) parser fix, ANSIBLE_CONFIG default, browser.open_on_start, provisioning.network man page, first-run config fix ([98c25b8](https://github.com/Makr91/hyperweaver-agent/commit/98c25b84145abd103cdb36ab9e10ebc69425c372))
* RDP, API Shaping, General Improvments ([06e170e](https://github.com/Makr91/hyperweaver-agent/commit/06e170ef3027b21ddb01875d7bb31cee7bfeec42))
* RDP, API Shaping, General Improvments ([b4b68d5](https://github.com/Makr91/hyperweaver-agent/commit/b4b68d5d42551f4738845e69a82ed0bf041b8760))
* RDP, API Shaping, General Improvments ([3e2bdfb](https://github.com/Makr91/hyperweaver-agent/commit/3e2bdfb74535558e1bffc8a655ea2ba95a5789b1))
* RDP, API Shaping, General Improvments ([3fc0e48](https://github.com/Makr91/hyperweaver-agent/commit/3fc0e487062e3f70cdb756d7853e37b1d05e3a84))
* RDP, API Shaping, General Improvments ([e4a7dab](https://github.com/Makr91/hyperweaver-agent/commit/e4a7dab350a54b2bc28e19970eb487b18baee980))
* RDP, API Shaping, General Improvments ([90229c3](https://github.com/Makr91/hyperweaver-agent/commit/90229c3511521917b76a06faee2c24643dbff86e))
* RDP, API Shaping, General Improvments ([104c9d6](https://github.com/Makr91/hyperweaver-agent/commit/104c9d6013fc9dabb46603212193e96891a3c087))
* seed startcloud_generic_provisioner per Mark's ruling; audit fixes - one running task per machine (stop can no longer race a running vagrant up), PUT machines server_id kept in sync between spec and row; UI 0.10.12 ([3bb324c](https://github.com/Makr91/hyperweaver-agent/commit/3bb324c20165193460787b73804b38d0e9e2a0b4))
* updating version ([c4d26c4](https://github.com/Makr91/hyperweaver-agent/commit/c4d26c4cf5a4ea857f957b327b11f360052e9bef))

## [0.1.3](https://github.com/Makr91/hyperweaver-agent/compare/v0.1.2...v0.1.3) (2026-07-06)


### Bug Fixes

* embed SHI's initial-registry verbatim (~135 known HCL hashes; seeder parses SHI's format natively so updates are a cp), assets log category in vocabularies ([41d63c7](https://github.com/Makr91/hyperweaver-agent/commit/41d63c70ff8f011d91c47399c2369fcf7fbe7b35))
* HCL portal downloader (token exchange with rotated refresh persisted to secrets, exact-name catalog lookup with authoritative sha256, verified streamed download), updater apply flow + SHI settings parity (from prior stretch), Artifacts/updater/bridged-interfaces OpenAPI coverage ([9e83a5b](https://github.com/Makr91/hyperweaver-agent/commit/9e83a5b1049294841ecf8cd82ece78eaf494963f))
* installer file cache with full SHA-256 verification (artifacts table/endpoints/token, scan/download-with-progress/upload/register, expectation seeding, hard-link or verified-copy mounting, prepare-time refusal of unverified files), optional machine names with prefix_machine_names derivation (server_id--hostname.domain), safepath streaming writer ([ebd2e0b](https://github.com/Makr91/hyperweaver-agent/commit/ebd2e0b16c8d6f35018b2977c73fcaf871048e49))
* machine clone (zoneweaver contract, SHI metadata-copy model), decomposed start pipeline (parent + prepare/plugin/vagrant-up children with per-step progress, cascade cancel), per-machine rsync/scp sync method with SHI platform rules, rsync prereq detection, UI pin 0.10.10 (arch item 2 loose ends) ([4bc4e13](https://github.com/Makr91/hyperweaver-agent/commit/4bc4e13ef0cffbc9029ca957c861f14c3cdc3f09))
* provisioner package registry - SHI-format scan/import/delete, non-clobber seeding from packaged archives, /provisioning/provisioners API + provisioning token (arch item 2, piece 1) ([9366c40](https://github.com/Makr91/hyperweaver-agent/commit/9366c4005b2e8c71d72deda288c5e48a36a56695))
* provisioning engine core - pongo2 Hosts.yml generator + secrets store (/secrets, SECRETS_* vars), working-dir materialization (SHI layout, id-files/ssls/installers, secrets.yml never clobbered), machine-create/modify/provision/sync through the task queue, dual-path start via vagrant up, UUID-keyed reconciliation (arch item 2, pieces 2-4) ([204c5a3](https://github.com/Makr91/hyperweaver-agent/commit/204c5a35db9f15f3cbac82bbc9cbf4d6eb331e8b))
* Release 0.10.11 UI ([b454e07](https://github.com/Makr91/hyperweaver-agent/commit/b454e07f8d666a54c36d4d2ee7a9b7e00d360066))
* settings API with backups and self-restart, remove all lint suppressions, add safepath validation for all file and exec paths ([2c46596](https://github.com/Makr91/hyperweaver-agent/commit/2c465969f6fb0233cc0f6a8f997c573388b7063b))
* settings API with backups and self-restart, remove all lint suppressions, add safepath validation for all file and exec paths ([d86b9dd](https://github.com/Makr91/hyperweaver-agent/commit/d86b9dd80ed670d8a72324abb9468d6244b347b8))
* settings API with backups and self-restart, remove all lint suppressions, add safepath validation for all file and exec paths ([16d3b2d](https://github.com/Makr91/hyperweaver-agent/commit/16d3b2dbda9d97ca4db8b99225ec353704446011))
* ship the STARTcloud CA pair in packaging/ssl — gitignore exceptions so release builds can stage it into all three installers ([30783e7](https://github.com/Makr91/hyperweaver-agent/commit/30783e735a29494d66dccecefb708fa70e34b7ca))
* split oversized files per arch §14 — config.go (defaults/validate/paths), machines.go (bulk/meta), settings.go (schema), queue.go (parent) — pure moves, zero behavior change ([f3ebc92](https://github.com/Makr91/hyperweaver-agent/commit/f3ebc927dcf2e8bae6aa58d3ca5bea89b602e0e9))

## [0.1.2](https://github.com/Makr91/hyperweaver-agent/compare/v0.1.1...v0.1.2) (2026-07-06)


### Bug Fixes

* GET /stats via go-sysinfo with VirtualBox machine lists, hide console windows on child processes, api-docs server selector and authorize parity ([00af7f0](https://github.com/Makr91/hyperweaver-agent/commit/00af7f03ff95a3fb8d4729824bcfbd8dbed7879b))
* machines + task queue (Agent API v1) — VBoxManage lifecycle, queued discovery, de-zoned wire, machine-suspend token, Node config parity ([5039056](https://github.com/Makr91/hyperweaver-agent/commit/503905620092404cd304b29d0f319e47bd326d78))
* machines + task queue (Agent API v1) — VBoxManage lifecycle, queued discovery, de-zoned wire, machine-suspend token, Node config parity ([9d13618](https://github.com/Makr91/hyperweaver-agent/commit/9d1361809035d6e419382b184d058fd1f64f45e3))
* restore file modes clobbered by the drvfs mount ([1c444b2](https://github.com/Makr91/hyperweaver-agent/commit/1c444b2b5441f1d0364f6486f85647399efde824))
* settings API with backups and self-restart, remove all lint suppressions, add safepath validation for all file and exec paths ([17a3271](https://github.com/Makr91/hyperweaver-agent/commit/17a327185a57935e9c646461461d82edef9749dc))
* TLS-everywhere with STARTcloud CA chain, install-time trust, force_secure, Node config parity, one-write-path safepath.WriteFile, restart-race fix, /stats cpus, read-only swap surface + swap token ([ef34649](https://github.com/Makr91/hyperweaver-agent/commit/ef34649fbae216834c9aa904c7f9b6155f459b70))
* TLS-everywhere with STARTcloud CA chain, install-time trust, force_secure, Node config parity, one-write-path safepath.WriteFile, restart-race fix, /stats cpus, read-only swap surface + swap token, Releasing 0.10.9 UI ([0bfe757](https://github.com/Makr91/hyperweaver-agent/commit/0bfe75740bbbbd5b223dad13c52fbdc5880d49bc))

## [0.1.1](https://github.com/Makr91/hyperweaver-agent/compare/v0.1.0...v0.1.1) (2026-07-05)


### Bug Fixes

* initial import of repo scaffolding from zoneweaver-agent ([e4be2d7](https://github.com/Makr91/hyperweaver-agent/commit/e4be2d7439d6ba1407174a7795e1d01ecc305e10))
* initial release of hyperweaver-agent ([6ac2b29](https://github.com/Makr91/hyperweaver-agent/commit/6ac2b2953e5defa2d7a037dc80aeaf5d493ef69a))

## Changelog

Release notes are generated by release-please from conventional commits.
