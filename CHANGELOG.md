# Changelog

## [0.2.0](https://github.com/Makr91/hyperweaver-agent/compare/v0.1.4...v0.2.0) (2026-07-21)


### Features

* utm support ([f564106](https://github.com/Makr91/hyperweaver-agent/commit/f564106e96277ffce9f5a1a7face4dd4c6593139))


### Bug Fixes

* adding metrics ([4f01a3b](https://github.com/Makr91/hyperweaver-agent/commit/4f01a3b8d728379f9f66fbf5e85d68db9198d45c))
* dependency bumps, setup-go v7, zip-slip IsLocal barrier, provably-literal ORDER BY whitelist ([775fc84](https://github.com/Makr91/hyperweaver-agent/commit/775fc84683e0acc651efe80d6c71a868a4f3a83a))
* final 500-line splits — settings schema literal extracted to section vars, server route table extracted to registerRoutes ([b82283d](https://github.com/Makr91/hyperweaver-agent/commit/b82283d678322c9ef6dff65cfb4fc932503568f3))
* Hosts.yml Editor ([9b7fcc5](https://github.com/Makr91/hyperweaver-agent/commit/9b7fcc5c8794d162c53bbdde8fbc3b542116e4b7))
* machine-scoped WebSocket tickets — frozen cross-agent shape enforced on all five upgrade endpoints ([be2a4f7](https://github.com/Makr91/hyperweaver-agent/commit/be2a4f748aae4086525e36b96ecfe37929fe1fad))
* network-spaces surface, per-adapter VM traffic, NIC re-attachment, host address mutations, io_delay_pct, tray-key pruning, darwin-only utm prereq ([4a372d7](https://github.com/Makr91/hyperweaver-agent/commit/4a372d7cf3217198f54c70c4d8e686553702ee3f))
* OIDC device-flow login — RFC 8628 device grant, JWKS validation, TOFU account binding, admin-key mint, in-memory token refresh ([acf7b4c](https://github.com/Makr91/hyperweaver-agent/commit/acf7b4ca8d7725013a56b042a6399bdccc7dd373))
* OIDC resource server — bearer access-token auth on the Agent API, JWKS cache with rotation retry, TOFU subject gate ([67b2d83](https://github.com/Makr91/hyperweaver-agent/commit/67b2d838da7e696f054659a6303959b93e5b431e))
* OIDC UUID-first account binding with sub fallback, allowed_users matches UUIDs, device-start errors name the endpoint ([a66de3b](https://github.com/Makr91/hyperweaver-agent/commit/a66de3ba5fb0c3789f2508647e7a39c12ec272dd))
* RDP, API Shaping, General Improvments ([d6c1101](https://github.com/Makr91/hyperweaver-agent/commit/d6c1101156d305728a67dd1e91069bf7dbcd9146))
* RDP, API Shaping, General Improvments ([6a0f180](https://github.com/Makr91/hyperweaver-agent/commit/6a0f180a710050b8b8062c352654ef245f68659a))
* RDP, API Shaping, General Improvments ([fbb4213](https://github.com/Makr91/hyperweaver-agent/commit/fbb4213e4c50e85d24e7de7f465211159eb025cd))
* round-4 swaggo migration — machines, artifacts, provisioners, monitoring, terminals migrate to inline annotations; fragment keys deleted ([6137b15](https://github.com/Makr91/hyperweaver-agent/commit/6137b15c1eec49df40121db3dc19914920b3a13e))
* silent SSO pre-check — loopback auth-code PKCE with prompt=none, tray-grant handoff carrying the OIDC key, refresh family split ([b231bac](https://github.com/Makr91/hyperweaver-agent/commit/b231bacdb1a8146f038b9e6e0fb43cf551cf8dc3))
* silent SSO pre-check with PKCE loopback callback, tray-grant handoff, SSO key identity on key-info via the customer_id claim ([461d10b](https://github.com/Makr91/hyperweaver-agent/commit/461d10b2af2d05cb6014b505644196d29f765ef3))
* split 14 oversized Go files into ≤500-line siblings (config, assets, monitoring, provisioners, provision/modify/hostdoc/knob/executors execs, fielddsl, netconfig, filesystem_mutate, server, main) — pure mechanical moves ([3566708](https://github.com/Makr91/hyperweaver-agent/commit/3566708c246d9970f22463a225d44d12b47bbcd4))
* split final 14 oversized Go files into ≤500-line siblings (assets ops, snapshot/reconcile/templates/store execs, tasks store, guest_agent, rdp_bridge, provisioner import, network_spaces, dnsfile, processes, machines_modify, filesystem_archive) — pure mechanical moves ([7d4f5c7](https://github.com/Makr91/hyperweaver-agent/commit/7d4f5c77c5771b5874f7fd9265f9e6436aa2d446))
* structured-JSON convergence — task metadata real JSON with output nulled to its channels, byte/second/ms/day numerics on converged field names, open_files_sample array, nat_forwards derived view, os_languages array ([179c4ac](https://github.com/Makr91/hyperweaver-agent/commit/179c4acdf9fccdc61aa0acd54e8bb8cf72a22cf6))
* supporting more vbox networking features ([3f256fe](https://github.com/Makr91/hyperweaver-agent/commit/3f256fe5529f3b677f32df3385d07fd1de2fae41))
* swagger doc fully code-generated (hand spec removed) + structured-JSON conversions — loopback mappings and video mode structured, schema contracts on structs ([6acbee3](https://github.com/Makr91/hyperweaver-agent/commit/6acbee3d35fd31a790ecaa38e28c8bfd765ad043))
* swaggo round 2 — 33 paths moved inline (api-keys, tray/protocol, swap, orchestration, host-power, database + explorer, secrets, hosts, dns, media, notes/tags), responses typed on the real wire ([32db3ca](https://github.com/Makr91/hyperweaver-agent/commit/32db3ca84e5663cb974995dbc394499094448eec))
* swaggo round 3 — 76 paths moved inline (tasks, processes, machine ops/bulk/usb/nvram/ids/defaults/hosts-yml, guest agent, launchers, rdp, vnc state, remote templates, settings, hostname/addresses/nat, filesystem+archives, machine metrics, status), taskError failures typed, queuedOperation wired ([8a43acd](https://github.com/Makr91/hyperweaver-agent/commit/8a43acdf99f1426128de1e10ac85153b6dd998c7))
* swaggo round 5 — WS upgrades, network spaces list, filesystem move/copy migrate inline; fragment paths emptied ([6e38cdf](https://github.com/Makr91/hyperweaver-agent/commit/6e38cdfaea4b9101ccd1b68137b6522c03116497))
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
