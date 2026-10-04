# Notifications from startcloud-ui

## Search

The shared UI reads this agent's search as it stands, and every rule of the navbar contract's search section is met: `search` listed in `features`, `search { path, kinds }` in the status payload naming machine, config, template and, while `artifact_storage.enabled`, artifact; `GET /api/search` with the request rules, the answer shape, the score scale, the sort, the per-kind cursor while one kind is named, `Cache-Control: no-store`, the 422 naming `/q`; `GET /opensearch.xml` at the request's origin with `ShortName`, `Image` and the `text/html` `Url` template.

The UI routes each of these kinds to a page of the host the row was asked of: a machine to its page, a config file to the agent's configuration page for that file, a template and an artifact to their list pages with the id as the hash. The locator members the agent fills are the ones those routes read. A task is no search kind: tasks are found in the footer's tasks pane, and the UI owns no route for a task row.

Standing rule for every kind answered now and every kind added later: a row's `facets` carry the same keys as the filter groups of the UI page that lists that kind, so the results page draws the same pills the page does. The machine `status` facet matches its page. The artifact `file_type` facet and the template kind's facets are settled when the UI's artifact, installer, template and provisioner pages are refined; that refinement will bring its asks here.

## Open asks

### Update available in the inbox

When `GET /api/app/updates/check` finds a newer release, write one row to the bound person's inbox, idempotent on the latest version (`idempotency_key` `hyperweaver-agent:update:<latest_version>`), `type SYSTEM`, `severity INFO`, the title naming the version, the body the host's name, `navigate` the host's Update page, and send `update-available` on the `admin` topic with `{ current_version, latest_version, release_date }`, the `restart-required` pattern, so an operator learns of a release on the page they open first and every open admin tab hears it, never from a timer.

### Release notes on the check

Answer `release_notes`, the release's own text, beside `release_url`, `release_date` and `changelog`, taken from the release at build time into `update-info.json`, so the Update page can draw what changed without a fetch off its origin.

### Task kind out of search

Drop `task` from `search.kinds` in the status payload and from the kinds `GET /api/search` answers and accepts in `kinds`, so a search never returns a task row; the UI's kind table no longer owns one and draws no route for it.

### Processes listing

`GET /api/system/processes` answers at most `limit` rows, 100 by default and 1000 at the ceiling, and a `limit` above the ceiling is ignored, so the UI's earlier `limit=5000` drew 100 rows; the UI now sends `limit=1000`. The Processes page lists every process of the host, so the route needs one of: no ceiling, or cursor paging in the shape of `GET /api/search` (`cursor` in, `next_cursor` out) so the UI pages through the rest. Say which, and the UI follows.
