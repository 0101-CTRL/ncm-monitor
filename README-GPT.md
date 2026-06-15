# ChatGPT-Friendly Technical Notes — NCM Monitor v5.0.3

This file is intended to help ChatGPT or a future maintainer quickly understand the application, its architecture, and the major troubleshooting context.

## Application summary

NCM Monitor is a local Python/FastAPI application that collects, caches, and visualizes NetCloud Manager router data. It is used for router fleet monitoring, support investigations, customer-facing analysis, and professional-services style engagements.

The app runs as a local web service using Uvicorn/FastAPI and SQLite.

Default service:

```text
ncm-monitor
```

Default app path:

```text
/opt/ncm-monitor
```

Default app file:

```text
/opt/ncm-monitor/app.py
```

Default main DB:

```text
/opt/ncm-monitor/data/ncm_monitor.db
```

Default global/setup DB:

```text
/opt/ncm-monitor/data/global/global.db
```

## Important NCM API rules

These rules matter when troubleshooting polling logic:

```text
/api/v2/net_devices/ accepts router=<router_id>
net_device_* endpoints require net_device=<net_device_id>
router_stream_usage_samples accepts router=<router_id>
router_state_samples accepts router=<router_id>
router_logs requires group logging enabled
```

## UI areas

Important routes/pages:

```text
/setup
/login
/launcher
/ui?profile_id=<id>
/monitoring-targets-ui?profile_id=<id>
/pool-admin?profile_id=<id>
/router-view/<router_id>?profile_id=<id>
/router/<router_id>/detail?profile_id=<id>
```

## v5 architecture concepts

### Profiles / dashboards

Most router data is profile-aware. `profile_id` is important and should be preserved across UI navigation and API calls.

### Monitoring targets

v5 introduced direct monitoring targets separate from pools. A router can be added as an individual target or managed through a pool.

### Modules

Modules define what the app collects or exposes. Examples include:

```text
metadata
net_devices
router_state
signal_health
router_stream_usage
alerts
location
router_logs
sim_usage
```

### Local cache

The app stores samples locally in SQLite and should prefer local cache for UI restore behavior.

Manual user actions can poll/backfill NCM.

Silent page restore should avoid consuming NCM API calls.

## Chart behavior

Router detail charts include:

```text
Signal Health
Data Usage
Alert Timeline
```

Chart ranges support:

```text
7 days
14 days
30 days
60 days
90 days
custom
```

The selected chart range is persisted in browser localStorage using a key like:

```text
ncm-monitor:router-chart-ranges:<router_id>:profile:<profile_id>
```

Example value:

```json
{"signal":{"mode":"90","startDate":null,"endDate":null}}
```

Manual Apply may request expanded data from NCM if needed.

Auto-restore must use:

```text
cache_only=1
```

Example:

```text
/router/<router_id>/detail?days=90&profile_id=1&cache_only=1
```

This prevents silent API consumption during page reload/navigation restore.

## Event Context side panel

Daily chart dots can open an Event Context panel. The panel correlates chart points with router logs.

It supports:

```text
daily bucket context
bounded log windows
same-day tail pull
nearest-log highlighting
CSV export
cached-log fallback
```

Daily chart restore and Event Context logic are sensitive to local/UTC date handling.

## Router detail endpoint

Primary endpoint:

```text
GET /router/{router_id}/detail
```

Important parameters:

```text
profile_id
days
start_date
end_date
cache_only
```

cache_only=1 means read local SQLite only and skip backfill/polling.

## Backfill behavior

Before v5.0.3, requesting more than 30 days on router detail triggered signal and usage backfill.

v5.0.3 adds cache_only so silent restore does not burn NCM API calls.

Manual user-triggered Apply can still backfill.

## Common troubleshooting

Compile check:

```bash
sudo python3 -m py_compile /opt/ncm-monitor/app.py
```

Service logs:

```bash
sudo journalctl -u ncm-monitor -n 200 --no-pager
```

Search important functions:

```bash
grep -n "router_detail\|fetchRouterDetailForChart\|applyChartRange\|restoreSavedChartRangePreferences" /opt/ncm-monitor/app.py
```

Check stored chart preferences in browser console:

```js
Object.keys(localStorage).filter(k => k.includes('ncm-monitor:router-chart-ranges'))
```

Inspect one stored preference:

```js
localStorage.getItem('ncm-monitor:router-chart-ranges:<router_id>:profile:<profile_id>')
```

## Critical release safety

Do not package runtime or sensitive files:

```text
.env
.app_secret
*.db
*.db-wal
*.db-shm
venv/
logs/
backups/
release/
__pycache__/
```

Before release, always verify:

```bash
tar -tzf <release>.tar.gz | grep -E '\.env|\.app_secret|\.db|\.db-wal|\.db-shm|venv|logs|backups|release' || echo "Clean"
```

## v5.0.3 note

This version should be treated as the first polished v5.0.x release where 90-day chart restore is user-visible and cache-safe.

Manual Apply may consume NCM API calls.

Auto-restore of a saved range should use local SQLite cache only.
