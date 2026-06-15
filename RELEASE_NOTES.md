# NCM Monitor Release Notes

NCM Monitor Release History
===========================

v5.0.3
------

Release type:
  Golden release / stabilization / UX and cache-safety release.

Primary focus:
  Router detail chart restore behavior, Event Context reliability, cache-only restore, and Apply-button state clarity.

Major additions:
  - Added visible Apply button loading, success, and failure states.
  - Added saved chart range persistence using browser localStorage.
  - Added automatic chart range restore when returning to a router page.
  - Added visible "Restoring..." state so users know a saved 60/90/custom view is being restored.
  - Added cache_only=1 support to /router/{router_id}/detail.
  - Auto-restore now uses local SQLite cache only and skips NCM polling/backfill.
  - Manual Apply can still poll/backfill NCM when the user intentionally requests a wider range.

Chart / UI fixes:
  - Removed redundant "Loading range..." text next to Apply buttons.
  - Apply button now shows loading while range data is being fetched/rendered.
  - Apply button turns green on success.
  - Apply button turns red on failure.
  - Saved chart range key format:
      ncm-monitor:router-chart-ranges:<router_id>:profile:<profile_id>
  - Example saved preference:
      {"signal":{"mode":"90","startDate":null,"endDate":null}}

Router detail endpoint:
  - Added cache_only bool query parameter.
  - /router/{router_id}/detail?cache_only=1 reads existing SQLite data only.
  - Signal backfill is skipped when cache_only=1.
  - Usage backfill is skipped when cache_only=1.
  - Frontend fetchRouterDetailForChart(kind, {cacheOnly:true}) appends cache_only=1.
  - Frontend applyChartRange(kind, {cacheOnly:true}) uses the cache-only fetch path.

Event Context fixes:
  - Fixed daily chart Event Context window where start could be after end.
  - Daily chart clicks now use the selected local day correctly.
  - Today daily window now ends at current local time.
  - Router log filtering now considers both reported_at and created_at timestamps.
  - Same-day tail pull added for recent router logs.
  - Cached-log fallback improved.
  - Event Context CSV export preserved.
  - Nearest-log highlighting preserved.
  - Daily bucket mismatch visibility preserved.

Safety / packaging:
  - v5.0.3 golden tarball should exclude:
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
      .git/
  - User-specific dashboard names, API keys, databases, logs, router lists, and runtime state should not be included.

v5.0.2
------

Release type:
  Working feature branch.

Primary focus:
  Cellular mobility, Event Context side panel, router chart/log correlation, and router UI polish.

Fixes / changes:
  - Pool add-routers fixed tuple-vs-row access in apply_pool_module_defaults.
  - Pool add button now shows state and success.
  - Unassigned fallback behavior improved after delete/remove workflows.
  - Add Device page condensed.
  - Existing targets section reduced visual bloat.
  - Pool-managed and individually-added targets separated.
  - Open Router button fixed.
  - Router navigation improved:
      Back to Router Overview
      Pool Administration quick link
      Back to Dashboard retained
  - Cellular Mobility redesigned.
  - cell_identity_key now uses MCC|MNC|TAC|Cell ID only.
  - service_type no longer triggers false cellular mobility events.
  - 5G capability detection based on mfg_product containing "5G".
  - Added 5g_service_mode_change event for LTE <-> 5G NSA changes.
  - Non-5G service churn updates current state quietly without event noise.
  - Event Context side panel added for chart-to-log correlation.
  - Signal/Usage/Alert chart points can open Event Context.
  - Event Context default window changed to 60 minutes before/after anchor.
  - Added +/- 1 day and Jump to Present controls.
  - Added loading/spinner text.
  - Nearest log to chart anchor highlighted.
  - Anchor timestamp displayed.
  - CSV export added for Event Context.
  - Added bounded and broad-since fetch modes for router logs.
  - Daily bucket mismatch warning added.
  - Added fallback to cached logs.
  - Added earliest record line/plugin to Signal and Usage charts.
  - Ubuntu Server selected as required target due to Pi dependency build issues.

v5.0.1
------

Release type:
  First v5 stabilization release.

Fixes / changes:
  - Setup/login redirect loops resolved.
  - Add-routers crash fixed.
  - Open Router button added.
  - Add Device no longer exposes confusing Hydrate Now flow.
  - Monitoring targets collapsed by default.
  - Open Router and Back to Pool Admin navigation added.
  - Earliest record line added to Signal/Usage charts.
  - Daily bucket detection improved.
  - Add Device summary scope=direct behavior improved.
  - Condensed target view.
  - Saved module changes fixed.
  - Not Found on save fixed.

v5.0.0
------

Release type:
  Initial v5 release.

Fixes / changes:
  - Monitoring targets introduced.
  - Users can add a device without assigning it to a pool.
  - Added /monitoring-targets-ui.
  - Added display_name support for monitoring targets.
  - Auto-hydrate text added.
  - Estimated API volume shown as calls/hour and calls/month.
  - Built-in discovery modules added:
      metadata
      net_devices
  - Configurable monitoring separated from on-request features.
  - Setup wizard and login gating fixed.
  - New routers show 30-day signal and 30-day NCM usage after hydration.

v4.1.3
------

Release type:
  Python/runtime compatibility release.

Fixes / changes:
  - Python 3.8-safe requirements.
  - Missing runtime dependencies fixed.
  - app.py annotation compatibility improved.
  - Installer permissions hardened.
  - App import validation added.
  - Pool add-routers stabilized.
  - Odometer counting improved.
  - Router detail graphs stabilized.

v4.1.2
------

Release type:
  Golden v4 release.

Fixes / changes:
  - Installer ownership after venv fixed.
  - Python SyntaxWarning fixed.
  - Multi-dashboard schema improved.
  - monitoring_pools and routers made profile-aware.
  - ensure_app_profile_schema() migration logic added.
  - Unique indexes improved.
  - Router product fields added:
      product_name
      router_model
      router_image_path
  - Deep Dive job schema fixes.
  - Usage XLSX now reports MB only.
  - Odometer made per-dashboard.
  - Router logs viewer added.
  - Usage investigation UI added.
  - Release tarball verified clean of runtime/sensitive files.

v4.1.0
------

Release type:
  v4 feature/stabilization release.

Fixes / changes:
  - Router profile fallback bugs fixed.
  - target_profile_id NameError fixed.
  - Router hydration improved.
  - Router product/image handling improved.
  - Router detail data visibility fixed.
  - Pool/profile routing improved.
  - Dashboard data now loads under correct profile.
  - API odometer behavior improved.

General release safety
----------------------

Never package:
  - .env
  - .app_secret
  - *.db
  - *.db-wal
  - *.db-shm
  - venv/
  - logs/
  - backups/
  - release/
  - __pycache__/
  - .git/

Recommended validation:
  python3 -m py_compile app.py

Recommended tarball scrub check:
  tar -tzf <release>.tar.gz | grep -E '\.env|\.app_secret|\.db|\.db-wal|\.db-shm|venv|logs|backups|release|__pycache__|\.git' || echo "Clean"
