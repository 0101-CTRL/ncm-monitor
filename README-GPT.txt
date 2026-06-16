NCM Monitor v5.0.4 Golden - ChatGPT Context

Purpose:
NCM Monitor is a local FastAPI application used to collect, cache, visualize, and troubleshoot NetCloud Manager router data. It is used for customer-facing operational analysis, router health review, cellular/signal review, data usage investigation, alert review, and log correlation.

Runtime:
- Install path: /opt/ncm-monitor
- Service: ncm-monitor
- Uvicorn app: app:app
- Default port: 8000
- Runtime user: www-data
- Main DB: /opt/ncm-monitor/data/ncm_monitor.db
- Global/setup DB: /opt/ncm-monitor/data/global/global.db

Primary source file:
- app.py

Recommended OS:
- Ubuntu Server 20.04 or newer
- Python 3.8+
- systemd
- SQLite

Do not include in release packages:
- .env
- .app_secret
- *.db
- *.db-wal
- *.db-shm
- venv/
- logs/
- backups/
- data/
- release/
- __pycache__/
- app.py.bak-*

Important NCM API rules:
- /api/v2/net_devices/ accepts router=<router_id>
- net_device endpoints require net_device=<net_device_id>
- router_stream_usage_samples accepts router=<router_id>
- router_state_samples accepts router=<router_id>
- router_logs requires NCM group logging to be enabled

Important v5.0.4 changes:
1. Router chart drag zoom and reset controls
   - Signal, Usage, and Alert charts have drag-to-zoom behavior.
   - Reset zoom returns to the previous/saved/default range.
   - Reset uses cache-only chart reload to avoid slow external refresh.
   - Cursor over router chart canvases is crosshair.
   - Empty chart background clicks should not open the log helper side panel.
   - Only actual chart points, bars, or cellular markers should open the side panel.

2. Cellular event UI cleanup
   - Same-day cell/tower events are grouped on the signal chart.
   - Tooltips show grouped event counts and latest old/new TAC/cell values.
   - Recent cellular mobility section summarizes last 1 hour, 24 hours, and 7 days.
   - Raw recent event rows are hidden behind expandable details.

3. Profile isolation fixes
   - Cellular monitor router selection filters by router profile_id.
   - poll_router last_seen update is profile-scoped.
   - Cellular API summary/timeline/events endpoints normalize and filter profile_id.
   - Avoid cross-dashboard cellular data reads.

Known caveats and future work:
- Some historical/sample tables still do not have profile_id columns:
  - net_devices
  - signal_samples
  - router_state_samples
  - router_stream_usage_samples
  - usage_samples
  - alerts
  - locations
  - router_logs
- Full profile isolation would eventually require schema migrations for those tables.
- True sub-day/hourly zoom is not fully implemented yet. Current chart ranges are date/day based.
- refresh_population and local inventory backfill should be reviewed later for profile awareness.
- GitHub pushes may require authentication. Do not place tokens in scripts, README files, or the repo.

Useful commands:
- Syntax check:
  python3 -m py_compile app.py

- Runtime syntax check:
  sudo -u www-data /opt/ncm-monitor/venv/bin/python3 -m py_compile /opt/ncm-monitor/app.py

- Restart:
  sudo systemctl restart ncm-monitor

- Logs:
  sudo journalctl -u ncm-monitor -n 150 --no-pager

- Error scan:
  sudo journalctl -u ncm-monitor -n 150 --no-pager | grep -Ei "Traceback|SyntaxError|Exception|failed| no such column| no such table|database is locked|forbidden|profile-fallback" || echo "No obvious errors found"

Release packaging:
- Folder name: ncm-monitor-v5.0.4-golden
- Tarball name: ncm-monitor-v5.0.4-golden.tar.gz
- SHA file: ncm-monitor-v5.0.4-golden.tar.gz.sha256
