# NCM Monitor v5.0.3

NCM Monitor is a local FastAPI-based monitoring and analysis tool for NetCloud Manager router data. It is designed for technical users who need to investigate router health, signal history, cellular behavior, NCM traffic, SIM/WAN usage, alerts, and router-level event context from a local browser UI.

## What it does

NCM Monitor connects to NCM using user-provided API credentials, stores collected data locally in SQLite, and presents router-level dashboards in a browser.

Core capabilities include:

- Multi-dashboard/profile support
- Router monitoring targets
- Pool-based router organization
- Router detail pages
- Signal health charts
- Data usage charts
- Alert timeline charts
- Router logs viewer
- Event Context side panel
- Cellular mobility/service-mode tracking
- Local cache-based historical chart restore
- API odometer tracking
- Deep Dive batch exports

## Access

After installation, browse to:

```text
http://<server-ip>:8000
```

Initial setup will guide you through admin user creation and NCM API credential entry.

## Supported platform

Recommended:

```text
Ubuntu Server 20.04+ / 22.04+ / 24.04+
Python 3.8+
```

Raspberry Pi is not the preferred target for v5.x because some Python dependency builds can fail on Pi-based environments.

## Runtime paths

Default install path:

```text
/opt/ncm-monitor
```

Main service:

```text
ncm-monitor
```

Main database:

```text
/opt/ncm-monitor/data/ncm_monitor.db
```

Global setup database:

```text
/opt/ncm-monitor/data/global/global.db
```

## Common commands

Check service:

```bash
sudo systemctl status ncm-monitor
```

Restart service:

```bash
sudo systemctl restart ncm-monitor
```

View logs:

```bash
sudo journalctl -u ncm-monitor -n 120 --no-pager
```

Follow logs:

```bash
sudo journalctl -u ncm-monitor -f
```

## Install / upgrade

From the extracted release folder, run:

```bash
sudo python3 InstallScript.py
```

Then open:

```text
http://<server-ip>:8000
```

## Release safety

Release packages should not include runtime or sensitive files:

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

## Notes

This application stores operational data locally. API credentials, databases, logs, virtual environments, and backup folders should not be included in release tarballs.
