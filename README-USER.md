# NCM Monitor v5.0.4 Golden

NCM Monitor is a local web application for monitoring and analyzing NetCloud Manager router data.

It is designed for operational review, router troubleshooting, signal health review, cellular mobility analysis, data usage investigation, alert visibility, and router log correlation.

## What this application does

NCM Monitor connects to NetCloud Manager using user-provided API credentials and stores collected data locally in SQLite.

The application provides:

- Multi-dashboard support for separate NCM accounts or credential sets
- Router monitoring targets
- Router pool management
- Signal health charts
- Carrier/SIM usage charts
- Optional NCM cloud traffic overlay
- Alert timeline charts
- Router log helper panel
- Cellular mobility summaries
- Cell/tower change visibility
- 5G service mode change visibility
- API odometer tracking
- Deep-dive router analysis workflows

## New in v5.0.4

Version 5.0.4 focuses on graph usability and multi-dashboard cellular isolation.

Notable changes:

- Added drag-to-zoom behavior for router charts
- Added reset zoom controls for chart ranges
- Added crosshair cursor behavior over chart canvases
- Improved chart click behavior so empty chart background clicks do not open the log helper panel
- Restricted chart click actions to real chart points, bars, or cellular markers
- Improved reset zoom behavior using cached chart data to avoid long reset delays
- Added summarized recent cellular mobility cards
- Grouped same-day cellular events on the signal chart
- Fixed cellular monitor profile isolation so routers from one dashboard are not polled under another dashboard
- Fixed cellular API profile filtering for dashboard-specific cellular data

## Supported platform

Recommended platform:

- Ubuntu Server 20.04 or newer
- Python 3.8 or newer
- systemd
- SQLite

Raspberry Pi is not the preferred target for this release because some Python dependency builds may be unreliable on Pi OS environments.

## Installation

Extract the release package:

    tar -xzf ncm-monitor-v5.0.4-golden.tar.gz
    cd ncm-monitor-v5.0.4-golden

Run the installer:

    sudo python3 InstallScript.py

After installation, open the application in a browser:

    http://SERVER-IP:8000

The first launch will guide you through setup.

## Runtime location

The installer places the application in:

    /opt/ncm-monitor

The systemd service is:

    ncm-monitor

Useful service commands:

    sudo systemctl status ncm-monitor --no-pager -l
    sudo systemctl restart ncm-monitor
    sudo journalctl -u ncm-monitor -n 150 --no-pager

## Data storage

Runtime data is stored locally under:

    /opt/ncm-monitor/data

The primary SQLite database is:

    /opt/ncm-monitor/data/ncm_monitor.db

The release package does not include runtime data, API keys, dashboards, local databases, logs, or secrets.

## Security notes

Do not share:

- .env
- .app_secret
- SQLite database files
- Runtime backups containing credentials
- GitHub tokens or personal access tokens

## Upgrading from an older version

Before upgrading, back up the existing runtime directory:

    sudo systemctl stop ncm-monitor
    sudo tar -czf ~/ncm-monitor-backup-$(date +%Y%m%d-%H%M%S).tar.gz /opt/ncm-monitor

Then run the installer from the extracted v5.0.4 folder:

    sudo python3 InstallScript.py

The installer is intended to preserve runtime data while updating application files.

## Common pages

    /setup
    /login
    /launcher
    /ui?profile_id=1
    /monitoring-targets-ui?profile_id=1
    /pool-admin?profile_id=1
    /router-view/<router_id>?profile_id=1

Use the correct profile_id for the dashboard you are working in.
