#!/usr/bin/env python3
from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

INSTALL_DIR = Path("/opt/ncm-monitor")
SERVICE_NAME = "ncm-monitor"
SERVICE_USER = "www-data"
SERVICE_GROUP = "www-data"


def run(cmd, *, cwd=None):
    print("+", " ".join(str(c) for c in cmd))
    subprocess.run(cmd, cwd=cwd, check=True)


def require_root():
    if os.geteuid() != 0:
        print("Please run this installer with sudo:")
        print("  sudo python3 InstallScript.py")
        sys.exit(1)


def install_os_packages():
    run(["apt-get", "update"])
    run([
        "apt-get", "install", "-y",
        "python3",
        "python3-venv",
        "python3-pip",
        "sqlite3",
        "curl",
        "rsync",
    ])


def ensure_dirs():
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    (INSTALL_DIR / "data").mkdir(parents=True, exist_ok=True)
    (INSTALL_DIR / "data" / "global").mkdir(parents=True, exist_ok=True)
    (INSTALL_DIR / "logs").mkdir(parents=True, exist_ok=True)
    (INSTALL_DIR / "backups").mkdir(parents=True, exist_ok=True)


def copy_source_if_needed():
    src = Path.cwd().resolve()
    dst = INSTALL_DIR.resolve()

    if src == dst:
        print("Installer is already running from /opt/ncm-monitor; skipping source copy.")
        return

    excludes = {
        ".env",
        ".app_secret",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".git",
        "logs",
        "backups",
        "release",
        "data",
    }

    for item in src.iterdir():
        if item.name in excludes:
            continue

        target = INSTALL_DIR / item.name

        if item.is_dir():
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)


def create_secret_if_missing():
    secret_path = INSTALL_DIR / ".app_secret"
    if not secret_path.exists():
        secret_path.write_text(secrets.token_urlsafe(48) + "\n")


def create_env_if_missing():
    env_path = INSTALL_DIR / ".env"
    if env_path.exists():
        return

    env_path.write_text(
        "NCM_MONITOR_HOST=0.0.0.0\n"
        "NCM_MONITOR_PORT=8000\n"
        "NCM_MONITOR_DB=/opt/ncm-monitor/data/ncm_monitor.db\n"
        "NCM_MONITOR_GLOBAL_DB=/opt/ncm-monitor/data/global/global.db\n"
    )


def create_venv_and_install_requirements():
    venv_dir = INSTALL_DIR / "venv"

    if not venv_dir.exists():
        run(["python3", "-m", "venv", str(venv_dir)])

    pip = venv_dir / "bin" / "pip"

    run([str(pip), "install", "--upgrade", "pip", "wheel", "setuptools"])

    requirements = INSTALL_DIR / "requirements.txt"
    if requirements.exists():
        run([str(pip), "install", "-r", str(requirements)])
    else:
        run([
            str(pip), "install",
            "fastapi",
            "uvicorn[standard]",
            "jinja2",
            "python-multipart",
            "requests",
            "openpyxl",
            "itsdangerous",
            "passlib[bcrypt]",
        ])


def validate_app():
    app_py = INSTALL_DIR / "app.py"
    if not app_py.exists():
        raise FileNotFoundError(f"Missing {app_py}")

    run([str(INSTALL_DIR / "venv" / "bin" / "python"), "-m", "py_compile", str(app_py)])


def write_systemd_service():
    service_body = f"""[Unit]
Description=NCM Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={SERVICE_USER}
Group={SERVICE_GROUP}
WorkingDirectory={INSTALL_DIR}
Environment=PYTHONUNBUFFERED=1
ExecStart={INSTALL_DIR}/venv/bin/uvicorn app:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    Path(f"/etc/systemd/system/{SERVICE_NAME}.service").write_text(service_body)


def fix_permissions():
    run(["chown", "-R", f"{SERVICE_USER}:{SERVICE_GROUP}", str(INSTALL_DIR)])
    run(["chmod", "-R", "u+rwX,g+rwX,o-rwx", str(INSTALL_DIR)])
    run(["chmod", "755", str(INSTALL_DIR / "InstallScript.py")])


def start_service():
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", SERVICE_NAME])
    run(["systemctl", "restart", SERVICE_NAME])


def main():
    require_root()

    print("Installing NCM Monitor...")

    install_os_packages()
    ensure_dirs()
    copy_source_if_needed()
    create_secret_if_missing()
    create_env_if_missing()
    create_venv_and_install_requirements()
    validate_app()
    write_systemd_service()
    fix_permissions()
    start_service()

    print()
    print("Install complete.")
    print()
    print("Open the application:")
    print("  http://<server-ip>:8000")
    print()
    print("Useful commands:")
    print("  sudo systemctl status ncm-monitor")
    print("  sudo systemctl restart ncm-monitor")
    print("  sudo journalctl -u ncm-monitor -n 120 --no-pager")


if __name__ == "__main__":
    main()
