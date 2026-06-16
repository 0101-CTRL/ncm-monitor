from __future__ import annotations

import os
import hashlib
from pathlib import Path
import sqlite3
import asyncio
import csv
import io
import tempfile
from datetime import datetime, timezone, timedelta
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo

import httpx
from dotenv import load_dotenv
from fastapi import Body, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, Response, JSONResponse, StreamingResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from itsdangerous import TimestampSigner, BadSignature
from passlib.context import CryptContext
import base64
import json
import secrets
from urllib.parse import quote

load_dotenv()

# v5 monitoring module definitions
MONITORING_MODULES = {
    "metadata": {
        "label": "Device profile",
        "default_enabled": True,
        "default_mode": "cached",
        "default_interval_minutes": 1440,
    },
    "net_devices": {
        "label": "SIM/interface discovery",
        "default_enabled": True,
        "default_mode": "discovery",
        "default_interval_minutes": None,
        "user_visible": False,
    },
    "signal_health": {
        "label": "Signal history",
        "default_enabled": True,
        "default_mode": "passive",
        "default_interval_minutes": 5,
    },
    "router_state": {
        "label": "Online/offline status",
        "default_enabled": True,
        "default_mode": "passive",
        "default_interval_minutes": 5,
    },
    "alerts": {
        "label": "Alerts",
        "default_enabled": False,
        "default_mode": "passive",
        "default_interval_minutes": 15,
    },
    "router_stream_usage": {
        "label": "NCM cloud traffic",
        "default_enabled": False,
        "default_mode": "passive",
        "default_interval_minutes": 60,
    },
    "sim_usage": {
        "label": "Carrier/SIM data usage",
        "default_enabled": False,
        "default_mode": "on_demand",
        "default_interval_minutes": None,
    },
    "location": {
        "label": "Location",
        "default_enabled": False,
        "default_mode": "passive",
        "default_interval_minutes": 1440,
    },
    "router_logs": {
        "label": "Router logs",
        "default_enabled": False,
        "default_mode": "on_demand",
        "default_interval_minutes": None,
    },
}

app = FastAPI(title="NCM Monitor")

BASE_DIR = "/opt/ncm-monitor"
DB_PATH = f"{BASE_DIR}/data/ncm_monitor.db"  # legacy rollback DB
GLOBAL_DB_PATH = f"{BASE_DIR}/data/global/global.db"
DASHBOARD_DB_DIR = f"{BASE_DIR}/data/dashboards"
ROUTER_LIST_DIR = f"{BASE_DIR}/router_lists"
STATIC_DIR = f"{BASE_DIR}/static"

# Serves /opt/ncm-monitor/static/images/E100.webp and S400.webp
app.mount("/static", StaticFiles(directory=STATIC_DIR, check_dir=False), name="static")

APP_SECRET_PATH = f"{BASE_DIR}/.app_secret"

def get_or_create_app_secret():
    env_secret = os.getenv("APP_SESSION_SECRET")
    if env_secret:
        return env_secret

    path = Path(APP_SECRET_PATH)
    if path.exists():
        return path.read_text().strip()

    secret = secrets.token_urlsafe(48)
    path.write_text(secret)
    try:
        os.chmod(APP_SECRET_PATH, 0o600)
    except Exception:
        pass
    return secret

app.add_middleware(
    SessionMiddleware,
    secret_key=get_or_create_app_secret(),
    same_site="lax",
    https_only=False,
)


NCM_BASE_URL = os.getenv("NCM_BASE_URL", "https://www.us0.cradlepointecm.com").rstrip("/")
LOCAL_TZ_NAME = os.getenv("LOCAL_TZ", "America/Boise")
CELLULAR_MONITOR_ENABLED = os.getenv("CELLULAR_MONITOR_ENABLED", "true").lower() == "true"
CELLULAR_GLOBAL_MONITOR_ENABLED = os.getenv("CELLULAR_GLOBAL_MONITOR_ENABLED", "true").lower() == "true"
CELLULAR_POLL_INTERVAL_SECONDS = int(os.getenv("CELLULAR_POLL_INTERVAL_SECONDS", "300"))
CELLULAR_GLOBAL_BATCH_SIZE = int(os.getenv("CELLULAR_GLOBAL_BATCH_SIZE", "50"))
CELLULAR_ROUTER_POLL_TIMEOUT_SECONDS = int(os.getenv("CELLULAR_ROUTER_POLL_TIMEOUT_SECONDS", "45"))
LOCAL_TZ = ZoneInfo(LOCAL_TZ_NAME)

# Monitoring scope: ignore/prevent display of historical data before this local date.
MONITORING_START_LOCAL_DATE = os.getenv("MONITORING_START_LOCAL_DATE", "2026-05-19")
MONITORING_START_LOCAL = datetime.fromisoformat(MONITORING_START_LOCAL_DATE).replace(tzinfo=LOCAL_TZ)
MONITORING_START_UTC = MONITORING_START_LOCAL.astimezone(timezone.utc).isoformat()

HEADERS = {
    "X-ECM-API-ID": os.getenv("X_ECM_API_ID", ""),
    "X-ECM-API-KEY": os.getenv("X_ECM_API_KEY", ""),
    "X-CP-API-ID": os.getenv("X_CP_API_ID", ""),
    "X-CP-API-KEY": os.getenv("X_CP_API_KEY", ""),
    "Accept": "application/json",
}


def _sqlite_connect(path):
    conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=NORMAL")
    except Exception:
        pass
    return conn


def global_db():
    return _sqlite_connect(GLOBAL_DB_PATH)


def dashboard_db_path(profile_id):
    profile_id = normalize_profile_id(profile_id)
    return f"{DASHBOARD_DB_DIR}/profile_{profile_id}.db"


def dashboard_db(profile_id=None):
    return _sqlite_connect(dashboard_db_path(profile_id))


def db(profile_id=None):
    # Temporary compatibility shim.
    # Old code still calls db(); new multi-dashboard code should call dashboard_db(profile_id)
    # or global_db() explicitly.
    if profile_id is not None:
        return dashboard_db(profile_id)
    return _sqlite_connect(DB_PATH)


def normalize_profile_id(value=None):
    try:
        pid = int(value)
        return pid if pid > 0 else 1
    except Exception:
        return 1


def payload_profile_id(payload=None, default=None):
    payload = payload or {}
    return normalize_profile_id(payload.get("profile_id", default))


def parse_dt(value):
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value.replace("Z", "+00:00")
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except Exception:
        return None


def to_local_string(value):
    dt = parse_dt(value)
    if not dt:
        return value or ""
    return dt.astimezone(LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S %Z")


def to_local_hour(value):
    dt = parse_dt(value)
    if not dt:
        return None
    return dt.astimezone(LOCAL_TZ).hour




def normalize_router_model(product_name: str | None) -> str | None:
    """Normalize NCM full_product_name to a stock router image model.

    Examples:
    - S400-C6-NA -> S400
    - S400-C18B -> S400
    - E100-5GB -> E100
    - IBR900-600M -> IBR900
    """
    if not product_name:
        return None

    raw = str(product_name).strip().upper()
    if not raw:
        return None

    known_models = [
        "AER2200",
        "IBR200",
        "IBR900",
        "R920",
        "R980",
        "W1855",
        "E3000",
        "E400",
        "E100",
        "S400",
        "X20",
    ]

    for model in known_models:
        if raw == model or raw.startswith(model + "-") or raw.startswith(model + "_"):
            return model

    # Fallback: use first token before dash/space/underscore.
    return raw.replace("_", "-").split("-")[0].split()[0]


def router_image_for_product(product_name: str | None) -> str | None:
    """Return browser path for the best matching router image."""
    model = normalize_router_model(product_name)
    if not model:
        return None

    image_map = {
        "AER2200": "/static/images/AER2200.png",
        "IBR200": "/static/images/IBR200.png",
        "X20": "/static/images/X20.png",
        "E400": "/static/images/E400.png",
        "IBR900": "/static/images/IBR900.png",
        "R920": "/static/images/R920.png",
        "R980": "/static/images/R980.png",
        "W1855": "/static/images/W1855.png",
        "E3000": "/static/images/E3000.png",
        "E100": "/static/images/E100.webp",
        "S400": "/static/images/S400.webp",
    }

    return image_map.get(model)


def now_utc():
    return datetime.now(timezone.utc).isoformat()


def ensure_monitoring_target(conn, profile_id, router_id, pool_id=None, display_name=None):
    """Create/update a v5 monitoring target without forcing passive polling."""
    now = now_utc()
    router_id = str(router_id).strip()

    conn.execute("""
        INSERT OR IGNORE INTO monitoring_targets (
            profile_id,
            router_id,
            pool_id,
            display_name,
            enabled,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, 1, ?, ?)
    """, (
        profile_id,
        router_id,
        pool_id,
        display_name,
        now,
        now,
    ))

    conn.execute("""
        UPDATE monitoring_targets
        SET pool_id = COALESCE(?, pool_id),
            display_name = COALESCE(?, display_name),
            updated_at = ?
        WHERE profile_id = ? AND router_id = ?
    """, (
        pool_id,
        display_name,
        now,
        profile_id,
        router_id,
    ))


def ensure_monitoring_module_defaults(conn, profile_id, router_id):
    """Initialize default v5 module settings for a router target."""
    now = now_utc()
    router_id = str(router_id).strip()

    for module_name, cfg in MONITORING_MODULES.items():
        conn.execute("""
            INSERT OR IGNORE INTO monitoring_target_modules (
                profile_id,
                router_id,
                module_name,
                enabled,
                interval_minutes,
                mode,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            profile_id,
            router_id,
            module_name,
            1 if cfg.get("default_enabled") else 0,
            cfg.get("default_interval_minutes"),
            cfg.get("default_mode", "disabled"),
            now,
        ))


def cell_identity_key_from_metric(metric: dict) -> str:
    # Cellular mobility identity intentionally excludes service_type.
    # Service type can oscillate between LTE/5G NSA without an actual tower/cell move.
    return "|".join([
        str(metric.get("mcc") or ""),
        str(metric.get("mnc") or ""),
        str(metric.get("tac") or ""),
        str(metric.get("cell_id") or ""),
    ])


RADIO_CONTEXT_FIELDS = ["rfband", "rfband5g", "rfchannel", "ltebandwidth", "mtu"]


def radio_context_key_from_metric(metric: dict) -> str:
    return "|".join(str(metric.get(k) or "") for k in RADIO_CONTEXT_FIELDS)


def radio_context_changed(old_row, metric: dict) -> bool:
    for field in RADIO_CONTEXT_FIELDS:
        try:
            old_value = old_row[field]
        except Exception:
            old_value = None
        if str(old_value or "") != str(metric.get(field) or ""):
            return True
    return False


def is_5g_capable_mfg_product(value) -> bool:
    return "5G" in str(value or "").upper()


def is_5g_capable_net_device(conn, net_device_id: str) -> bool:
    try:
        row = conn.execute(
            "SELECT mfg_product FROM net_devices WHERE id = ? LIMIT 1",
            (str(net_device_id),),
        ).fetchone()

        if not row:
            return False

        try:
            mfg_product = row["mfg_product"]
        except Exception:
            mfg_product = row[0]

        return is_5g_capable_mfg_product(mfg_product)
    except Exception:
        return False


async def maybe_enrich_metric_with_fresh_signal(
    router_id: str,
    net_device_id: str,
    metric: dict,
    profile_id=None,
    stale_threshold_seconds: int = 180,
):
    """
    When a cellular identity/radio-context change is about to be recorded,
    make sure the signal values attached to that event are fresh enough.

    net_device_metrics can lag behind local signal history. If the latest local
    signal sample is older than metric.update_ts by more than the threshold,
    refresh net_device_signal_samples and use the closest local sample.
    """
    try:
        router_id = str(router_id)
        net_device_id = str(net_device_id)
        event_dt = parse_dt(metric.get("update_ts")) or datetime.now(timezone.utc)

        with db() as conn:
            conn.row_factory = sqlite3.Row

            old = conn.execute(
                """
                SELECT *
                FROM cellular_current_state
                WHERE net_device_id = ?
                """,
                (net_device_id,),
            ).fetchone()

            # No baseline means first_seen. Do not spend extra API calls.
            if old is None:
                return metric

            new_identity_key = cell_identity_key_from_metric(metric)
            identity_changed = str(old["identity_key"] or "") != str(new_identity_key or "")
            radio_changed = radio_context_changed(old, metric)

            if not identity_changed and not radio_changed:
                return metric

            latest = conn.execute(
                """
                SELECT created_at
                FROM signal_samples
                WHERE router_id = ?
                  AND net_device_id = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (router_id, net_device_id),
            ).fetchone()

            latest_dt = parse_dt(latest["created_at"]) if latest and latest["created_at"] else None

            should_refresh = latest_dt is None or latest_dt < (event_dt - timedelta(seconds=stale_threshold_seconds))

            sim_row = conn.execute(
                """
                SELECT sim_label
                FROM net_devices
                WHERE id = ?
                LIMIT 1
                """,
                (net_device_id,),
            ).fetchone()

            sim_label = sim_row["sim_label"] if sim_row and sim_row["sim_label"] else None

        if should_refresh:
            try:
                await poll_signal_samples(
                    router_id,
                    net_device_id,
                    sim_label or "UNKNOWN",
                    profile_id=profile_id,
                    days=1,
                )
            except Exception as exc:
                print(f"[cellular-signal-refresh] Failed refreshing signal for router={router_id} net_device={net_device_id}: {exc}")

        # Use the closest local signal sample to the metric/event timestamp.
        with db() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT created_at, dbm, rsrp, rsrq, sinr, signal_percent
                FROM signal_samples
                WHERE router_id = ?
                  AND net_device_id = ?
                ORDER BY created_at DESC
                LIMIT 500
                """,
                (router_id, net_device_id),
            ).fetchall()

        best = None
        best_delta = None

        for sample in rows:
            sample_dt = parse_dt(sample["created_at"])
            if not sample_dt:
                continue

            delta = abs((sample_dt - event_dt).total_seconds())
            if best_delta is None or delta < best_delta:
                best = sample
                best_delta = delta

        if best is not None:
            for metric_key, sample_key in (
                ("dbm", "dbm"),
                ("rsrp", "rsrp"),
                ("rsrq", "rsrq"),
                ("sinr", "sinr"),
                ("signal_strength", "signal_percent"),
            ):
                value = best[sample_key]
                if value is not None:
                    metric[metric_key] = value

            metric["_signal_enriched_from_sample_at"] = best["created_at"]
            metric["_signal_enriched_delta_seconds"] = best_delta
            metric["_signal_refreshed_for_event"] = should_refresh

    except Exception as exc:
        print(f"[cellular-signal-enrich] Failed enriching event signal router={router_id} net_device={net_device_id}: {exc}")

    return metric


def classify_cellular_event(old_row, metric: dict) -> str:
    old_mcc = old_row["mcc"]
    old_mnc = old_row["mnc"]
    old_tac = old_row["tac"]
    old_cell_id = old_row["cell_id"]
    old_service_type = old_row["service_type"]

    new_mcc = metric.get("mcc")
    new_mnc = metric.get("mnc")
    new_tac = metric.get("tac")
    new_cell_id = metric.get("cell_id")
    new_service_type = metric.get("service_type")

    carrier_changed = old_mcc != new_mcc or old_mnc != new_mnc
    tac_changed = old_tac != new_tac
    cell_changed = old_cell_id != new_cell_id
    service_changed = old_service_type != new_service_type

    if carrier_changed:
        return "carrier_change"
    if tac_changed and cell_changed:
        return "tac_and_cell_change"
    if cell_changed:
        return "cell_id_change"
    if tac_changed:
        return "tac_change"
    # service_type-only changes are intentionally not treated as mobility events.
    # They are still stored on cellular_current_state, but do not create event rows.
    return "cell_identity_change"



def _cellular_identity_value(value) -> str:
    """Normalize cellular identity values for matching/storage.

    NCM may return Cell ID as "21590529 (0x1497201)" while OpenCellID
    stores the decimal value. Keep only the decimal portion for lookup/history.
    """
    if value is None:
        return ""
    value = str(value).strip()
    if " (0x" in value.lower():
        value = value.split("(", 1)[0].strip()
    return value


def _cellular_metric_float(metric: dict, key: str):
    value = metric.get(key)
    if value is None:
        return None

    value = str(value).strip()
    if not value:
        return None

    value = value.replace("%", "").strip()

    # Keep the first numeric token if NCM ever includes unit text.
    value = value.split()[0]

    try:
        return float(value)
    except Exception:
        return None


def _row_value(row, key):
    try:
        return row[key]
    except Exception:
        try:
            return row.get(key)
        except Exception:
            return None


def _identity_stat_update(row, prefix: str, value):
    count_key = f"{prefix}_sample_count"
    min_key = f"min_{prefix}"
    max_key = f"max_{prefix}"
    avg_key = f"avg_{prefix}"

    old_count = int(_row_value(row, count_key) or 0)
    old_min = _row_value(row, min_key)
    old_max = _row_value(row, max_key)
    old_avg = _row_value(row, avg_key)

    new_count = old_count + 1
    new_min = value if old_min is None else min(float(old_min), value)
    new_max = value if old_max is None else max(float(old_max), value)

    if old_avg is None:
        new_avg = value
    else:
        new_avg = ((float(old_avg) * old_count) + value) / new_count

    return new_min, new_max, new_avg, new_count


def update_cellular_identity_history_signal_stats(conn, router_id: str, net_device_id: str, metric: dict, profile_id=None):
    """Update RF quality aggregates for the current cellular identity history row."""
    try:
        profile_id = int(profile_id or 1)
    except Exception:
        profile_id = 1

    router_id = str(router_id)
    net_device_id = str(net_device_id)

    mcc = _cellular_identity_value(metric.get("mcc"))
    mnc = _cellular_identity_value(metric.get("mnc"))
    tac = _cellular_identity_value(metric.get("tac"))
    cell_id = _cellular_identity_value(metric.get("cell_id"))

    if not all((mcc, mnc, tac, cell_id)):
        return {"status": "skipped", "reason": "incomplete_cell_identity"}

    identity_key = f"{mcc}|{mnc}|{tac}|{cell_id}"

    row = conn.execute("""
        SELECT *
        FROM cellular_identity_history
        WHERE profile_id = ?
          AND router_id = ?
          AND net_device_id = ?
          AND identity_key = ?
          AND is_current = 1
        ORDER BY id DESC
        LIMIT 1
    """, (profile_id, router_id, net_device_id, identity_key)).fetchone()

    if not row:
        return {"status": "skipped", "reason": "no_current_identity_history_row"}

    metric_map = {
        "dbm": "dbm",
        "rsrp": "rsrp",
        "rsrq": "rsrq",
        "sinr": "sinr",
        "signal_strength": "signal_strength",
    }

    updates = []
    params = []

    for metric_key, prefix in metric_map.items():
        value = _cellular_metric_float(metric, metric_key)
        if value is None:
            continue

        new_min, new_max, new_avg, new_count = _identity_stat_update(row, prefix, value)

        updates.extend([
            f"last_{prefix} = ?",
            f"min_{prefix} = ?",
            f"max_{prefix} = ?",
            f"avg_{prefix} = ?",
            f"{prefix}_sample_count = ?",
        ])
        params.extend([value, new_min, new_max, new_avg, new_count])

    if not updates:
        return {"status": "skipped", "reason": "no_rf_values"}

    updates.append("updated_at = ?")
    params.append(now_utc())
    params.append(row["id"])

    conn.execute(f"""
        UPDATE cellular_identity_history
        SET {", ".join(updates)}
        WHERE id = ?
    """, params)

    return {
        "status": "updated",
        "identity_history_id": row["id"],
        "identity_key": identity_key,
        "fields_updated": len(updates) - 1,
    }



def lookup_opencellid_cell(conn, mcc, mnc, tac, cell_id):
    """Return an exact OpenCellID match for MCC/MNC/TAC/Cell ID, if imported."""
    mcc = _cellular_identity_value(mcc)
    mnc = _cellular_identity_value(mnc)
    tac = _cellular_identity_value(tac)
    cell_id = _cellular_identity_value(cell_id)

    if not all((mcc, mnc, tac, cell_id)):
        return None

    return conn.execute(
        """
        SELECT
            mcc,
            mnc,
            tac,
            cell_id,
            lat,
            lon,
            range_m,
            samples,
            updated
        FROM opencellid_cells
        WHERE mcc = ?
          AND mnc = ?
          AND tac = ?
          AND cell_id = ?
        LIMIT 1
        """,
        (mcc, mnc, tac, cell_id),
    ).fetchone()


def upsert_cellular_identity_history(conn, router_id: str, router_name: str, net_device_id: str, metric: dict, profile_id=None):
    """
    Maintain router-observed cellular identity history.

    This is intentionally separate from cellular_events:
    - cellular_events captures notable changes for UI/event context.
    - cellular_identity_history captures observed tower identity over time.
    """
    profile_id = int(profile_id or 1)
    router_id = str(router_id)
    router_name = str(router_name or router_id)
    net_device_id = str(net_device_id)

    mcc = _cellular_identity_value(metric.get("mcc"))
    mnc = _cellular_identity_value(metric.get("mnc"))
    tac = _cellular_identity_value(metric.get("tac"))
    cell_id = _cellular_identity_value(metric.get("cell_id"))

    if not all((mcc, mnc, tac, cell_id)):
        return {"status": "skipped", "reason": "incomplete_cell_identity"}

    identity_key = f"{mcc}|{mnc}|{tac}|{cell_id}"
    now = now_utc()
    last_sample_ts = metric.get("update_ts") or now

    sim_label = None
    try:
        sim_row = conn.execute(
            "SELECT sim_label FROM net_devices WHERE id = ? LIMIT 1",
            (net_device_id,),
        ).fetchone()
        if sim_row:
            sim_label = sim_row["sim_label"] if isinstance(sim_row, sqlite3.Row) else sim_row[0]
    except Exception:
        sim_label = None

    match = lookup_opencellid_cell(conn, mcc, mnc, tac, cell_id)
    match_status = "exact" if match else "unmatched"

    if match:
        opencellid_mcc = match["mcc"]
        opencellid_mnc = match["mnc"]
        opencellid_tac = match["tac"]
        opencellid_cell_id = match["cell_id"]
        opencellid_lat = match["lat"]
        opencellid_lon = match["lon"]
        opencellid_range_m = match["range_m"]
        opencellid_samples = match["samples"]
        opencellid_updated = match["updated"]
    else:
        opencellid_mcc = None
        opencellid_mnc = None
        opencellid_tac = None
        opencellid_cell_id = None
        opencellid_lat = None
        opencellid_lon = None
        opencellid_range_m = None
        opencellid_samples = None
        opencellid_updated = None

    # Close any previously-current identity for this modem when the identity changes.
    conn.execute(
        """
        UPDATE cellular_identity_history
        SET
            is_current = 0,
            closed_at = COALESCE(closed_at, ?),
            updated_at = ?
        WHERE net_device_id = ?
          AND is_current = 1
          AND COALESCE(identity_key, '') != ?
        """,
        (now, now, net_device_id, identity_key),
    )

    current = conn.execute(
        """
        SELECT id
        FROM cellular_identity_history
        WHERE net_device_id = ?
          AND is_current = 1
          AND identity_key = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (net_device_id, identity_key),
    ).fetchone()

    values = (
        profile_id,
        router_id,
        router_name,
        net_device_id,
        sim_label,
        mcc,
        mnc,
        tac,
        cell_id,
        identity_key,
        metric.get("service_type"),
        metric.get("rfband"),
        metric.get("rfband5g"),
        metric.get("rfchannel"),
        metric.get("ltebandwidth"),
        metric.get("mtu"),
        now,
        last_sample_ts,
        match_status,
        now,
        opencellid_mcc,
        opencellid_mnc,
        opencellid_tac,
        opencellid_cell_id,
        opencellid_lat,
        opencellid_lon,
        opencellid_range_m,
        opencellid_samples,
        opencellid_updated,
        now,
    )

    if current:
        history_id = current["id"] if isinstance(current, sqlite3.Row) else current[0]
        conn.execute(
            """
            UPDATE cellular_identity_history
            SET
                profile_id = ?,
                router_id = ?,
                router_name = ?,
                net_device_id = ?,
                sim_label = ?,
                mcc = ?,
                mnc = ?,
                tac = ?,
                cell_id = ?,
                identity_key = ?,
                service_type = ?,
                rfband = ?,
                rfband5g = ?,
                rfchannel = ?,
                ltebandwidth = ?,
                mtu = ?,
                last_seen_ts = ?,
                last_sample_ts = ?,
                sample_count = sample_count + 1,
                is_current = 1,
                closed_at = NULL,
                match_status = ?,
                match_updated_at = ?,
                opencellid_mcc = ?,
                opencellid_mnc = ?,
                opencellid_tac = ?,
                opencellid_cell_id = ?,
                opencellid_lat = ?,
                opencellid_lon = ?,
                opencellid_range_m = ?,
                opencellid_samples = ?,
                opencellid_updated = ?,
                updated_at = ?
            WHERE id = ?
            """,
            values + (history_id,),
        )
        return {"status": "updated", "match_status": match_status, "history_id": history_id}

    conn.execute(
        """
        INSERT INTO cellular_identity_history (
            profile_id,
            router_id,
            router_name,
            net_device_id,
            sim_label,
            mcc,
            mnc,
            tac,
            cell_id,
            identity_key,
            service_type,
            rfband,
            rfband5g,
            rfchannel,
            ltebandwidth,
            mtu,
            first_seen_ts,
            last_seen_ts,
            last_sample_ts,
            sample_count,
            is_current,
            match_status,
            match_updated_at,
            opencellid_mcc,
            opencellid_mnc,
            opencellid_tac,
            opencellid_cell_id,
            opencellid_lat,
            opencellid_lon,
            opencellid_range_m,
            opencellid_samples,
            opencellid_updated,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            profile_id,
            router_id,
            router_name,
            net_device_id,
            sim_label,
            mcc,
            mnc,
            tac,
            cell_id,
            identity_key,
            metric.get("service_type"),
            metric.get("rfband"),
            metric.get("rfband5g"),
            metric.get("rfchannel"),
            metric.get("ltebandwidth"),
            metric.get("mtu"),
            now,
            now,
            last_sample_ts,
            match_status,
            now,
            opencellid_mcc,
            opencellid_mnc,
            opencellid_tac,
            opencellid_cell_id,
            opencellid_lat,
            opencellid_lon,
            opencellid_range_m,
            opencellid_samples,
            opencellid_updated,
            now,
            now,
        ),
    )

    return {"status": "inserted", "match_status": match_status}



def record_cellular_metric_event(conn, router_id: str, net_device_id: str, metric: dict, profile_id=None):
    """
    Records first_seen and cellular identity changes for a modem net device.

    Cellular identity is:
      MCC + MNC + TAC + Cell ID + Service Type
    """

    if not CELLULAR_MONITOR_ENABLED:
        return {"status": "disabled"}

    try:
        profile_id = int(profile_id or 1)
    except Exception:
        profile_id = 1

    ensure_cellular_monitor_tables(profile_id)

    router_id = str(router_id)
    net_device_id = str(net_device_id)

    new_identity_key = cell_identity_key_from_metric(metric)
    now = now_utc()

    cellular_fields = [
        metric.get("mcc"),
        metric.get("mnc"),
        metric.get("tac"),
        metric.get("cell_id"),
    ]
    service_type = str(metric.get("service_type") or "").strip().lower()

    if not any(str(v or "").strip() for v in cellular_fields):
        return {"status": "skipped", "reason": "empty_cell_identity"}

    if service_type in {"not available", "unavailable", "unknown", "none", "null"} and not any(str(v or "").strip() for v in cellular_fields):
        return {"status": "skipped", "reason": "inactive_or_unavailable_modem"}

    conn.row_factory = sqlite3.Row

    old = conn.execute(
        """
        SELECT *
        FROM cellular_current_state
        WHERE net_device_id = ?
        """,
        (net_device_id,)
    ).fetchone()

    router_name = router_id

    try:
        upsert_cellular_identity_history(
            conn,
            router_id=router_id,
            router_name=router_name,
            net_device_id=net_device_id,
            metric=metric,
            profile_id=profile_id,
        )
        update_cellular_identity_history_signal_stats(
            conn,
            router_id=router_id,
            net_device_id=net_device_id,
            metric=metric,
            profile_id=profile_id,
        )
    except Exception as exc:
        print(f"[cellular-identity-history] Failed updating history router={router_id} net_device={net_device_id}: {exc}")

    if old is None:
        conn.execute(
            """
            INSERT INTO cellular_events (
                profile_id, router_id, router_name, net_device_id,
                event_type,
                new_mcc, new_mnc, new_tac, new_cell_id, new_service_type, new_identity_key,
                new_rfband, new_rfband5g, new_rfchannel, new_ltebandwidth, new_mtu,
                dbm, rsrp, rsrq, sinr, signal_strength,
                ncm_update_ts, detected_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                profile_id,
                router_id,
                router_name,
                net_device_id,
                "first_seen",
                metric.get("mcc"),
                metric.get("mnc"),
                metric.get("tac"),
                metric.get("cell_id"),
                metric.get("service_type"),
                new_identity_key,
                metric.get("rfband"),
                metric.get("rfband5g"),
                metric.get("rfchannel"),
                metric.get("ltebandwidth"),
                metric.get("mtu"),
                metric.get("dbm"),
                metric.get("rsrp"),
                metric.get("rsrq"),
                metric.get("sinr"),
                metric.get("signal_strength"),
                metric.get("update_ts"),
                now,
            )
        )

        conn.execute(
            """
            INSERT OR REPLACE INTO cellular_current_state (
                net_device_id, router_id, router_name, profile_id,
                mcc, mnc, tac, cell_id, service_type,
                dbm, rsrp, rsrq, sinr, signal_strength,
                rfband, rfband5g, rfchannel, ltebandwidth, mtu,
                identity_key,
                first_seen_ts, last_seen_ts, update_ts,
                poll_count, change_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0)
            """,
            (
                net_device_id,
                router_id,
                router_name,
                profile_id,
                metric.get("mcc"),
                metric.get("mnc"),
                metric.get("tac"),
                metric.get("cell_id"),
                metric.get("service_type"),
                metric.get("dbm"),
                metric.get("rsrp"),
                metric.get("rsrq"),
                metric.get("sinr"),
                metric.get("signal_strength"),
                metric.get("rfband"),
                metric.get("rfband5g"),
                metric.get("rfchannel"),
                metric.get("ltebandwidth"),
                metric.get("mtu"),
                new_identity_key,
                now,
                now,
                metric.get("update_ts"),
            )
        )

        return {"status": "first_seen"}

    old_service_type = str(old["service_type"] or "")
    new_service_type = str(metric.get("service_type") or "")
    service_mode_changed = old_service_type != new_service_type
    fiveg_capable = is_5g_capable_net_device(conn, net_device_id)

    if service_mode_changed and old["identity_key"] == new_identity_key:
        if fiveg_capable:
            event_type = "5g_service_mode_change"

            conn.execute(
                """
                INSERT INTO cellular_events (
                    profile_id, router_id, router_name, net_device_id,
                    event_type,
                    old_mcc, old_mnc, old_tac, old_cell_id, old_service_type, old_identity_key,
                    old_rfband, old_rfband5g, old_rfchannel, old_ltebandwidth, old_mtu,
                    new_mcc, new_mnc, new_tac, new_cell_id, new_service_type, new_identity_key,
                    new_rfband, new_rfband5g, new_rfchannel, new_ltebandwidth, new_mtu,
                    dbm, rsrp, rsrq, sinr, signal_strength,
                    ncm_update_ts, detected_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile_id,
                    router_id,
                    router_name,
                    net_device_id,
                    event_type,
                    old["mcc"],
                    old["mnc"],
                    old["tac"],
                    old["cell_id"],
                    old["service_type"],
                    old["identity_key"],
                    old["rfband"],
                    old["rfband5g"],
                    old["rfchannel"],
                    old["ltebandwidth"],
                    old["mtu"],
                    metric.get("mcc"),
                    metric.get("mnc"),
                    metric.get("tac"),
                    metric.get("cell_id"),
                    metric.get("service_type"),
                    new_identity_key,
                    metric.get("rfband"),
                    metric.get("rfband5g"),
                    metric.get("rfchannel"),
                    metric.get("ltebandwidth"),
                    metric.get("mtu"),
                    metric.get("dbm"),
                    metric.get("rsrp"),
                    metric.get("rsrq"),
                    metric.get("sinr"),
                    metric.get("signal_strength"),
                    metric.get("update_ts"),
                    now,
                )
            )

            conn.execute(
                """
                UPDATE cellular_current_state
                SET
                    service_type = ?,
                    dbm = ?,
                    rsrp = ?,
                    rsrq = ?,
                    sinr = ?,
                    signal_strength = ?,
                    rfband = ?,
                    rfband5g = ?,
                    rfchannel = ?,
                    ltebandwidth = ?,
                    mtu = ?,
                    last_seen_ts = ?,
                    update_ts = ?,
                    poll_count = poll_count + 1,
                    change_count = change_count + 1
                WHERE net_device_id = ?
                """,
                (
                    metric.get("service_type"),
                    metric.get("dbm"),
                    metric.get("rsrp"),
                    metric.get("rsrq"),
                    metric.get("sinr"),
                    metric.get("signal_strength"),
                    metric.get("rfband"),
                    metric.get("rfband5g"),
                    metric.get("rfchannel"),
                    metric.get("ltebandwidth"),
                    metric.get("mtu"),
                    now,
                    metric.get("update_ts"),
                    net_device_id,
                )
            )

            return {"status": event_type}

        conn.execute(
            """
            UPDATE cellular_current_state
            SET
                service_type = ?,
                dbm = ?,
                rsrp = ?,
                rsrq = ?,
                sinr = ?,
                signal_strength = ?,
                rfband = ?,
                rfband5g = ?,
                rfchannel = ?,
                ltebandwidth = ?,
                mtu = ?,
                last_seen_ts = ?,
                update_ts = ?,
                poll_count = poll_count + 1
            WHERE net_device_id = ?
            """,
            (
                metric.get("service_type"),
                metric.get("dbm"),
                metric.get("rsrp"),
                metric.get("rsrq"),
                metric.get("sinr"),
                metric.get("signal_strength"),
                metric.get("rfband"),
                metric.get("rfband5g"),
                metric.get("rfchannel"),
                metric.get("ltebandwidth"),
                metric.get("mtu"),
                now,
                metric.get("update_ts"),
                net_device_id,
            )
        )

        return {"status": "service_type_updated_no_event"}

    if old["identity_key"] != new_identity_key:
        event_type = classify_cellular_event(old, metric)

        conn.execute(
            """
            INSERT INTO cellular_events (
                profile_id, router_id, router_name, net_device_id,
                event_type,
                old_mcc, old_mnc, old_tac, old_cell_id, old_service_type, old_identity_key,
                old_rfband, old_rfband5g, old_rfchannel, old_ltebandwidth, old_mtu,
                new_mcc, new_mnc, new_tac, new_cell_id, new_service_type, new_identity_key,
                new_rfband, new_rfband5g, new_rfchannel, new_ltebandwidth, new_mtu,
                dbm, rsrp, rsrq, sinr, signal_strength,
                ncm_update_ts, detected_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                profile_id,
                router_id,
                router_name,
                net_device_id,
                event_type,
                old["mcc"],
                old["mnc"],
                old["tac"],
                old["cell_id"],
                old["service_type"],
                old["identity_key"],
                old["rfband"],
                old["rfband5g"],
                old["rfchannel"],
                old["ltebandwidth"],
                old["mtu"],
                metric.get("mcc"),
                metric.get("mnc"),
                metric.get("tac"),
                metric.get("cell_id"),
                metric.get("service_type"),
                new_identity_key,
                metric.get("rfband"),
                metric.get("rfband5g"),
                metric.get("rfchannel"),
                metric.get("ltebandwidth"),
                metric.get("mtu"),
                metric.get("dbm"),
                metric.get("rsrp"),
                metric.get("rsrq"),
                metric.get("sinr"),
                metric.get("signal_strength"),
                metric.get("update_ts"),
                now,
            )
        )

        conn.execute(
            """
            UPDATE cellular_current_state
            SET
                router_id = ?,
                router_name = ?,
                profile_id = ?,
                mcc = ?,
                mnc = ?,
                tac = ?,
                cell_id = ?,
                service_type = ?,
                rfband = ?,
                rfband5g = ?,
                rfchannel = ?,
                ltebandwidth = ?,
                mtu = ?,
                dbm = ?,
                rsrp = ?,
                rsrq = ?,
                sinr = ?,
                signal_strength = ?,
                identity_key = ?,
                last_seen_ts = ?,
                update_ts = ?,
                poll_count = poll_count + 1,
                change_count = change_count + 1
            WHERE net_device_id = ?
            """,
            (
                router_id,
                router_name,
                profile_id,
                metric.get("mcc"),
                metric.get("mnc"),
                metric.get("tac"),
                metric.get("cell_id"),
                metric.get("service_type"),
                metric.get("rfband"),
                metric.get("rfband5g"),
                metric.get("rfchannel"),
                metric.get("ltebandwidth"),
                metric.get("mtu"),
                metric.get("dbm"),
                metric.get("rsrp"),
                metric.get("rsrq"),
                metric.get("sinr"),
                metric.get("signal_strength"),
                new_identity_key,
                now,
                metric.get("update_ts"),
                net_device_id,
            )
        )

        return {"status": event_type}

    if radio_context_changed(old, metric):
        event_type = "radio_context_change"
        conn.execute(
            """
            INSERT INTO cellular_events (
                profile_id, router_id, router_name, net_device_id,
                event_type,
                old_mcc, old_mnc, old_tac, old_cell_id, old_service_type, old_identity_key,
                old_rfband, old_rfband5g, old_rfchannel, old_ltebandwidth, old_mtu,
                new_mcc, new_mnc, new_tac, new_cell_id, new_service_type, new_identity_key,
                new_rfband, new_rfband5g, new_rfchannel, new_ltebandwidth, new_mtu,
                dbm, rsrp, rsrq, sinr, signal_strength,
                ncm_update_ts, detected_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                profile_id,
                router_id,
                router_name,
                net_device_id,
                event_type,
                old["mcc"],
                old["mnc"],
                old["tac"],
                old["cell_id"],
                old["service_type"],
                old["identity_key"],
                old["rfband"],
                old["rfband5g"],
                old["rfchannel"],
                old["ltebandwidth"],
                old["mtu"],
                metric.get("mcc"),
                metric.get("mnc"),
                metric.get("tac"),
                metric.get("cell_id"),
                metric.get("service_type"),
                new_identity_key,
                metric.get("rfband"),
                metric.get("rfband5g"),
                metric.get("rfchannel"),
                metric.get("ltebandwidth"),
                metric.get("mtu"),
                metric.get("dbm"),
                metric.get("rsrp"),
                metric.get("rsrq"),
                metric.get("sinr"),
                metric.get("signal_strength"),
                metric.get("update_ts"),
                now,
            )
        )

        conn.execute(
            """
            UPDATE cellular_current_state
            SET
                dbm = ?,
                rsrp = ?,
                rsrq = ?,
                sinr = ?,
                signal_strength = ?,
                rfband = ?,
                rfband5g = ?,
                rfchannel = ?,
                ltebandwidth = ?,
                mtu = ?,
                last_seen_ts = ?,
                update_ts = ?,
                poll_count = poll_count + 1,
                change_count = change_count + 1
            WHERE net_device_id = ?
            """,
            (
                metric.get("dbm"),
                metric.get("rsrp"),
                metric.get("rsrq"),
                metric.get("sinr"),
                metric.get("signal_strength"),
                metric.get("rfband"),
                metric.get("rfband5g"),
                metric.get("rfchannel"),
                metric.get("ltebandwidth"),
                metric.get("mtu"),
                now,
                metric.get("update_ts"),
                net_device_id,
            )
        )

        return {"status": event_type}

    conn.execute(
        """
        UPDATE cellular_current_state
        SET
            dbm = ?,
            rsrp = ?,
            rsrq = ?,
            sinr = ?,
            signal_strength = ?,
            rfband = ?,
            rfband5g = ?,
            rfchannel = ?,
            ltebandwidth = ?,
            mtu = ?,
            last_seen_ts = ?,
            update_ts = ?,
            poll_count = poll_count + 1
        WHERE net_device_id = ?
        """,
        (
            metric.get("dbm"),
            metric.get("rsrp"),
            metric.get("rsrq"),
            metric.get("sinr"),
            metric.get("signal_strength"),
            metric.get("rfband"),
            metric.get("rfband5g"),
            metric.get("rfchannel"),
            metric.get("ltebandwidth"),
            metric.get("mtu"),
            now,
            metric.get("update_ts"),
            net_device_id,
        )
    )

    return {"status": "unchanged"}





def ensure_cellular_monitor_tables(profile_id=None):
    """Ensure cellular monitor tables exist in the selected dashboard/profile DB."""
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cellular_current_state (
                net_device_id TEXT PRIMARY KEY,
                router_id TEXT,
                router_name TEXT,
                profile_id INTEGER DEFAULT 1,

                mcc TEXT,
                mnc TEXT,
                tac TEXT,
                cell_id TEXT,
                service_type TEXT,

                dbm REAL,
                rsrp REAL,
                rsrq REAL,
                sinr REAL,
                signal_strength REAL,

                rfband TEXT,
                rfband5g TEXT,
                rfchannel TEXT,
                ltebandwidth TEXT,
                mtu TEXT,

                identity_key TEXT,

                first_seen_ts TEXT,
                last_seen_ts TEXT,
                update_ts TEXT,

                poll_count INTEGER DEFAULT 0,
                change_count INTEGER DEFAULT 0
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS cellular_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                profile_id INTEGER DEFAULT 1,
                router_id TEXT,
                router_name TEXT,
                net_device_id TEXT,

                event_type TEXT,

                old_mcc TEXT,
                old_mnc TEXT,
                old_tac TEXT,
                old_cell_id TEXT,
                old_service_type TEXT,
                old_identity_key TEXT,
                old_rfband TEXT,
                old_rfband5g TEXT,
                old_rfchannel TEXT,
                old_ltebandwidth TEXT,
                old_mtu TEXT,

                new_mcc TEXT,
                new_mnc TEXT,
                new_tac TEXT,
                new_cell_id TEXT,
                new_service_type TEXT,
                new_identity_key TEXT,
                new_rfband TEXT,
                new_rfband5g TEXT,
                new_rfchannel TEXT,
                new_ltebandwidth TEXT,
                new_mtu TEXT,

                dbm REAL,
                rsrp REAL,
                rsrq REAL,
                sinr REAL,
                signal_strength REAL,

                ncm_update_ts TEXT,
                detected_at TEXT
            )
        """)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_cellular_events_detected_at ON cellular_events(detected_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cellular_events_profile_detected ON cellular_events(profile_id, detected_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cellular_events_net_device ON cellular_events(net_device_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cellular_events_event_type ON cellular_events(event_type)")

        # v5.1.0 OpenCellID reference and cellular identity history tables.
        # OpenCellID is global reference data, not profile/customer-specific data.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS opencellid_imports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_file TEXT,
                imported_at TEXT,
                rows_seen INTEGER DEFAULT 0,
                rows_inserted INTEGER DEFAULT 0,
                rows_updated INTEGER DEFAULT 0,
                rows_skipped INTEGER DEFAULT 0,
                status TEXT,
                notes TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS opencellid_cells (
                radio TEXT,
                mcc TEXT NOT NULL,
                mnc TEXT NOT NULL,
                area TEXT,
                tac TEXT NOT NULL,
                cell_id TEXT NOT NULL,
                unit TEXT,
                lon REAL,
                lat REAL,
                range_m INTEGER,
                samples INTEGER,
                changeable INTEGER,
                created INTEGER,
                updated INTEGER,
                average_signal INTEGER,
                source_file TEXT,
                imported_at TEXT,
                PRIMARY KEY (mcc, mnc, tac, cell_id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS cellular_identity_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                profile_id INTEGER DEFAULT 1,
                router_id TEXT,
                router_name TEXT,
                net_device_id TEXT,
                sim_label TEXT,

                mcc TEXT,
                mnc TEXT,
                tac TEXT,
                cell_id TEXT,
                identity_key TEXT,

                service_type TEXT,
                rfband TEXT,
                rfband5g TEXT,
                rfchannel TEXT,
                ltebandwidth TEXT,
                mtu TEXT,

                first_seen_ts TEXT,
                last_seen_ts TEXT,
                last_sample_ts TEXT,
                sample_count INTEGER DEFAULT 0,

                is_current INTEGER DEFAULT 0,
                closed_at TEXT,

                match_status TEXT DEFAULT 'unmatched',
                match_updated_at TEXT,

                opencellid_mcc TEXT,
                opencellid_mnc TEXT,
                opencellid_tac TEXT,
                opencellid_cell_id TEXT,
                opencellid_lat REAL,
                opencellid_lon REAL,
                opencellid_range_m INTEGER,
                opencellid_samples INTEGER,
                opencellid_updated INTEGER,

                created_at TEXT,
                updated_at TEXT
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_opencellid_lookup
            ON opencellid_cells(mcc, mnc, tac, cell_id)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_opencellid_mcc_mnc
            ON opencellid_cells(mcc, mnc)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_cellular_identity_history_router_seen
            ON cellular_identity_history(profile_id, router_id, last_seen_ts)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_cellular_identity_history_net_device_current
            ON cellular_identity_history(net_device_id, is_current)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_cellular_identity_history_identity
            ON cellular_identity_history(mcc, mnc, tac, cell_id)
        """)

        # v5.1.0 RF quality aggregates for tower-history analysis.
        cellular_identity_history_rf_columns = {
            "last_dbm": "REAL",
            "min_dbm": "REAL",
            "max_dbm": "REAL",
            "avg_dbm": "REAL",
            "dbm_sample_count": "INTEGER DEFAULT 0",

            "last_rsrp": "REAL",
            "min_rsrp": "REAL",
            "max_rsrp": "REAL",
            "avg_rsrp": "REAL",
            "rsrp_sample_count": "INTEGER DEFAULT 0",

            "last_rsrq": "REAL",
            "min_rsrq": "REAL",
            "max_rsrq": "REAL",
            "avg_rsrq": "REAL",
            "rsrq_sample_count": "INTEGER DEFAULT 0",

            "last_sinr": "REAL",
            "min_sinr": "REAL",
            "max_sinr": "REAL",
            "avg_sinr": "REAL",
            "sinr_sample_count": "INTEGER DEFAULT 0",

            "last_signal_strength": "REAL",
            "min_signal_strength": "REAL",
            "max_signal_strength": "REAL",
            "avg_signal_strength": "REAL",
            "signal_strength_sample_count": "INTEGER DEFAULT 0",
        }

        for col_name, col_type in cellular_identity_history_rf_columns.items():
            try:
                conn.execute(f"ALTER TABLE cellular_identity_history ADD COLUMN {col_name} {col_type}")
            except sqlite3.OperationalError as exc:
                if "duplicate column name" not in str(exc).lower():
                    raise


        for table_name in ("net_device_metrics", "cellular_current_state"):
            for col_name, col_type in (
                ("rfband", "TEXT"),
                ("rfband5g", "TEXT"),
                ("rfchannel", "TEXT"),
                ("ltebandwidth", "TEXT"),
                ("mtu", "TEXT"),
            ):
                try:
                    conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}")
                except sqlite3.OperationalError:
                    pass

        for col_name, col_type in (
            ("old_rfband", "TEXT"),
            ("old_rfband5g", "TEXT"),
            ("old_rfchannel", "TEXT"),
            ("old_ltebandwidth", "TEXT"),
            ("old_mtu", "TEXT"),
            ("new_rfband", "TEXT"),
            ("new_rfband5g", "TEXT"),
            ("new_rfchannel", "TEXT"),
            ("new_ltebandwidth", "TEXT"),
            ("new_mtu", "TEXT"),
        ):
            try:
                conn.execute(f"ALTER TABLE cellular_events ADD COLUMN {col_name} {col_type}")
            except sqlite3.OperationalError:
                pass





def _opencellid_bool(value) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _opencellid_row_value(row: dict, *names):
    lowered = {str(k or "").strip().lower(): v for k, v in row.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


def _opencellid_text(value) -> str:
    value = _cellular_identity_value(value)
    return value


def _opencellid_int(value):
    value = _cellular_identity_value(value)
    if value == "":
        return None
    try:
        return int(float(value))
    except Exception:
        return None


def _opencellid_float(value):
    value = _cellular_identity_value(value)
    if value == "":
        return None
    try:
        return float(value)
    except Exception:
        return None


def _cleanup_opencellid_temp_file(text_stream=None, tmp_path=None):
    try:
        if text_stream is not None:
            text_stream.close()
    except Exception:
        pass

    try:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
    except Exception:
        pass


def _opencellid_import_summary(conn):
    latest = conn.execute("""
        SELECT *
        FROM opencellid_imports
        ORDER BY id DESC
        LIMIT 1
    """).fetchone()

    counts = conn.execute("""
        SELECT
            COUNT(*) AS total_cells,
            COUNT(DISTINCT mcc || '|' || mnc) AS networks,
            COUNT(DISTINCT mcc || '|' || mnc || '|' || tac) AS areas
        FROM opencellid_cells
    """).fetchone()

    history = conn.execute("""
        SELECT
            COUNT(*) AS history_rows,
            SUM(CASE WHEN match_status = 'exact' THEN 1 ELSE 0 END) AS exact_matches,
            SUM(CASE WHEN match_status = 'unmatched' THEN 1 ELSE 0 END) AS unmatched
        FROM cellular_identity_history
    """).fetchone()

    return {
        "cells": {
            "total": int(counts["total_cells"] or 0),
            "networks": int(counts["networks"] or 0),
            "areas": int(counts["areas"] or 0),
        },
        "history": {
            "rows": int(history["history_rows"] or 0),
            "exact_matches": int(history["exact_matches"] or 0),
            "unmatched": int(history["unmatched"] or 0),
        },
        "latest_import": dict(latest) if latest else None,
    }


def refresh_cellular_identity_history_matches(conn):
    """Refresh OpenCellID exact matches for existing cellular identity history rows."""
    conn.row_factory = sqlite3.Row

    rows = conn.execute("""
        SELECT id, mcc, mnc, tac, cell_id
        FROM cellular_identity_history
        WHERE COALESCE(TRIM(mcc), '') != ''
          AND COALESCE(TRIM(mnc), '') != ''
          AND COALESCE(TRIM(tac), '') != ''
          AND COALESCE(TRIM(cell_id), '') != ''
    """).fetchall()

    checked = 0
    exact = 0
    unmatched = 0
    now = now_utc()

    for row in rows:
        checked += 1
        match = lookup_opencellid_cell(conn, row["mcc"], row["mnc"], row["tac"], row["cell_id"])

        if match:
            exact += 1
            conn.execute("""
                UPDATE cellular_identity_history
                SET
                    match_status = 'exact',
                    match_updated_at = ?,
                    opencellid_mcc = ?,
                    opencellid_mnc = ?,
                    opencellid_tac = ?,
                    opencellid_cell_id = ?,
                    opencellid_lat = ?,
                    opencellid_lon = ?,
                    opencellid_range_m = ?,
                    opencellid_samples = ?,
                    opencellid_updated = ?,
                    updated_at = ?
                WHERE id = ?
            """, (
                now,
                match["mcc"],
                match["mnc"],
                match["tac"],
                match["cell_id"],
                match["lat"],
                match["lon"],
                match["range_m"],
                match["samples"],
                match["updated"],
                now,
                row["id"],
            ))
        else:
            unmatched += 1
            conn.execute("""
                UPDATE cellular_identity_history
                SET
                    match_status = 'unmatched',
                    match_updated_at = ?,
                    opencellid_mcc = NULL,
                    opencellid_mnc = NULL,
                    opencellid_tac = NULL,
                    opencellid_cell_id = NULL,
                    opencellid_lat = NULL,
                    opencellid_lon = NULL,
                    opencellid_range_m = NULL,
                    opencellid_samples = NULL,
                    opencellid_updated = NULL,
                    updated_at = ?
                WHERE id = ?
            """, (now, now, row["id"]))

    return {
        "checked": checked,
        "exact": exact,
        "unmatched": unmatched,
    }




def _tower_float(value):
    try:
        if value is None or value == "":
            return None
        return float(value)
    except Exception:
        return None


def _tower_int(value):
    try:
        if value is None or value == "":
            return None
        return int(value)
    except Exception:
        return None


def _tower_iso(value):
    if not value:
        return None
    return str(value)


def classify_tower_rf_quality(row):
    """
    RF quality for tower mapping.

    Preference order:
    1. SINR, using last_sinr then avg_sinr
    2. RSRP, using last_rsrp then avg_rsrp
    3. Unknown
    """
    sinr = _tower_float(row.get("last_sinr"))
    if sinr is None:
        sinr = _tower_float(row.get("avg_sinr"))

    rsrp = _tower_float(row.get("last_rsrp"))
    if rsrp is None:
        rsrp = _tower_float(row.get("avg_rsrp"))

    if sinr is not None:
        basis = "sinr"
        value = sinr
        if sinr >= 20:
            quality = "excellent"
            color = "#15803d"
        elif sinr >= 13:
            quality = "good"
            color = "#65a30d"
        elif sinr >= 5:
            quality = "fair"
            color = "#d97706"
        else:
            quality = "poor"
            color = "#dc2626"
        return {
            "quality": quality,
            "basis": basis,
            "value": value,
            "sinr": sinr,
            "rsrp": rsrp,
            "line_color": color,
        }

    if rsrp is not None:
        basis = "rsrp"
        value = rsrp
        if rsrp >= -90:
            quality = "excellent"
            color = "#15803d"
        elif rsrp >= -100:
            quality = "good"
            color = "#65a30d"
        elif rsrp >= -110:
            quality = "fair"
            color = "#d97706"
        else:
            quality = "poor"
            color = "#dc2626"
        return {
            "quality": quality,
            "basis": basis,
            "value": value,
            "sinr": sinr,
            "rsrp": rsrp,
            "line_color": color,
        }

    return {
        "quality": "unknown",
        "basis": "none",
        "value": None,
        "sinr": None,
        "rsrp": None,
        "line_color": "#64748b",
    }




def _tower_normalize_cell_id(value):
    """
    Normalize NCM cell IDs for tower API use.

    Examples:
    - "21590529 (0x1497201)" -> "21590529"
    - 21590529 -> "21590529"
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if " " in text:
        text = text.split(" ", 1)[0].strip()
    if "(" in text:
        text = text.split("(", 1)[0].strip()
    return text or None

def _tower_identity_key_from_row(row):
    """
    Build a stable, normalized tower key for summary/playback use.

    Do not rely on stored identity_key because older rows may contain
    raw NCM cell values like "21590529 (0x1497201)".
    """
    mcc = str(row.get("mcc") or "").strip()
    mnc = str(row.get("mnc") or "").strip()
    tac = str(row.get("tac") or "").strip()
    cell_id = _tower_normalize_cell_id(row.get("cell_id")) or str(row.get("cell_id") or "").strip()

    if mcc and mnc and tac and cell_id:
        return f"{mcc}|{mnc}|{tac}|{cell_id}"

    raw = row.get("identity_key")
    return str(raw).strip() if raw else None

def _tower_history_row_to_segment(row, router_location=None):
    row = dict(row)
    rf = classify_tower_rf_quality(row)

    tower_lat = _tower_float(row.get("opencellid_lat"))
    tower_lon = _tower_float(row.get("opencellid_lon"))
    has_tower_location = tower_lat is not None and tower_lon is not None and row.get("match_status") == "exact"
    has_router_location = bool((router_location or {}).get("found"))
    has_path = bool(has_router_location and has_tower_location)

    return {
        "id": row.get("id"),
        "router_id": str(row.get("router_id") or ""),
        "router_name": row.get("router_name"),
        "profile_id": _tower_int(row.get("profile_id")),
        "net_device_id": str(row.get("net_device_id") or "") if row.get("net_device_id") is not None else None,
        "sim_label": row.get("sim_label"),
        "identity": {
            "mcc": row.get("mcc"),
            "mnc": row.get("mnc"),
            "tac": row.get("tac"),
            "area": row.get("tac"),
            "area_label": "TAC" if str(row.get("service_type") or "").upper() in ("LTE", "5G NSA", "5G") else "Area",
            "cell_id": _tower_normalize_cell_id(row.get("cell_id")) or row.get("cell_id"),
            "identity_key": row.get("identity_key"),
            "tower_key": _tower_identity_key_from_row(row),
        },
        "radio": {
            "service_type": row.get("service_type"),
            "rfband": row.get("rfband"),
            "rfband5g": row.get("rfband5g"),
            "rfchannel": row.get("rfchannel"),
            "ltebandwidth": row.get("ltebandwidth"),
            "mtu": row.get("mtu"),
        },
        "window": {
            "first_seen_ts": _tower_iso(row.get("first_seen_ts")),
            "last_seen_ts": _tower_iso(row.get("last_seen_ts")),
            "last_sample_ts": _tower_iso(row.get("last_sample_ts")),
            "closed_at": _tower_iso(row.get("closed_at")),
            "is_current": bool(row.get("is_current")),
            "sample_count": _tower_int(row.get("sample_count")) or 0,
        },
        "match": {
            "status": row.get("match_status") or "unmatched",
            "updated_at": _tower_iso(row.get("match_updated_at")),
        },
        "tower": {
            "found": has_tower_location,
            "lat": tower_lat,
            "lon": tower_lon,
            "range_m": _tower_int(row.get("opencellid_range_m")),
            "samples": _tower_int(row.get("opencellid_samples")),
            "updated": _tower_int(row.get("opencellid_updated")),
            "mcc": row.get("opencellid_mcc"),
            "mnc": row.get("opencellid_mnc"),
            "tac": row.get("opencellid_tac"),
            "cell_id": row.get("opencellid_cell_id"),
        },
        "rf": {
            "quality": rf["quality"],
            "basis": rf["basis"],
            "value": rf["value"],
            "line_color": rf["line_color"],
            "last": {
                "dbm": _tower_float(row.get("last_dbm")),
                "rsrp": _tower_float(row.get("last_rsrp")),
                "rsrq": _tower_float(row.get("last_rsrq")),
                "sinr": _tower_float(row.get("last_sinr")),
                "signal_strength": _tower_float(row.get("last_signal_strength")),
            },
            "avg": {
                "dbm": _tower_float(row.get("avg_dbm")),
                "rsrp": _tower_float(row.get("avg_rsrp")),
                "rsrq": _tower_float(row.get("avg_rsrq")),
                "sinr": _tower_float(row.get("avg_sinr")),
                "signal_strength": _tower_float(row.get("avg_signal_strength")),
            },
            "sample_counts": {
                "dbm": _tower_int(row.get("dbm_sample_count")) or 0,
                "rsrp": _tower_int(row.get("rsrp_sample_count")) or 0,
                "rsrq": _tower_int(row.get("rsrq_sample_count")) or 0,
                "sinr": _tower_int(row.get("sinr_sample_count")) or 0,
                "signal_strength": _tower_int(row.get("signal_strength_sample_count")) or 0,
            },
        },
        "map": {
            "has_router_location": has_router_location,
            "has_tower_location": has_tower_location,
            "has_path": has_path,
            "line_color": rf["line_color"],
            "router_lat": (router_location or {}).get("lat"),
            "router_lon": (router_location or {}).get("lon"),
            "tower_lat": tower_lat,
            "tower_lon": tower_lon,
        },
    }


@app.get("/api/router/{router_id}/tower-history")
async def api_router_tower_history(
    router_id: str,
    profile_id: int = Query(1),
    hours: int = Query(168, ge=1, le=2160),
):
    profile_id = normalize_profile_id(profile_id)
    router_id = str(router_id).strip()
    if not router_id:
        raise HTTPException(status_code=400, detail="router_id is required")

    now_utc = datetime.now(timezone.utc)
    since_utc = now_utc - timedelta(hours=hours)
    since_iso = since_utc.isoformat()

    with db() as conn:
        conn.row_factory = sqlite3.Row

        loc = conn.execute("""
            SELECT router_id, latitude, longitude, accuracy, method, updated_at
            FROM locations
            WHERE router_id = ?
            LIMIT 1
        """, (router_id,)).fetchone()

        if loc:
            router_location = {
                "found": True,
                "router_id": str(loc["router_id"]),
                "lat": _tower_float(loc["latitude"]),
                "lon": _tower_float(loc["longitude"]),
                "accuracy": _tower_float(loc["accuracy"]),
                "method": loc["method"],
                "updated_at": loc["updated_at"],
                "updated_at_local": to_local_string(loc["updated_at"]),
                "source": "locations",
            }
        else:
            router_location = {
                "found": False,
                "router_id": router_id,
                "lat": None,
                "lon": None,
                "accuracy": None,
                "method": None,
                "updated_at": None,
                "updated_at_local": None,
                "source": "locations",
                "message": "No cached router location is available. Enable or refresh the Location module to draw router-to-tower paths.",
            }

        rows = conn.execute("""
            SELECT *
            FROM cellular_identity_history
            WHERE router_id = ?
              AND profile_id = ?
              AND (
                    is_current = 1
                    OR COALESCE(closed_at, last_seen_ts, updated_at, created_at) >= ?
                    OR COALESCE(first_seen_ts, created_at) >= ?
              )
            ORDER BY
                CASE WHEN is_current = 1 THEN 0 ELSE 1 END,
                COALESCE(last_seen_ts, updated_at, created_at) DESC
        """, (router_id, profile_id, since_iso, since_iso)).fetchall()

    history = [_tower_history_row_to_segment(row, router_location) for row in rows]
    current_segments = [item for item in history if item["window"]["is_current"]]
    current = current_segments[0] if current_segments else None

    quality_counts = {
        "excellent": 0,
        "good": 0,
        "fair": 0,
        "poor": 0,
        "unknown": 0,
    }
    unique_identity_keys = set()
    exact_matches = 0
    map_ready_segments = 0

    for item in history:
        q = item["rf"]["quality"] or "unknown"
        quality_counts[q] = quality_counts.get(q, 0) + 1

        key = item["identity"].get("tower_key") or item["identity"].get("identity_key")
        if key:
            unique_identity_keys.add(key)

        if item["match"]["status"] == "exact":
            exact_matches += 1

        if item["map"]["has_path"]:
            map_ready_segments += 1

    return {
        "ok": True,
        "router_id": router_id,
        "profile_id": profile_id,
        "hours": hours,
        "since_utc": since_iso,
        "until_utc": now_utc.isoformat(),
        "router_location": router_location,
        "current": current,
        "current_segments": current_segments,
        "history": history,
        "summary": {
            "segments": len(history),
            "current_segments": len(current_segments),
            "exact_matches": exact_matches,
            "unique_towers": len(unique_identity_keys),
            "map_ready_segments": map_ready_segments,
            "quality_counts": quality_counts,
            "has_router_location": router_location["found"],
            "has_current_tower": bool(current and current["tower"]["found"]),
            "has_current_path": bool(current and current["map"]["has_path"]),
        },
    }


@app.get("/api/opencellid/status")
async def api_opencellid_status():
    ensure_cellular_monitor_tables()

    with db() as conn:
        conn.row_factory = sqlite3.Row
        return _opencellid_import_summary(conn)


@app.post("/api/opencellid/import")
async def api_opencellid_import(
    file: UploadFile = File(...),
    replace_existing: str = Form("false"),
    rematch_history: str = Form("true"),
):
    """
    Import an OpenCellID CSV export.

    Supported common headers:
    - radio
    - mcc
    - net or mnc
    - area, lac, or tac
    - cell, cid, or cell_id
    - lon/lng/longitude
    - lat/latitude
    - range/range_m
    - samples
    - changeable
    - created
    - updated
    - averageSignal or average_signal
    """
    ensure_cellular_monitor_tables()

    source_file = Path(file.filename or "opencellid.csv").name
    imported_at = now_utc()
    replace_existing_bool = _opencellid_bool(replace_existing)
    rematch_history_bool = _opencellid_bool(rematch_history)

    with db() as conn:
        conn.row_factory = sqlite3.Row

        cur = conn.execute("""
            INSERT INTO opencellid_imports (
                source_file,
                imported_at,
                rows_seen,
                rows_inserted,
                rows_updated,
                rows_skipped,
                status,
                notes
            )
            VALUES (?, ?, 0, 0, 0, 0, 'running', ?)
        """, (
            source_file,
            imported_at,
            "OpenCellID CSV import started.",
        ))
        import_id = cur.lastrowid

        rows_seen = 0
        rows_inserted = 0
        rows_updated = 0
        rows_skipped = 0
        rematch_result = None
        text_stream = None
        tmp_path = None
        uploaded_bytes = 0

        try:
            if replace_existing_bool:
                conn.execute("DELETE FROM opencellid_cells")

            with tempfile.NamedTemporaryFile(mode="wb", delete=False, prefix="opencellid-", suffix=".csv") as tmp:
                tmp_path = tmp.name

                while True:
                    chunk = await file.read(1024 * 1024)
                    if not chunk:
                        break
                    uploaded_bytes += len(chunk)
                    tmp.write(chunk)

            if uploaded_bytes <= 0:
                raise HTTPException(status_code=400, detail="CSV file is empty.")

            text_stream = open(tmp_path, "r", encoding="utf-8-sig", errors="replace", newline="")
            reader = csv.DictReader(text_stream)

            if not reader.fieldnames:
                raise HTTPException(status_code=400, detail="CSV file has no header row.")

            for row in reader:
                rows_seen += 1

                radio = _opencellid_text(_opencellid_row_value(row, "radio"))
                mcc = _opencellid_text(_opencellid_row_value(row, "mcc"))
                mnc = _opencellid_text(_opencellid_row_value(row, "net", "mnc"))
                tac = _opencellid_text(_opencellid_row_value(row, "area", "lac", "tac"))
                cell_id = _opencellid_text(_opencellid_row_value(row, "cell", "cid", "cell_id"))

                if not all((mcc, mnc, tac, cell_id)):
                    rows_skipped += 1
                    continue

                unit = _opencellid_text(_opencellid_row_value(row, "unit"))
                lon = _opencellid_float(_opencellid_row_value(row, "lon", "lng", "longitude"))
                lat = _opencellid_float(_opencellid_row_value(row, "lat", "latitude"))
                range_m = _opencellid_int(_opencellid_row_value(row, "range", "range_m"))
                samples = _opencellid_int(_opencellid_row_value(row, "samples"))
                changeable = _opencellid_int(_opencellid_row_value(row, "changeable"))
                created = _opencellid_int(_opencellid_row_value(row, "created"))
                updated = _opencellid_int(_opencellid_row_value(row, "updated"))
                average_signal = _opencellid_int(_opencellid_row_value(row, "averageSignal", "average_signal"))

                existing = conn.execute("""
                    SELECT 1
                    FROM opencellid_cells
                    WHERE mcc = ?
                      AND mnc = ?
                      AND tac = ?
                      AND cell_id = ?
                    LIMIT 1
                """, (mcc, mnc, tac, cell_id)).fetchone()

                if existing:
                    rows_updated += 1
                else:
                    rows_inserted += 1

                conn.execute("""
                    INSERT INTO opencellid_cells (
                        radio,
                        mcc,
                        mnc,
                        area,
                        tac,
                        cell_id,
                        unit,
                        lon,
                        lat,
                        range_m,
                        samples,
                        changeable,
                        created,
                        updated,
                        average_signal,
                        source_file,
                        imported_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(mcc, mnc, tac, cell_id) DO UPDATE SET
                        radio = excluded.radio,
                        area = excluded.area,
                        unit = excluded.unit,
                        lon = excluded.lon,
                        lat = excluded.lat,
                        range_m = excluded.range_m,
                        samples = excluded.samples,
                        changeable = excluded.changeable,
                        created = excluded.created,
                        updated = excluded.updated,
                        average_signal = excluded.average_signal,
                        source_file = excluded.source_file,
                        imported_at = excluded.imported_at
                """, (
                    radio,
                    mcc,
                    mnc,
                    tac,
                    tac,
                    cell_id,
                    unit,
                    lon,
                    lat,
                    range_m,
                    samples,
                    changeable,
                    created,
                    updated,
                    average_signal,
                    source_file,
                    imported_at,
                ))

                if rows_seen % 1000 == 0:
                    conn.execute("""
                        UPDATE opencellid_imports
                        SET
                            rows_seen = ?,
                            rows_inserted = ?,
                            rows_updated = ?,
                            rows_skipped = ?,
                            notes = ?
                        WHERE id = ?
                    """, (
                        rows_seen,
                        rows_inserted,
                        rows_updated,
                        rows_skipped,
                        f"Import running. Last checkpoint at row {rows_seen}.",
                        import_id,
                    ))
                    conn.commit()

            _cleanup_opencellid_temp_file(text_stream, tmp_path)
            text_stream = None
            tmp_path = None

            if rematch_history_bool:
                rematch_result = refresh_cellular_identity_history_matches(conn)

            conn.execute("""
                UPDATE opencellid_imports
                SET
                    rows_seen = ?,
                    rows_inserted = ?,
                    rows_updated = ?,
                    rows_skipped = ?,
                    status = 'complete',
                    notes = ?
                WHERE id = ?
            """, (
                rows_seen,
                rows_inserted,
                rows_updated,
                rows_skipped,
                "Import complete.",
                import_id,
            ))

            conn.commit()

            summary = _opencellid_import_summary(conn)
            summary["import_result"] = {
                "import_id": import_id,
                "source_file": source_file,
                "rows_seen": rows_seen,
                "rows_inserted": rows_inserted,
                "rows_updated": rows_updated,
                "rows_skipped": rows_skipped,
                "replace_existing": replace_existing_bool,
                "rematch_history": rematch_history_bool,
                "rematch_result": rematch_result,
            }
            return summary

        except HTTPException:
            _cleanup_opencellid_temp_file(text_stream, tmp_path)

            conn.execute("""
                UPDATE opencellid_imports
                SET
                    rows_seen = ?,
                    rows_inserted = ?,
                    rows_updated = ?,
                    rows_skipped = ?,
                    status = 'failed',
                    notes = ?
                WHERE id = ?
            """, (
                rows_seen,
                rows_inserted,
                rows_updated,
                rows_skipped,
                "Import failed due to invalid CSV input.",
                import_id,
            ))
            conn.commit()
            raise
        except Exception as exc:
            _cleanup_opencellid_temp_file(text_stream, tmp_path)

            conn.execute("""
                UPDATE opencellid_imports
                SET
                    rows_seen = ?,
                    rows_inserted = ?,
                    rows_updated = ?,
                    rows_skipped = ?,
                    status = 'failed',
                    notes = ?
                WHERE id = ?
            """, (
                rows_seen,
                rows_inserted,
                rows_updated,
                rows_skipped,
                f"Import failed: {exc}",
                import_id,
            ))
            conn.commit()
            raise HTTPException(status_code=500, detail=f"OpenCellID import failed: {exc}")





@app.get("/opencellid-admin", response_class=HTMLResponse)
async def opencellid_admin_page():
    return HTMLResponse("""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>OpenCellID Admin</title>
  <style>
    body {
      margin: 0;
      font-family: Inter, Arial, sans-serif;
      background: #0f172a;
      color: #e5e7eb;
    }
    .wrap {
      max-width: 1180px;
      margin: 0 auto;
      padding: 28px;
    }
    .topbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      margin-bottom: 22px;
    }
    .title {
      font-size: 28px;
      font-weight: 900;
      margin: 0;
    }
    .sub {
      color: #94a3b8;
      margin-top: 6px;
      line-height: 1.45;
    }
    a {
      color: #93c5fd;
      text-decoration: none;
      font-weight: 700;
    }
    a:hover {
      text-decoration: underline;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 14px;
      margin: 18px 0;
    }
    .card {
      background: rgba(15, 23, 42, .92);
      border: 1px solid rgba(148, 163, 184, .25);
      border-radius: 18px;
      box-shadow: 0 18px 45px rgba(0, 0, 0, .28);
      padding: 18px;
    }
    .metric-label {
      color: #94a3b8;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .08em;
      font-weight: 800;
    }
    .metric-value {
      font-size: 30px;
      font-weight: 900;
      margin-top: 8px;
    }
    .section-title {
      font-size: 18px;
      font-weight: 900;
      margin: 0 0 12px;
    }
    .row {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
      margin: 10px 0;
    }
    input[type="file"] {
      background: #111827;
      border: 1px solid rgba(148, 163, 184, .35);
      color: #e5e7eb;
      border-radius: 12px;
      padding: 10px;
      min-width: 360px;
    }
    label {
      color: #cbd5e1;
      font-weight: 700;
    }
    button {
      border: 0;
      background: linear-gradient(135deg, #2563eb, #1d4ed8);
      color: white;
      border-radius: 12px;
      padding: 11px 15px;
      font-weight: 900;
      cursor: pointer;
      box-shadow: 0 12px 28px rgba(37, 99, 235, .28);
    }
    button:disabled {
      opacity: .55;
      cursor: wait;
    }
    .danger {
      background: linear-gradient(135deg, #dc2626, #991b1b);
    }
    .muted {
      color: #94a3b8;
      font-size: 13px;
      line-height: 1.45;
    }
    .warn {
      background: rgba(245, 158, 11, .12);
      border: 1px solid rgba(245, 158, 11, .35);
      color: #fde68a;
      border-radius: 14px;
      padding: 12px 14px;
      margin-top: 12px;
      line-height: 1.45;
    }
    .ok {
      background: rgba(34, 197, 94, .12);
      border: 1px solid rgba(34, 197, 94, .35);
      color: #bbf7d0;
      border-radius: 14px;
      padding: 12px 14px;
      margin-top: 12px;
      line-height: 1.45;
    }
    .err {
      background: rgba(239, 68, 68, .12);
      border: 1px solid rgba(239, 68, 68, .35);
      color: #fecaca;
      border-radius: 14px;
      padding: 12px 14px;
      margin-top: 12px;
      line-height: 1.45;
      white-space: pre-wrap;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
      overflow: hidden;
      border-radius: 14px;
    }
    th, td {
      border-bottom: 1px solid rgba(148, 163, 184, .18);
      text-align: left;
      padding: 10px;
      font-size: 13px;
    }
    th {
      color: #cbd5e1;
      background: rgba(30, 41, 59, .72);
      text-transform: uppercase;
      letter-spacing: .06em;
      font-size: 11px;
    }
    td {
      color: #e5e7eb;
    }
    pre {
      background: #020617;
      border: 1px solid rgba(148, 163, 184, .22);
      border-radius: 14px;
      padding: 12px;
      overflow: auto;
      max-height: 360px;
      color: #c4b5fd;
    }
    @media (max-width: 900px) {
      .grid { grid-template-columns: 1fr; }
      input[type="file"] { min-width: 0; width: 100%; }
      .topbar { align-items: flex-start; flex-direction: column; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div>
        <h1 class="title">OpenCellID Admin</h1>
        <div class="sub">
          Import OpenCellID CSV data and refresh exact matches for cellular identity history.
        </div>
      </div>
      <div class="row">
        <a href="/launcher">Launcher</a>
        <a href="/ui">Dashboard</a>
        <a href="/monitoring-targets-ui">Router Overview</a>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <div class="metric-label">Imported Cells</div>
        <div class="metric-value" id="cellTotal">...</div>
        <div class="muted"><span id="networkTotal">...</span> networks, <span id="areaTotal">...</span> areas</div>
      </div>
      <div class="card">
        <div class="metric-label">Identity History Rows</div>
        <div class="metric-value" id="historyRows">...</div>
        <div class="muted">Current and closed cellular identities</div>
      </div>
      <div class="card">
        <div class="metric-label">Exact Matches</div>
        <div class="metric-value" id="exactMatches">...</div>
        <div class="muted"><span id="unmatchedTotal">...</span> unmatched</div>
      </div>
    </div>

    <div class="card">
      <h2 class="section-title">Import OpenCellID CSV</h2>
      <div class="muted">
        Use the CSV file from the OpenCellID dataset download. Large imports may take a while. Leave this page open until the import completes.
      </div>

      <div class="warn">
        Recommended for full USA datasets: import one CSV at a time. The backend now streams uploads through temporary files, but browser uploads can still take time depending on file size and server resources.
      </div>

      <form id="importForm">
        <div class="row">
          <input id="csvFile" name="file" type="file" accept=".csv,text/csv" required>
        </div>

        <div class="row">
          <label>
            <input id="replaceExisting" type="checkbox">
            Replace existing OpenCellID cells before import
          </label>
        </div>

        <div class="row">
          <label>
            <input id="rematchHistory" type="checkbox" checked>
            Rematch cellular identity history after import
          </label>
        </div>

        <div class="row">
          <button id="importBtn" type="submit">Import CSV</button>
          <button type="button" onclick="loadStatus()">Refresh Status</button>
        </div>
      </form>

      <div id="importMessage"></div>
    </div>

    <div class="card" style="margin-top:14px;">
      <h2 class="section-title">Latest Import</h2>
      <div id="latestImport"></div>
    </div>

    <div class="card" style="margin-top:14px;">
      <h2 class="section-title">Raw Status</h2>
      <pre id="rawStatus">Loading...</pre>
    </div>
  </div>

<script>
function fmt(value) {
  if (value === null || value === undefined) return "0";
  const n = Number(value);
  if (!Number.isFinite(n)) return String(value);
  return n.toLocaleString();
}

function latestImportHtml(latest) {
  if (!latest) {
    return '<div class="muted">No imports recorded yet.</div>';
  }

  return `
    <table>
      <tr><th>ID</th><td>${latest.id ?? ''}</td></tr>
      <tr><th>Source File</th><td>${latest.source_file ?? ''}</td></tr>
      <tr><th>Imported At</th><td>${latest.imported_at ?? ''}</td></tr>
      <tr><th>Rows Seen</th><td>${fmt(latest.rows_seen)}</td></tr>
      <tr><th>Inserted</th><td>${fmt(latest.rows_inserted)}</td></tr>
      <tr><th>Updated</th><td>${fmt(latest.rows_updated)}</td></tr>
      <tr><th>Skipped</th><td>${fmt(latest.rows_skipped)}</td></tr>
      <tr><th>Status</th><td>${latest.status ?? ''}</td></tr>
      <tr><th>Notes</th><td>${latest.notes ?? ''}</td></tr>
    </table>
  `;
}

async function loadStatus() {
  const raw = document.getElementById('rawStatus');
  raw.textContent = 'Loading...';

  try {
    const res = await fetch('/api/opencellid/status', { credentials: 'same-origin' });
    const text = await res.text();

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${text}`);
    }

    const data = JSON.parse(text);

    document.getElementById('cellTotal').textContent = fmt(data.cells?.total);
    document.getElementById('networkTotal').textContent = fmt(data.cells?.networks);
    document.getElementById('areaTotal').textContent = fmt(data.cells?.areas);
    document.getElementById('historyRows').textContent = fmt(data.history?.rows);
    document.getElementById('exactMatches').textContent = fmt(data.history?.exact_matches);
    document.getElementById('unmatchedTotal').textContent = fmt(data.history?.unmatched);
    document.getElementById('latestImport').innerHTML = latestImportHtml(data.latest_import);

    raw.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    raw.textContent = String(err);
    document.getElementById('latestImport').innerHTML = `<div class="err">${String(err)}</div>`;
  }
}

document.getElementById('importForm').addEventListener('submit', async (event) => {
  event.preventDefault();

  const fileInput = document.getElementById('csvFile');
  const btn = document.getElementById('importBtn');
  const msg = document.getElementById('importMessage');

  if (!fileInput.files || fileInput.files.length === 0) {
    msg.innerHTML = '<div class="err">Choose a CSV file first.</div>';
    return;
  }

  const fd = new FormData();
  fd.append('file', fileInput.files[0]);
  fd.append('replace_existing', document.getElementById('replaceExisting').checked ? 'true' : 'false');
  fd.append('rematch_history', document.getElementById('rematchHistory').checked ? 'true' : 'false');

  btn.disabled = true;
  btn.textContent = 'Importing...';
  msg.innerHTML = '<div class="warn">Import running. Leave this page open. Large datasets can take a while.</div>';

  try {
    const res = await fetch('/api/opencellid/import', {
      method: 'POST',
      body: fd,
      credentials: 'same-origin'
    });

    const text = await res.text();

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${text}`);
    }

    const data = JSON.parse(text);
    const result = data.import_result || {};

    msg.innerHTML = `
      <div class="ok">
        Import complete.<br>
        Rows seen: ${fmt(result.rows_seen)}<br>
        Inserted: ${fmt(result.rows_inserted)}<br>
        Updated: ${fmt(result.rows_updated)}<br>
        Skipped: ${fmt(result.rows_skipped)}
      </div>
    `;

    await loadStatus();
  } catch (err) {
    msg.innerHTML = `<div class="err">${String(err)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Import CSV';
  }
});

loadStatus();
</script>
</body>
</html>
    """)



def platform_from_bucket(bucket):
    b = (bucket or "").upper()
    # Bucket-based fallback: No SDK2 population is S400; E100 Swaps are E100.
    if "S400" in b or "NO SDK2" in b:
        return {"label": "S400", "image_url": "/static/images/S400.webp"}
    if "E100" in b:
        return {"label": "E100", "image_url": "/static/images/E100.webp"}
    return {"label": "Unknown", "image_url": None}


def init_db():
    os.makedirs(f"{BASE_DIR}/data", exist_ok=True)

    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS routers (
                profile_id INTEGER NOT NULL DEFAULT 1,
                router_id TEXT NOT NULL,
                bucket TEXT,
                last_seen_utc TEXT,
                product_name TEXT,
                router_model TEXT,
                router_image_path TEXT,
                polling_paused INTEGER NOT NULL DEFAULT 0,
                pause_reason TEXT,
                paused_at TEXT,
                PRIMARY KEY(profile_id, router_id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS net_devices (
                id TEXT PRIMARY KEY,
                router_id TEXT,
                sim_label TEXT,
                carrier TEXT,
                connection_state TEXT,
                service_type TEXT,
                mfg_product TEXT,
                updated_at TEXT,
                uptime REAL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                created_at_timeuuid TEXT PRIMARY KEY,
                router_id TEXT,
                type TEXT,
                friendly_info TEXT,
                detected_at TEXT,
                created_at TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS locations (
                router_id TEXT PRIMARY KEY,
                latitude REAL,
                longitude REAL,
                accuracy REAL,
                method TEXT,
                updated_at TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS location_labels (
                router_id TEXT PRIMARY KEY,
                latitude REAL,
                longitude REAL,
                city TEXT,
                state TEXT,
                label TEXT,
                updated_at TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS signal_samples (
                created_at_timeuuid TEXT PRIMARY KEY,
                router_id TEXT,
                net_device_id TEXT,
                sim_label TEXT,
                created_at TEXT,
                dbm REAL,
                rsrp REAL,
                rsrq REAL,
                sinr REAL,
                signal_percent REAL,
                uptime REAL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS usage_samples (
                id TEXT PRIMARY KEY,
                router_id TEXT,
                net_device_id TEXT,
                sim_label TEXT,
                created_at TEXT,
                bytes_in REAL,
                bytes_out REAL,
                total_bytes REAL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS router_stream_usage_samples (
                created_at_timeuuid TEXT PRIMARY KEY,
                router_id TEXT,
                created_at TEXT,
                bytes_in REAL,
                bytes_out REAL,
                total_bytes REAL,
                period REAL,
                uptime REAL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS router_logs (
                profile_id INTEGER NOT NULL DEFAULT 1,
                log_key TEXT NOT NULL,
                router_id TEXT NOT NULL,
                reported_at TEXT,
                created_at TEXT,
                level TEXT,
                source TEXT,
                message TEXT,
                exception TEXT,
                sequence TEXT,
                created_at_timeuuid TEXT,
                fetched_at TEXT,
                PRIMARY KEY(profile_id, router_id, log_key)
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_router_logs_lookup
            ON router_logs(profile_id, router_id, COALESCE(reported_at, created_at))
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS router_state_samples (
                created_at_timeuuid TEXT PRIMARY KEY,
                router_id TEXT,
                created_at TEXT,
                state TEXT,
                period REAL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS net_device_metrics (
                net_device_id TEXT PRIMARY KEY,
                router_id TEXT,
                mcc TEXT,
                mnc TEXT,
                tac TEXT,
                cell_id TEXT,
                service_type TEXT,
                dbm REAL,
                rsrp REAL,
                rsrq REAL,
                sinr REAL,
                signal_strength REAL,
                rfband TEXT,
                rfband5g TEXT,
                rfchannel TEXT,
                ltebandwidth TEXT,
                mtu TEXT,
                update_ts TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS issues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id TEXT NOT NULL,
                issue_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                summary TEXT,
                first_seen TEXT,
                last_seen TEXT,
                resolved_at TEXT,
                resolution_note TEXT,
                UNIQUE(router_id, issue_type, status)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS issue_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id TEXT NOT NULL,
                issue_id INTEGER,
                comment TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS general_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS poll_state (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS monitoring_pools (
                profile_id INTEGER NOT NULL DEFAULT 1,
                name TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                polling_paused INTEGER NOT NULL DEFAULT 0,
                pause_reason TEXT,
                paused_at TEXT,
                PRIMARY KEY(profile_id, name)
            )
        """)

        # v5 monitoring target/module schema.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS monitoring_targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id INTEGER NOT NULL,
                router_id TEXT NOT NULL,
                pool_id INTEGER,
                display_name TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT,
                updated_at TEXT,
                UNIQUE(profile_id, router_id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS monitoring_target_modules (
                profile_id INTEGER NOT NULL,
                router_id TEXT NOT NULL,
                module_name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                interval_minutes INTEGER,
                mode TEXT NOT NULL DEFAULT 'disabled',
                last_polled_at TEXT,
                next_poll_after TEXT,
                updated_at TEXT,
                PRIMARY KEY (profile_id, router_id, module_name)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS monitoring_pool_modules (
                profile_id INTEGER NOT NULL,
                pool_id INTEGER NOT NULL,
                module_name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                interval_minutes INTEGER,
                mode TEXT NOT NULL DEFAULT 'disabled',
                updated_at TEXT,
                PRIMARY KEY (profile_id, pool_id, module_name)
            )
        """)

        # Lightweight migrations for existing Pi databases.
        try:
            conn.execute("ALTER TABLE net_devices ADD COLUMN uptime REAL")
        except sqlite3.OperationalError:
            pass


def seed_default_pools():
    """Stock build: do not seed customer-specific legacy monitoring pools.

    Pools should be created by the user from Pool Administration or created
    automatically during router import/add workflows.
    """
    return


def get_default_profile_id_for_schema():
    """Return the current default dashboard/profile id without relying on profile names."""
    try:
        with global_db() as conn:
            row = conn.execute(
                "SELECT id FROM dashboard_profiles WHERE is_default = 1 ORDER BY id LIMIT 1"
            ).fetchone()
            if row and row[0] is not None:
                return int(row[0])

            row = conn.execute(
                "SELECT id FROM dashboard_profiles ORDER BY id LIMIT 1"
            ).fetchone()
            if row and row[0] is not None:
                return int(row[0])
    except Exception:
        pass
    return 1


def ensure_app_profile_schema():
    """Idempotent app DB migrations for dashboard/profile-scoped data.

    This intentionally does not rely on dashboard names, customer-specific IDs,
    API credentials, or seeded data. It is safe for fresh installs and upgrades.
    """
    default_profile_id = get_default_profile_id_for_schema()

    with db() as conn:
        def table_exists(table):
            return conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone() is not None

        def cols(table):
            if not table_exists(table):
                return []
            return [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]

        def add_col(table, column, ddl):
            if table_exists(table) and column not in cols(table):
                conn.execute(ddl)

        # monitoring_pools was legacy-created as name TEXT PRIMARY KEY.
        # Add profile/pause fields for existing DBs and create a unique index
        # required by ON CONFLICT(profile_id, name).
        if table_exists("monitoring_pools"):
            add_col("monitoring_pools", "profile_id", "ALTER TABLE monitoring_pools ADD COLUMN profile_id INTEGER")
            conn.execute(
                "UPDATE monitoring_pools SET profile_id = ? WHERE profile_id IS NULL",
                (default_profile_id,),
            )
            add_col("monitoring_pools", "polling_paused", "ALTER TABLE monitoring_pools ADD COLUMN polling_paused INTEGER NOT NULL DEFAULT 0")
            add_col("monitoring_pools", "pause_reason", "ALTER TABLE monitoring_pools ADD COLUMN pause_reason TEXT")
            add_col("monitoring_pools", "paused_at", "ALTER TABLE monitoring_pools ADD COLUMN paused_at TEXT")
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_monitoring_pools_profile_name ON monitoring_pools(profile_id, name)"
            )

        # routers and related app tables need profile_id for profile-scoped UI/API paths.
        if table_exists("routers"):
            add_col("routers", "profile_id", "ALTER TABLE routers ADD COLUMN profile_id INTEGER")
            conn.execute(
                "UPDATE routers SET profile_id = ? WHERE profile_id IS NULL",
                (default_profile_id,),
            )
            add_col("routers", "product_name", "ALTER TABLE routers ADD COLUMN product_name TEXT")
            add_col("routers", "router_model", "ALTER TABLE routers ADD COLUMN router_model TEXT")
            add_col("routers", "router_image_path", "ALTER TABLE routers ADD COLUMN router_image_path TEXT")
            add_col("routers", "polling_paused", "ALTER TABLE routers ADD COLUMN polling_paused INTEGER NOT NULL DEFAULT 0")
            add_col("routers", "pause_reason", "ALTER TABLE routers ADD COLUMN pause_reason TEXT")
            add_col("routers", "paused_at", "ALTER TABLE routers ADD COLUMN paused_at TEXT")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_routers_profile_id ON routers(profile_id)"
            )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_routers_profile_router_id ON routers(profile_id, router_id)"
            )

        if table_exists("api_call_counter"):
            add_col("api_call_counter", "profile_id", "ALTER TABLE api_call_counter ADD COLUMN profile_id INTEGER")
            conn.execute(
                "UPDATE api_call_counter SET profile_id = ? WHERE profile_id IS NULL",
                (default_profile_id,),
            )


def ensure_stock_setup_tables():
    os.makedirs(f"{BASE_DIR}/data", exist_ok=True)
    os.makedirs(GLOBAL_DB_PATH.rsplit("/", 1)[0], exist_ok=True)
    os.makedirs(DASHBOARD_DB_DIR, exist_ok=True)
    os.makedirs(ROUTER_LIST_DIR, exist_ok=True)

    ts = now_utc()
    with global_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                job_title TEXT,
                organization TEXT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS setup_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                detail TEXT,
                created_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS dashboard_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                base_url TEXT,
                api_id TEXT,
                api_key TEXT,
                cp_api_id TEXT,
                cp_api_key TEXT,
                is_default INTEGER NOT NULL DEFAULT 0,
                polling_paused INTEGER NOT NULL DEFAULT 0,
                pause_reason TEXT,
                paused_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        existing = conn.execute("SELECT id FROM dashboard_profiles LIMIT 1").fetchone()
        if not existing:
            conn.execute("""
                INSERT INTO dashboard_profiles
                (name, description, base_url, is_default, created_at, updated_at)
                VALUES (?, ?, ?, 1, ?, ?)
            """, (
                "Default Dashboard",
                "Primary NCM Monitor dashboard profile.",
                NCM_BASE_URL,
                ts,
                ts,
            ))

        conn.commit()


def get_app_setting(key, default=None):
    try:
        with global_db() as conn:
            row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
            return row[0] if row else default
    except Exception:
        return default


def set_app_setting(key, value):
    with global_db() as conn:
        conn.execute("""
            INSERT INTO app_settings(key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
        """, (key, str(value), now_utc()))
        conn.commit()


def users_exist():
    try:
        with global_db() as conn:
            row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
            return bool(row and row[0] > 0)
    except Exception:
        return False


def setup_complete():
    return get_app_setting("setup_complete", "0") == "1" and users_exist()


def setup_resume_url(request: Request = None):
    """
    First-run setup is staged:
    - no users yet: create admin account at /setup
    - user exists but setup is incomplete:
        - if already logged in, continue NCM API setup at /api-setup
        - if not logged in, show /login so the admin can authenticate first
    - setup complete: normal app flow
    """
    if not users_exist():
        return "/setup"

    if not setup_complete():
        if request is not None and current_user(request):
            return "/api-setup"
        return "/login"

    return None


def current_user(request: Request):
    user_id = request.session.get("user_id")
    if not user_id:
        return None

    try:
        with global_db() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("""
                SELECT id, name, job_title, organization, username, role
                FROM users
                WHERE id = ?
            """, (user_id,)).fetchone()
            return dict(row) if row else None
    except Exception:
        return None


def login_required(request: Request):
    return current_user(request) is not None


def stock_page(title, body):
    return f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{title}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {{
      margin: 0;
      font-family: Inter, Arial, sans-serif;
      background: radial-gradient(circle at top left, #1f4f75 0, #0b1720 42%, #071018 100%);
      color: #e8f1f7;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 32px;
    }}
    .card {{
      width: min(860px, 100%);
      background: rgba(10, 22, 31, 0.92);
      border: 1px solid rgba(255,255,255,0.14);
      border-radius: 22px;
      box-shadow: 0 24px 80px rgba(0,0,0,0.35);
      padding: 34px;
    }}
    h1 {{
      margin: 0 0 8px 0;
      font-size: 34px;
      letter-spacing: -0.03em;
    }}
    h2 {{
      margin-top: 26px;
      font-size: 18px;
      color: #b8d5e8;
    }}
    p {{
      color: #b8c8d3;
      line-height: 1.55;
    }}
    label {{
      display: block;
      margin-top: 16px;
      font-size: 13px;
      color: #b8d5e8;
      font-weight: 700;
    }}
    input, textarea {{
      box-sizing: border-box;
      width: 100%;
      margin-top: 6px;
      padding: 12px 13px;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,0.16);
      background: rgba(255,255,255,0.06);
      color: #fff;
      font-size: 15px;
    }}
    input[type=checkbox] {{
      width: auto;
      margin-right: 8px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
    }}
    .notice {{
      margin-top: 22px;
      padding: 16px;
      border-radius: 14px;
      background: rgba(255, 193, 7, 0.12);
      border: 1px solid rgba(255, 193, 7, 0.28);
      color: #f4ddb3;
    }}
    .error {{
      margin-top: 18px;
      padding: 13px;
      border-radius: 12px;
      background: rgba(255, 80, 80, 0.14);
      border: 1px solid rgba(255, 80, 80, 0.28);
      color: #ffd0d0;
    }}
    button {{
      margin-top: 24px;
      border: 0;
      border-radius: 999px;
      padding: 13px 22px;
      font-weight: 800;
      color: #071018;
      background: #71d6ff;
      cursor: pointer;
      font-size: 15px;
    }}
    a {{
      color: #71d6ff;
      text-decoration: none;
    }}
    .muted {{
      color: #8ca7b7;
      font-size: 13px;
    }}
    @media (max-width: 720px) {{
      .grid {{ grid-template-columns: 1fr; }}
      body {{ padding: 16px; }}
      .card {{ padding: 24px; }}
    }}
  


</style>
</head>
<body>
  <div class="card">
    {body}
  </div>
</body>
</html>
"""





def hash_password(password: str) -> str:
    """Hash a local admin password using PBKDF2-SHA256.

    Format:
      pbkdf2_sha256$iterations$salt$hash
    """
    iterations = 260000
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        str(password).encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    )
    return f"pbkdf2_sha256${iterations}${salt}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a local admin password.

    Supports the stock PBKDF2-SHA256 format. Returns False for unknown/legacy
    hashes instead of throwing a 500.
    """
    try:
        if not stored_hash:
            return False

        parts = str(stored_hash).split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False

        _, iterations_s, salt, expected_hex = parts
        iterations = int(iterations_s)

        dk = hashlib.pbkdf2_hmac(
            "sha256",
            str(password).encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        )
        return secrets.compare_digest(dk.hex(), expected_hex)
    except Exception:
        return False


def current_user_from_cookie(request: Request):
    """Read Starlette SessionMiddleware cookie without requiring request.session.

    This is used only inside the custom middleware gate because that gate can run
    before SessionMiddleware has attached request.session.
    """
    raw_cookie = request.cookies.get("session")
    if not raw_cookie:
        return None

    try:
        signer = TimestampSigner(get_or_create_app_secret())
        data = signer.unsign(raw_cookie, max_age=14 * 24 * 60 * 60)
        session_data = json.loads(base64.b64decode(data))
        user_id = session_data.get("user_id")
    except Exception:
        return None

    if not user_id:
        return None

    try:
        with global_db() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("""
                SELECT id, name, job_title, organization, username, role
                FROM users
                WHERE id = ?
            """, (user_id,)).fetchone()
            return dict(row) if row else None
    except Exception:
        return None


def login_cookie_present(request: Request):
    return current_user_from_cookie(request) is not None



def _event_context_router_logs_retention_note() -> str:
    return "NCM router logs generally retain about 60 days of history."

def _normalize_event_context_window_for_daily_dot(start_dt, end_dt, anchor_dt=None, selected_day_dt=None, is_daily_bucket=False):
    """
    For daily graph dots, use the selected local day:
      selected day 00:00 local -> selected day 23:59:59 local
      if selected day is today, end = current local time

    Also guarantees callers never proceed with start >= end.
    """
    from datetime import datetime, time, timedelta

    if is_daily_bucket and selected_day_dt is not None:
        day = selected_day_dt.date()
        tz = selected_day_dt.tzinfo

        start_dt = datetime.combine(day, time(0, 0, 0), tzinfo=tz)
        proposed_end = datetime.combine(day, time(23, 59, 59), tzinfo=tz)

        now_local = datetime.now(tz) if tz else datetime.now()
        if day == now_local.date():
            end_dt = now_local
        else:
            end_dt = proposed_end

    if start_dt and end_dt and start_dt >= end_dt:
        return start_dt, end_dt, False, "Invalid log window: start time is greater than or equal to end time. NCM log lookup was skipped."

    return start_dt, end_dt, True, None


@app.middleware("http")
async def stock_setup_and_login_gate(request: Request, call_next):
    path = request.url.path

    allowed_prefixes = (
        "/static",
        "/setup",
        "/api-setup",
        "/login",
        "/logout",
        "/health",
        "/favicon.ico",
    )

    if path.startswith(allowed_prefixes):
        return await call_next(request)

    resume_url = setup_resume_url(request)
    if resume_url:
        return RedirectResponse(url=resume_url, status_code=303)

    if not login_cookie_present(request):
        return RedirectResponse(url="/login", status_code=303)

    return await call_next(request)


@app.get("/setup", response_class=HTMLResponse)
async def setup_get(request: Request):
    ensure_stock_setup_tables()

    if setup_complete():
        return RedirectResponse(url="/login", status_code=303)

    if users_exist():
        return RedirectResponse(url=setup_resume_url(request), status_code=303)

    body = """
    <h1>NCM Monitor</h1>
    <p><strong>Operational Intelligence for NetCloud Manager</strong></p>
    <p>
      This setup wizard will create a local administrator account for this NCM Monitor instance.
      After that, you will connect the tool to NetCloud Manager using your authorized API credentials.
    </p>

    <form method="post" action="/setup">
      <div class="grid">
        <div>
          <label>Your name</label>
          <input name="name" required autocomplete="name">
        </div>
        <div>
          <label>Job title</label>
          <input name="job_title" autocomplete="organization-title">
        </div>
      </div>

      <label>Organization / team</label>
      <input name="organization">

      <div class="grid">
        <div>
          <label>Admin username</label>
          <input name="username" required autocomplete="username">
        </div>
        <div>
          <label>Admin password</label>
          <input name="password" type="password" required autocomplete="new-password">
          <p class="muted" style="margin-top:6px;">
            Password must be at least 8 characters. Use something unique to this local NCM Monitor instance.
          </p>
        </div>
      </div>

      <label>Confirm password</label>
      <input name="confirm_password" type="password" required autocomplete="new-password">
      <p class="muted" style="margin-top:6px;">
        Re-enter the same password to confirm the local administrator account.
      </p>

      <div class="notice">
        <label>
          <input type="checkbox" name="accepted_use" value="yes" required>
          I understand that this tool uses the NetCloud Manager API credentials I provide and may consume API calls against the selected customer/account. I confirm that I am authorized to access the accounts, routers, telemetry, and reports configured in this tool.
        </label>
      </div>

      <button type="submit">Create admin account</button>
    </form>
    """
    return HTMLResponse(stock_page("NCM Monitor Setup", body))


@app.post("/setup", response_class=HTMLResponse)
async def setup_post(
    request: Request,
    name: str = Form(...),
    job_title: str = Form(""),
    organization: str = Form(""),
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    accepted_use: str = Form(None),
):
    ensure_stock_setup_tables()

    if users_exist():
        return RedirectResponse(url=setup_resume_url(request), status_code=303)

    if password != confirm_password:
        return HTMLResponse(stock_page("Setup error", "<h1>Setup error</h1><div class='error'>Passwords do not match.</div><p><a href='/setup'>Go back</a></p>"), status_code=400)

    if len(password) < 8:
        return HTMLResponse(stock_page("Setup error", "<h1>Setup error</h1><div class='error'>Password must be at least 8 characters.</div><p><a href='/setup'>Go back</a></p>"), status_code=400)

    if accepted_use != "yes":
        return HTMLResponse(stock_page("Setup error", "<h1>Setup error</h1><div class='error'>You must accept the usage acknowledgement to continue.</div><p><a href='/setup'>Go back</a></p>"), status_code=400)

    ts = now_utc()
    password_hash = hash_password(password)

    with global_db() as conn:
        cur = conn.execute("""
            INSERT INTO users(name, job_title, organization, username, password_hash, role, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'admin', ?, ?)
        """, (name.strip(), job_title.strip(), organization.strip(), username.strip(), password_hash, ts, ts))

        user_id = cur.lastrowid

        conn.execute("""
            INSERT INTO app_settings(key, value, updated_at)
            VALUES ('acceptable_use_accepted', '1', ?)
            ON CONFLICT(key) DO UPDATE SET value = '1', updated_at = excluded.updated_at
        """, (ts,))

        conn.execute("""
            INSERT INTO setup_audit(event_type, detail, created_at)
            VALUES ('admin_created', ?, ?)
        """, (username.strip(), ts))

        conn.commit()

    request.session["user_id"] = user_id
    request.session["username"] = username.strip()

    return RedirectResponse(url="/api-setup", status_code=303)


@app.get("/api-setup", response_class=HTMLResponse)
async def api_setup_get(request: Request):
    ensure_stock_setup_tables()

    if not current_user(request):
        return RedirectResponse(url="/login", status_code=303)

    body = """
    <h1>Connect NetCloud Manager</h1>
    <p>
      Add the NCM API credentials for the customer/account you want this dashboard to monitor.
      These credentials are stored locally on this server and are used only by this NCM Monitor instance.
    </p>

    <form method="post" action="/api-setup" enctype="multipart/form-data">
      <label>Dashboard / profile name</label>
      <input name="profile_name" placeholder="Example: Customer Name, Lab, Production Fleet" required>

      <label>NCM base URL</label>
      <input name="base_url" value="https://www.us0.cradlepointecm.com" required>

      <div class="grid">
        <div>
          <label>X-ECM-API-ID</label>
          <input name="api_id" type="password" required autocomplete="off" placeholder="Stored locally; hidden on screen.">
        </div>
        <div>
          <label>X-ECM-API-KEY</label>
          <input name="api_key" type="password" required autocomplete="off" placeholder="Stored locally; hidden on screen.">
        </div>
      </div>

      <div class="grid">
        <div>
          <label>X-CP-API-ID</label>
          <input name="cp_api_id" type="password" required autocomplete="off" placeholder="Stored locally; hidden on screen.">
        </div>
        <div>
          <label>X-CP-API-KEY</label>
          <input name="cp_api_key" type="password" required autocomplete="off" placeholder="Stored locally; hidden on screen.">
        </div>
      </div>

      <label>Customer / account name</label>
      <input name="account_name" placeholder="Optional">

      <label>Customer logo</label>
      <input name="customer_logo" type="file" accept="image/png,image/jpeg,image/webp,image/svg+xml">
      <p class="muted" style="margin-top:6px;">
        Optional. Upload a customer or team logo to display on the dashboard launcher.
      </p>

      <div class="notice">
        <strong>API usage note:</strong> This tool uses the NetCloud Manager API credentials you provide to query router inventory,
        signal history, usage data, alerts, locations, and cellular state. Background polling, dashboard refreshes, usage reports,
        and deep-dive exports may consume API calls against the selected NCM account.
      </div>

      <div class="notice">
        <strong>Background processes:</strong> When enabled, NCM Monitor can periodically poll router and cellular data so dashboard trends
        become more useful over time. Polling behavior depends on the installed configuration, number of routers, and selected dashboard profile.
      </div>

      <button type="submit">Save and launch dashboard</button>
    </form>

    <p class="muted">You can rotate or update these credentials later from the dashboard profile settings.</p>
    """
    return HTMLResponse(stock_page("Connect NCM", body))


def html_escape_basic(value):
    value = "" if value is None else str(value)
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def friendly_ncm_exception_message(exc, router_id=None):
    raw = str(exc or "")
    lower = raw.lower()

    if "401" in raw or "unauthorized" in lower:
        return "NCM rejected the request as unauthorized. Check the API ID/key pair values."

    if "403" in raw or "forbidden" in lower:
        if router_id:
            return (
                f"NCM rejected ID {router_id} with 403 Forbidden. "
                "This ID is not usable as a router ID for this dashboard profile. "
                "It may be a group ID, a router in another account/region, or a router your API user cannot access."
            )
        return "NCM returned 403 Forbidden. Check API user permissions, account scope, and base URL/region."

    if "404" in raw or "not found" in lower:
        if router_id:
            return (
                f"NCM could not find router ID {router_id}. "
                "Verify you copied the numeric router ID from the router detail page, not a group/account ID."
            )
        return "NCM returned 404 Not Found. Check the base URL/region."

    if "timeout" in lower or "timed out" in lower:
        return "NCM validation timed out. Check network connectivity and the NCM base URL."

    if "connection" in lower or "name or service not known" in lower:
        return "Could not connect to NCM. Check the base URL and network/DNS connectivity."

    if router_id:
        return (
            f"Router ID {router_id} could not be validated. "
            f"NCM response/error: {raw[:500]}"
        )

    return f"NCM credential validation failed: {raw[:500]}"


async def validate_ncm_credentials_direct(base_url, api_id, api_key, cp_api_id, cp_api_key):
    """
    Validate dashboard credentials before saving them.

    Uses a tiny direct request instead of ncm_get(), because during first setup
    the dashboard profile may not exist in the local DB yet.
    """
    import json
    import urllib.error
    import urllib.request

    clean_base = str(base_url or "").strip().rstrip("/")
    if not clean_base:
        return {"ok": False, "message": "NCM base URL is required."}

    url = clean_base + "/api/v2/routers/?limit=1"

    headers = {
        "Accept": "application/json",
        "X-CP-API-ID": str(cp_api_id or "").strip(),
        "X-CP-API-KEY": str(cp_api_key or "").strip(),
        "X-ECM-API-ID": str(api_id or "").strip(),
        "X-ECM-API-KEY": str(api_key or "").strip(),
    }

    def do_request():
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            status = getattr(resp, "status", 200)
            return status, body

    try:
        loop = asyncio.get_running_loop()
        status, body = await loop.run_in_executor(None, do_request)
        if status < 200 or status >= 300:
            return {
                "ok": False,
                "message": f"NCM returned HTTP {status} while validating credentials.",
            }

        try:
            parsed = json.loads(body or "{}")
        except Exception:
            parsed = {}

        return {
            "ok": True,
            "message": "NCM API credentials validated successfully.",
            "sample_count": len(parsed.get("data", [])) if isinstance(parsed, dict) and isinstance(parsed.get("data"), list) else None,
        }

    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", errors="replace")
        except Exception:
            detail = str(exc)
        return {
            "ok": False,
            "message": friendly_ncm_exception_message(f"{exc.code}: {detail}"),
        }
    except Exception as exc:
        return {
            "ok": False,
            "message": friendly_ncm_exception_message(exc),
        }


async def validate_router_id_for_profile(router_id, profile_id):
    """
    Validate a user-supplied router ID before inserting it as a monitoring target.

    This intentionally checks /api/v2/routers/<id>/ because group IDs, account IDs,
    and inaccessible router IDs should not be accepted as monitoring targets.
    """
    rid = str(router_id or "").strip()

    if not rid:
        return {"ok": False, "message": "router_id is required."}

    if not rid.isdigit():
        return {
            "ok": False,
            "message": f"'{rid}' is not a valid numeric router ID.",
        }

    try:
        payload = await ncm_get(f"/api/v2/routers/{rid}/", profile_id=profile_id)

        router_obj = payload
        if isinstance(payload, dict):
            data_obj = payload.get("data")
            if isinstance(data_obj, dict):
                router_obj = data_obj
            elif isinstance(data_obj, list) and data_obj:
                router_obj = data_obj[0]

        return {
            "ok": True,
            "message": "Router ID validated successfully.",
            "router": router_obj if isinstance(router_obj, dict) else None,
        }

    except Exception as exc:
        return {
            "ok": False,
            "message": friendly_ncm_exception_message(exc, router_id=rid),
        }


async def require_valid_router_id(router_id, profile_id):
    validation = await validate_router_id_for_profile(router_id, profile_id)
    if not validation.get("ok"):
        raise HTTPException(status_code=400, detail=validation.get("message") or "Router ID validation failed.")
    return validation



@app.post("/api-setup")
async def api_setup_post(
    request: Request,
    profile_name: str = Form(...),
    base_url: str = Form(...),
    api_id: str = Form(...),
    api_key: str = Form(...),
    cp_api_id: str = Form(...),
    cp_api_key: str = Form(...),
    account_name: str = Form(""),
    customer_logo: UploadFile = File(None),
):
    ensure_stock_setup_tables()

    user = current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    clean_profile_name = profile_name.strip()
    clean_account_name = account_name.strip()
    clean_base_url = base_url.strip().rstrip("/")

    if not clean_profile_name:
        return HTMLResponse(
            stock_page("Setup error", "<h1>Setup error</h1><div class='error'>Dashboard / profile name is required.</div><p><a href='/api-setup'>Go back</a></p>"),
            status_code=400,
        )

    if clean_profile_name.lower() in {"default dashboard", "default", "ncm monitor"}:
        return HTMLResponse(
            stock_page("Setup error", "<h1>Setup error</h1><div class='error'>Please enter a real customer, account, lab, or dashboard name instead of the default placeholder.</div><p><a href='/api-setup'>Go back</a></p>"),
            status_code=400,
        )

    if not all([clean_base_url, api_id.strip(), api_key.strip(), cp_api_id.strip(), cp_api_key.strip()]):
        return HTMLResponse(
            stock_page("Setup error", "<h1>Setup error</h1><div class='error'>All NCM API credential fields are required.</div><p><a href='/api-setup'>Go back</a></p>"),
            status_code=400,
        )

    credential_check = await validate_ncm_credentials_direct(
        clean_base_url,
        api_id.strip(),
        api_key.strip(),
        cp_api_id.strip(),
        cp_api_key.strip(),
    )
    if not credential_check.get("ok"):
        msg = html_escape_basic(credential_check.get("message") or "NCM API credential validation failed.")
        return HTMLResponse(
            stock_page(
                "Setup error",
                f"<h1>Setup error</h1><div class='error'>{msg}</div><p><a href='/api-setup'>Go back</a></p>"
            ),
            status_code=400,
        )

    ts = now_utc()

    logo_path = None
    if customer_logo and customer_logo.filename:
        safe_name = "".join(c for c in customer_logo.filename if c.isalnum() or c in ("-", "_", ".")).strip(".")
        ext = safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
        allowed_exts = {"png", "jpg", "jpeg", "webp", "svg"}

        if ext not in allowed_exts:
            return HTMLResponse(
                stock_page(
                    "Logo upload error",
                    "<h1>Logo upload error</h1><div class='error'>Logo must be PNG, JPG, JPEG, WEBP, or SVG.</div><p><a href='/api-setup'>Go back</a></p>"
                ),
                status_code=400,
            )

        logo_dir = Path(STATIC_DIR) / "logos"
        logo_dir.mkdir(parents=True, exist_ok=True)

        logo_filename = f"profile-logo-{int(datetime.now().timestamp())}.{ext}"
        logo_file_path = logo_dir / logo_filename

        content = await customer_logo.read()
        if len(content) > 2 * 1024 * 1024:
            return HTMLResponse(
                stock_page(
                    "Logo upload error",
                    "<h1>Logo upload error</h1><div class='error'>Logo must be smaller than 2 MB.</div><p><a href='/api-setup'>Go back</a></p>"
                ),
                status_code=400,
            )

        logo_file_path.write_bytes(content)
        try:
            os.chown(str(logo_file_path), os.getuid(), os.getgid())
        except Exception:
            pass

        logo_path = f"/static/logos/{logo_filename}"

    with global_db() as conn:
        row = conn.execute("SELECT id FROM dashboard_profiles WHERE is_default = 1 ORDER BY id LIMIT 1").fetchone()
        if row:
            profile_id = row[0]
            conn.execute("""
                UPDATE dashboard_profiles
                SET name = ?,
                    description = ?,
                    base_url = ?,
                    api_id = ?,
                    api_key = ?,
                    cp_api_id = ?,
                    cp_api_key = ?,
                    logo_path = COALESCE(?, logo_path),
                    is_default = 1,
                    updated_at = ?
                WHERE id = ?
            """, (
                profile_name.strip(),
                account_name.strip() or "Configured during first-run setup.",
                clean_base_url,
                api_id.strip(),
                api_key.strip(),
                cp_api_id.strip(),
                cp_api_key.strip(),
                logo_path,
                ts,
                profile_id,
            ))
        else:
            conn.execute("""
                INSERT INTO dashboard_profiles
                (name, description, base_url, api_id, api_key, cp_api_id, cp_api_key, logo_path, is_default, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """, (
                profile_name.strip(),
                account_name.strip() or "Configured during first-run setup.",
                clean_base_url,
                api_id.strip(),
                api_key.strip(),
                cp_api_id.strip(),
                cp_api_key.strip(),
                logo_path,
                ts,
                ts,
            ))

        conn.execute("""
            INSERT INTO app_settings(key, value, updated_at)
            VALUES ('setup_complete', '1', ?)
            ON CONFLICT(key) DO UPDATE SET value = '1', updated_at = excluded.updated_at
        """, (ts,))

        conn.execute("""
            INSERT INTO setup_audit(event_type, detail, created_at)
            VALUES ('ncm_profile_configured', ?, ?)
        """, (profile_name.strip(), ts))

        conn.commit()

    if not setup_complete():
        return RedirectResponse(url="/api-setup", status_code=303)

    return RedirectResponse(url="/launcher", status_code=303)


@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    ensure_stock_setup_tables()

    if not users_exist():
        return RedirectResponse(url="/setup", status_code=303)

    body = """
    <h1>NCM Monitor</h1>
    <p>Sign in to continue.</p>

    <form method="post" action="/login">
      <label>Username</label>
      <input name="username" required autocomplete="username">

      <label>Password</label>
      <input name="password" type="password" required autocomplete="current-password">

      <button type="submit">Sign in</button>
    </form>
    """
    return HTMLResponse(stock_page("NCM Monitor Login", body))


@app.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    ensure_stock_setup_tables()

    with global_db() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("""
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
        """, (username.strip(),)).fetchone()

    if not row or not verify_password(password, row["password_hash"]):
        return HTMLResponse(stock_page("Login failed", "<h1>Login failed</h1><div class='error'>Invalid username or password.</div><p><a href='/login'>Try again</a></p>"), status_code=401)

    request.session["user_id"] = row["id"]
    request.session["username"] = row["username"]

    return RedirectResponse(url="/launcher", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.on_event("startup")
def startup():
    ensure_stock_setup_tables()
    init_db()
    seed_default_pools()

    ensure_dashboard_profile_tables()
    ensure_app_profile_schema()
    ensure_cellular_monitor_tables(get_default_profile_id())

    if CELLULAR_MONITOR_ENABLED and CELLULAR_GLOBAL_MONITOR_ENABLED:
        asyncio.create_task(cellular_global_monitor_loop())


def ensure_dashboard_profile_tables():
    """Phase 1 foundation for multi-customer dashboards and polling pause controls."""
    ts = now_utc()

    with global_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dashboard_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                base_url TEXT,
                api_id TEXT,
                api_key TEXT,
                cp_api_id TEXT,
                cp_api_key TEXT,
                is_default INTEGER NOT NULL DEFAULT 0,
                polling_paused INTEGER NOT NULL DEFAULT 0,
                pause_reason TEXT,
                paused_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        existing = conn.execute("SELECT id FROM dashboard_profiles LIMIT 1").fetchone()
        if not existing:
            conn.execute("""
                INSERT INTO dashboard_profiles
                (name, description, is_default, created_at, updated_at)
                VALUES (?, ?, 1, ?, ?)
            """, (
                "Default Dashboard",
                "Original NCM Monitor dashboard profile.",
                ts,
                ts,
            ))

        # Add profile_id / pause controls to major tables without breaking existing data.
        migrations = [
            ("monitoring_pools", "profile_id", "ALTER TABLE monitoring_pools ADD COLUMN profile_id INTEGER DEFAULT 1"),
            ("monitoring_pools", "polling_paused", "ALTER TABLE monitoring_pools ADD COLUMN polling_paused INTEGER NOT NULL DEFAULT 0"),
            ("monitoring_pools", "pause_reason", "ALTER TABLE monitoring_pools ADD COLUMN pause_reason TEXT"),
            ("monitoring_pools", "paused_at", "ALTER TABLE monitoring_pools ADD COLUMN paused_at TEXT"),

            ("routers", "profile_id", "ALTER TABLE routers ADD COLUMN profile_id INTEGER DEFAULT 1"),
            ("routers", "polling_paused", "ALTER TABLE routers ADD COLUMN polling_paused INTEGER NOT NULL DEFAULT 0"),
            ("routers", "pause_reason", "ALTER TABLE routers ADD COLUMN pause_reason TEXT"),
            ("routers", "paused_at", "ALTER TABLE routers ADD COLUMN paused_at TEXT"),

            ("deep_dive_jobs", "profile_id", "ALTER TABLE deep_dive_jobs ADD COLUMN profile_id INTEGER DEFAULT 1"),
            ("api_call_counter", "profile_id", "ALTER TABLE api_call_counter ADD COLUMN profile_id INTEGER DEFAULT 1"),
        ]

        for table, column, ddl in migrations:
            try:
                existing_cols = [r[1] for r in conn.execute("PRAGMA table_info(%s)" % table).fetchall()]
                if column not in existing_cols:
                    conn.execute(ddl)
            except Exception:
                pass

        profile_migrations = [
            ("company_name", "ALTER TABLE dashboard_profiles ADD COLUMN company_name TEXT"),
            ("purpose", "ALTER TABLE dashboard_profiles ADD COLUMN purpose TEXT"),
            ("logo_path", "ALTER TABLE dashboard_profiles ADD COLUMN logo_path TEXT"),
        ]

        for column, ddl in profile_migrations:
            try:
                existing_cols = [r[1] for r in conn.execute("PRAGMA table_info(dashboard_profiles)").fetchall()]
                if column not in existing_cols:
                    conn.execute(ddl)
            except Exception:
                pass

        conn.commit()


def get_default_profile_id():
    try:
        with db() as conn:
            row = conn.execute("SELECT id FROM dashboard_profiles WHERE is_default = 1 ORDER BY id LIMIT 1").fetchone()
            if row:
                return int(row[0])
            row = conn.execute("SELECT id FROM dashboard_profiles ORDER BY id LIMIT 1").fetchone()
            return int(row[0]) if row else 1
    except Exception:
        return 1




@app.post("/api/dashboard-profiles/{profile_id}")
async def update_dashboard_profile(profile_id: int, payload: dict = Body(default={})):
    ensure_dashboard_profile_tables()

    fields = {
        "name": str(payload.get("name") or "").strip(),
        "company_name": str(payload.get("company_name") or "").strip(),
        "description": str(payload.get("description") or "").strip(),
        "purpose": str(payload.get("purpose") or "").strip(),
        "base_url": str(payload.get("base_url") or "").strip(),
        "api_id": str(payload.get("api_id") or "").strip(),
        "api_key": str(payload.get("api_key") or "").strip(),
        "cp_api_id": str(payload.get("cp_api_id") or "").strip(),
        "cp_api_key": str(payload.get("cp_api_key") or "").strip(),
        "logo_path": str(payload.get("logo_path") or "").strip(),
    }

    if not fields["name"]:
        raise HTTPException(status_code=400, detail="Dashboard name is required.")

    fields["base_url"] = str(fields.get("base_url") or "").strip().rstrip("/") or "https://www.us0.cradlepointecm.com"
    fields["api_id"] = str(fields.get("api_id") or "").strip()
    fields["api_key"] = str(fields.get("api_key") or "").strip()
    fields["cp_api_id"] = str(fields.get("cp_api_id") or "").strip()
    fields["cp_api_key"] = str(fields.get("cp_api_key") or "").strip()

    missing_fields = []
    if not fields["base_url"]:
        missing_fields.append("Base URL")
    if not fields["api_id"]:
        missing_fields.append("X-ECM-API-ID")
    if not fields["api_key"]:
        missing_fields.append("X-ECM-API-KEY")
    if not fields["cp_api_id"]:
        missing_fields.append("X-CP-API-ID")
    if not fields["cp_api_key"]:
        missing_fields.append("X-CP-API-KEY")
    if missing_fields:
        raise HTTPException(
            status_code=400,
            detail="Missing required NCM API credential fields: " + ", ".join(missing_fields)
        )

    credential_check = await validate_ncm_credentials_direct(
        fields["base_url"],
        fields["api_id"],
        fields["api_key"],
        fields["cp_api_id"],
        fields["cp_api_key"],
    )
    if not credential_check.get("ok"):
        raise HTTPException(
            status_code=400,
            detail=credential_check.get("message") or "NCM API credential validation failed.",
        )

    with global_db() as conn:
        conn.execute("""
            UPDATE dashboard_profiles
            SET name = ?,
                company_name = ?,
                description = ?,
                purpose = ?,
                base_url = ?,
                api_id = ?,
                api_key = ?,
                cp_api_id = ?,
                cp_api_key = ?,
                logo_path = COALESCE(NULLIF(?, ''), logo_path),
                updated_at = ?
            WHERE id = ?
        """, (
            fields["name"], fields["company_name"], fields["description"], fields["purpose"],
            fields["base_url"], fields["api_id"], fields["api_key"], fields["cp_api_id"],
            fields["cp_api_key"], fields["logo_path"], now_utc(), profile_id
        ))

    return {"ok": True, "profile_id": profile_id}


@app.post("/api/dashboard-profiles/{profile_id}/set-default")
async def set_default_dashboard_profile(profile_id: int):
    ensure_dashboard_profile_tables()
    with global_db() as conn:
        conn.execute("UPDATE dashboard_profiles SET is_default = 0")
        conn.execute("UPDATE dashboard_profiles SET is_default = 1, updated_at = ? WHERE id = ?", (now_utc(), profile_id))
    return {"ok": True, "default_profile_id": profile_id}


@app.post("/api/dashboard-profiles/{profile_id}/logo")
async def upload_dashboard_logo(profile_id: int, file: UploadFile = File(...)):
    ensure_dashboard_profile_tables()

    safe_name = "".join([c for c in file.filename if c.isalnum() or c in ("-", "_", ".")]) or "logo.png"
    ext = safe_name.split(".")[-1].lower()
    if ext not in ["png", "jpg", "jpeg", "webp", "gif", "svg"]:
        raise HTTPException(status_code=400, detail="Logo must be png, jpg, jpeg, webp, gif, or svg.")

    logo_dir = Path(f"{BASE_DIR}/static/logos")
    logo_dir.mkdir(parents=True, exist_ok=True)
    out_path = logo_dir / f"profile_{profile_id}_{safe_name}"

    content = await file.read()
    out_path.write_bytes(content)

    public_path = f"/static/logos/{out_path.name}"

    with global_db() as conn:
        conn.execute("""
            UPDATE dashboard_profiles
            SET logo_path = ?, updated_at = ?
            WHERE id = ?
        """, (public_path, now_utc(), profile_id))

    return {"ok": True, "profile_id": profile_id, "logo_path": public_path}





@app.get("/launcher", response_class=HTMLResponse)
async def launcher_page(request: Request):
    import html

    try:
        with global_db() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT
                    id,
                    name,
                    description,
                    base_url,
                    company_name,
                    purpose,
                    logo_path,
                    is_default,
                    polling_paused
                FROM dashboard_profiles
                ORDER BY is_default DESC, id ASC
            """).fetchall()
            profiles = [dict(r) for r in rows]
    except Exception as exc:
        profiles = []
        load_error = str(exc)
    else:
        load_error = ""

    def esc(value):
        return html.escape(str(value or ""))

    cards_html = ""

    if load_error:
        cards_html = f"""
        <div class="notice error">
          <h2>Dashboard profiles could not be loaded</h2>
          <p>The launcher could not read dashboard profile data from the local database.</p>
          <pre>{esc(load_error)}</pre>
        </div>
        """
    elif profiles:
        for p in profiles:
            pid = int(p.get("id") or 0)
            name = esc(p.get("name") or "Dashboard")
            company = esc(p.get("company_name") or p.get("description") or "")
            purpose = esc(p.get("purpose") or "Monitor router health, usage, signal quality, failover behavior, and operational reports.")
            logo = esc(p.get("logo_path") or "")
            base_url = esc(p.get("base_url") or "")
            initial = esc((p.get("name") or "D")[:1].upper())
            paused = bool(p.get("polling_paused"))
            default = bool(p.get("is_default"))

            logo_html = f'<img src="{logo}" alt="{name} logo">' if logo else f'<div class="initial">{initial}</div>'
            pill_text = "Paused" if paused else "Active"
            pill_class = "pill paused" if paused else "pill"
            default_html = '<span class="default-pill">Default</span>' if default else ""

            cards_html += f"""
            <a class="card" href="/ui?profile_id={pid}" onclick="localStorage.setItem('ncm_active_profile_id','{pid}')">
              <div class="topline">
                <div class="logoBox">{logo_html}</div>
                <div>
                  <div class="name">{name}</div>
                  <div class="company">{company}</div>
                  <div class="baseurl">{base_url}</div>
                </div>
              </div>
              <div class="purpose">{purpose}</div>
              <div class="cardFooter">
                <span class="{pill_class}">{pill_text}</span>
                {default_html}
              </div>
            </a>
            """
    else:
        cards_html = """
        <div class="empty-state">
          <div class="eyebrow">First Run</div>
          <h2>Get started with NCM Monitor</h2>
          <p>
            NCM Monitor turns NetCloud Manager API data into an operational dashboard for router health,
            cellular signal quality, WAN usage, failover behavior, customer pools, API consumption, and deep-dive reporting.
          </p>

          <div class="empty-grid">
            <div class="empty-panel">
              <h3>What this tool does</h3>
              <ul>
                <li>Creates customer-specific monitoring dashboards</li>
                <li>Groups routers into pools for focused monitoring</li>
                <li>Tracks signal health, cellular state, usage, and failover behavior</li>
                <li>Generates router deep-dive reports and exports</li>
                <li>Shows API call consumption with the built-in odometer</li>
              </ul>
            </div>

            <div class="empty-panel">
              <h3>What happens in the background</h3>
              <ul>
                <li>Your setup and dashboard configuration are stored locally</li>
                <li>NCM API credentials are used only by this app instance</li>
                <li>Polling and reports may consume NCM API calls</li>
                <li>Router inventory, signal, usage, and reports can be cached locally</li>
                <li>You control which customer/account profiles are monitored</li>
              </ul>
            </div>
          </div>

          <div class="empty-actions">
            <a class="primary-cta" href="/dashboards">Create your first dashboard</a>
            <a class="secondary-cta" href="/api-setup">Configure NCM API credentials</a>
          </div>
        </div>
        """

    return f"""
<!DOCTYPE html>
<html>
<head>
  <title>NCM Operations Center</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {{
      margin:0;
      font-family:Arial,sans-serif;
      background:#0f172a;
      color:#e5e7eb;
    }}
    .wrap {{
      max-width:1250px;
      margin:0 auto;
      padding:38px;
    }}
    .hero {{
      display:flex;
      justify-content:space-between;
      align-items:flex-start;
      gap:18px;
      margin-bottom:28px;
    }}
    h1 {{
      margin:0;
      font-size:34px;
      letter-spacing:-.03em;
    }}
    .muted {{
      color:#94a3b8;
      font-size:14px;
      margin-top:6px;
    }}
    .actions {{
      display:flex;
      flex-direction:row;
      flex-wrap:nowrap;
      align-items:center;
      justify-content:flex-end;
      gap:18px;
      white-space:nowrap;
    }}
    .actions a {{
      display:inline-flex;
      align-items:center;
      justify-content:center;
      min-height:44px;
      padding:0 18px;
      border-radius:13px;
      background:#334155;
      color:white;
      text-decoration:none;
      font-weight:900;
      box-shadow:0 10px 24px rgba(0,0,0,.18);
      transition:.15s ease;
    }}
    .actions a:hover {{
      background:#475569;
      transform:translateY(-1px);
    }}
    .actions a.logout {{
      background:rgba(127,29,29,.88);
    }}
    .actions a.logout:hover {{
      background:rgba(153,27,27,.95);
    }}
    .actions a.secondary {{
      background:#334155;
    }}
    .grid {{
      display:grid;
      grid-template-columns:repeat(auto-fill,minmax(310px,1fr));
      gap:18px;
    }}
    .card {{
      display:block;
      color:inherit;
      text-decoration:none;
      background:linear-gradient(135deg,#111827,#0b1220);
      border:1px solid #263449;
      border-radius:22px;
      padding:22px;
      box-shadow:0 18px 40px rgba(0,0,0,.28);
      cursor:pointer;
      transition:.15s ease;
    }}
    .card:hover {{
      transform:translateY(-3px);
      border-color:#3b82f6;
    }}
    .topline {{
      display:flex;
      align-items:center;
      gap:16px;
    }}
    .logoBox {{
      width:82px;
      height:82px;
      border-radius:20px;
      background:#020617;
      border:1px solid #334155;
      display:flex;
      align-items:center;
      justify-content:center;
      overflow:hidden;
      flex:0 0 auto;
    }}
    .logoBox img {{
      width:100%;
      height:100%;
      object-fit:contain;
      padding:8px;
      box-sizing:border-box;
    }}
    .initial {{
      font-size:34px;
      font-weight:900;
      color:#60a5fa;
    }}
    .name {{
      font-size:22px;
      font-weight:900;
    }}
    .company, .baseurl {{
      margin-top:4px;
      color:#94a3b8;
      font-size:13px;
    }}
    .purpose {{
      margin-top:14px;
      min-height:42px;
      color:#cbd5e1;
      line-height:1.45;
    }}
    .cardFooter {{
      margin-top:18px;
      display:flex;
      gap:8px;
      flex-wrap:wrap;
      align-items:center;
    }}
    .pill {{
      display:inline-block;
      padding:4px 9px;
      border-radius:999px;
      background:#14532d;
      color:#bbf7d0;
      font-size:12px;
    }}
    .pill.paused {{
      background:#7f1d1d;
      color:#fecaca;
    }}
    .default-pill {{
      display:inline-block;
      padding:4px 9px;
      border-radius:999px;
      background:#1e3a8a;
      color:#bfdbfe;
      font-size:12px;
    }}
    .empty-state, .notice {{
      grid-column:1/-1;
      margin-top:22px;
      border:1px solid rgba(255,255,255,.14);
      background:linear-gradient(180deg,rgba(35,55,78,.82),rgba(8,18,28,.92));
      border-radius:24px;
      padding:32px;
      box-shadow:0 24px 80px rgba(0,0,0,.25);
    }}
    .notice.error {{
      border-color:rgba(255,120,120,.35);
      background:rgba(255,80,80,.10);
      color:#ffd0d0;
    }}
    .eyebrow {{
      display:inline-block;
      padding:7px 11px;
      border-radius:999px;
      background:rgba(113,214,255,.14);
      color:#91e2ff;
      font-weight:800;
      font-size:12px;
      letter-spacing:.04em;
      text-transform:uppercase;
    }}
    .empty-state h2 {{
      margin:18px 0 10px 0;
      font-size:30px;
      letter-spacing:-.03em;
      color:#fff;
    }}
    .empty-state p {{
      color:#b9c8d6;
      line-height:1.6;
      max-width:860px;
      font-size:15px;
    }}
    .empty-grid {{
      display:grid;
      grid-template-columns:repeat(auto-fit,minmax(280px,1fr));
      gap:16px;
      margin-top:24px;
    }}
    .empty-panel {{
      border:1px solid rgba(255,255,255,.11);
      border-radius:18px;
      padding:20px;
      background:rgba(255,255,255,.045);
    }}
    .empty-panel h3 {{
      margin:0 0 10px 0;
      color:#fff;
    }}
    .empty-panel ul {{
      margin:0;
      padding-left:20px;
      color:#b9c8d6;
      line-height:1.8;
    }}
    .empty-actions {{
      display:flex;
      gap:12px;
      flex-wrap:wrap;
      margin-top:26px;
    }}
    .primary-cta, .secondary-cta {{
      display:inline-block;
      padding:13px 18px;
      border-radius:14px;
      font-weight:900;
      text-decoration:none;
    }}
    .primary-cta {{
      color:#071018;
      background:#71d6ff;
    }}
    .secondary-cta {{
      color:#e8f1f7;
      background:rgba(255,255,255,.11);
    }}
    @media (max-width: 760px) {{
      .wrap {{ padding:24px; }}
      .hero {{ flex-direction:column; }}
      .actions {{ flex-wrap:wrap; justify-content:flex-start; gap:10px; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <div>
        <h1>NCM Operations Center</h1>
        <div class="muted">Choose a dashboard profile to monitor routers, usage, signal health, failover behavior, and operational reports for a specific NCM account or customer.</div>
      </div>
      <div class="actions">
        <a class="secondary" href="/dashboards">Manage Dashboards</a>
        <a class="secondary" href="/api-setup">API Setup</a>
        <a class="secondary logout" href="/logout">Sign Out</a>
      </div>
    </div>

    <div id="cards" class="grid">
      {cards_html}
    </div>
  </div>
</body>
</html>
"""



@app.get("/dashboards", response_class=HTMLResponse)
async def manage_dashboards_page():
    return """
<!DOCTYPE html>
<html>
<head>
  <title>NCM Monitor - Dashboards</title>
  <style>
    body { margin:0; font-family:Arial,sans-serif; background:#0f172a; color:#e5e7eb; }
    .wrap { max-width:1200px; margin:0 auto; padding:34px; }
    .top { display:flex; justify-content:space-between; align-items:center; margin-bottom:24px; }
    a { color:#93c5fd; text-decoration:none; }
    .card { background:linear-gradient(135deg,#111827,#0b1220); border:1px solid #263449; border-radius:20px; padding:22px; box-shadow:0 18px 40px rgba(0,0,0,.28); margin-bottom:20px; }
    .grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; }
    label { display:block; font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:#94a3b8; margin-bottom:6px; }
    input, textarea { width:100%; box-sizing:border-box; border-radius:12px; border:1px solid #334155; background:#020617; color:#f8fafc; padding:11px; }
    textarea { min-height:82px; }
    button { border:0; border-radius:12px; padding:10px 14px; font-weight:800; cursor:pointer; background:#2563eb; color:white; }
    button.secondary { background:#334155; }
    button.danger { background:#dc2626; }
    .profile { display:grid; grid-template-columns:92px 1fr auto; gap:20px; align-items:center; }
    .logo { width:78px; height:78px; border-radius:18px; object-fit:contain; background:#020617; border:1px solid #334155; padding:8px; }
    .placeholder { width:78px; height:78px; border-radius:18px; display:flex; align-items:center; justify-content:center; background:#1e293b; border:1px solid #334155; font-size:28px; font-weight:900; color:#60a5fa; }
    .muted { color:#94a3b8; font-size:13px; }
    .pill { display:inline-block; padding:4px 9px; border-radius:999px; background:#1d4ed8; color:white; font-size:11px; margin-left:8px; vertical-align:middle; }
    .paused { background:#991b1b; }
    .row-actions { display:flex; gap:12px; flex-wrap:wrap; justify-content:flex-end; }
    .row-actions button { min-width:135px; }
    .meta { display:grid; grid-template-columns:130px 1fr; gap:8px 16px; margin-top:12px; font-size:14px; }
    .sectionTitle { margin:26px 0 12px 0; display:flex; justify-content:space-between; align-items:flex-end; gap:16px; }
    .sectionTitle h2 { margin:0; }
    .helpBox { margin:14px 0 22px 0; padding:15px 17px; border-radius:14px; background:rgba(37,99,235,.10); border:1px solid rgba(96,165,250,.24); color:#cbd5e1; line-height:1.55; }
    .helpBox strong { color:#fff; }
    .createCard { border-style:dashed; border-color:#3b82f6; }
    .createCard h2 { margin-top:0; }
    .subtleDivider { height:1px; background:#263449; margin:28px 0; }
    .meta span:first-child { color:#94a3b8; }
    .fileline { margin-top:12px; }
    .modalBack { display:none; position:fixed; inset:0; background:rgba(0,0,0,.65); z-index:999999; align-items:center; justify-content:center; }
    .modal { width:min(820px,92vw); background:#111827; border:1px solid #334155; border-radius:22px; padding:22px; box-shadow:0 24px 80px rgba(0,0,0,.55); }
    .modalTop { display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; }
    .modalTop h2 { margin:0; }
    .closeBtn { background:#334155; }
  </style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div>
      <h1>Dashboard Management</h1>
      <div class="muted">Modify existing dashboard profiles or create additional customer/account dashboards.</div>
    </div>
    <a href="/launcher">← Back to Dashboard Launcher</a>
  </div>

  <div class="helpBox">
    <strong>What this page is for:</strong>
    Dashboard profiles define which NCM account/customer the app connects to, what API credentials are used,
    how the dashboard is labeled, whether polling is paused, and which profile is treated as the default.
    Existing dashboards are shown first so you can edit, rotate credentials, upload logos, pause polling, or switch defaults.
  </div>

  <div class="sectionTitle">
    <div>
      <h2>Existing Dashboards</h2>
      <div class="muted">Manage dashboards that have already been created.</div>
    </div>
  </div>

  <div id="profiles"></div>

  <div class="subtleDivider"></div>

  <div class="sectionTitle">
    <div>
      <h2>Create New Dashboard</h2>
      <div class="muted">Add another NCM customer/account profile to this local app instance.</div>
    </div>
  </div>

  <div class="card createCard">
    <h2>New Dashboard Profile</h2>
    <div class="helpBox">
      <strong>Before creating a new dashboard:</strong>
      Make sure you are authorized to use the API credentials for the NCM account/customer being configured.
      Each dashboard profile stores its own API configuration locally and may consume API calls when refreshed, polled, or used for reports.
    </div>
    <div class="grid">
      <div><label>Dashboard Name</label><input id="name" placeholder="Customer / Lab / Pilot Group"></div>
      <div><label>Company Name</label><input id="company_name" placeholder="Customer or organization"></div>
      <div><label>Base URL</label><input id="base_url" value="https://www.us0.cradlepointecm.com" placeholder="https://www.us0.cradlepointecm.com"></div>
      <div><label>Purpose</label><input id="purpose" placeholder="Production monitoring, lab testing, pilot validation..."></div>
      <div><label>X-ECM-API-ID</label><input id="api_id" type="password" placeholder="Hidden on screen"></div>
      <div><label>X-ECM-API-KEY</label><input id="api_key" type="password" placeholder="Hidden on screen"></div>
      <div><label>X-CP-API-ID</label><input id="cp_api_id" type="password" placeholder="Hidden on screen"></div>
      <div><label>X-CP-API-KEY</label><input id="cp_api_key" type="password" placeholder="Hidden on screen"></div>
      <div id="create_profile_status" style="display:none;margin-top:14px;padding:14px 16px;border-radius:14px;font-weight:700;"></div>
      <div style="grid-column:1 / -1;"><label>Description</label><textarea id="description" placeholder="What this dashboard is used for..."></textarea></div>
      <div style="grid-column:1 / -1;">
        <label>Customer Logo</label>
        <input id="create_logo" type="file" accept="image/png,image/jpeg,image/webp,image/gif,image/svg+xml">
        <div class="muted" style="margin-top:6px;">Optional. Upload a customer or team logo for this dashboard profile.</div>
      </div>
    </div>
    <br>
    <button onclick="createProfile()">Create New Dashboard</button>
  </div>

  <div id="editModalBack" class="modalBack">
    <div class="modal">
      <div class="modalTop">
        <h2>Edit Dashboard</h2>
        <button class="closeBtn" onclick="closeEditModal()">Close</button>
      </div>

      <input type="hidden" id="edit_id">

      <div class="grid">
        <div><label>Dashboard Name</label><input id="edit_name"></div>
        <div><label>Company Name</label><input id="edit_company_name"></div>
        <div><label>Base URL</label><input id="edit_base_url"></div>
        <div><label>Purpose</label><input id="edit_purpose"></div>
        <div><label>X-ECM-API-ID</label><input id="edit_api_id" type="password" placeholder="Enter a new value only if rotating/updating"></div>
        <div><label>X-ECM-API-KEY</label><input id="edit_api_key" type="password" placeholder="Enter a new value only if rotating/updating"></div>
        <div><label>X-CP-API-ID</label><input id="edit_cp_api_id" type="password" placeholder="Enter a new value only if rotating/updating"></div>
        <div><label>X-CP-API-KEY</label><input id="edit_cp_api_key" type="password" placeholder="Enter a new value only if rotating/updating"></div>
        <div style="grid-column:1 / -1;"><label>Description</label><textarea id="edit_description"></textarea></div>
      </div>

      <br>
      <button onclick="saveProfileEdit()">Save Changes</button>
    </div>
  </div>
</div>

<script>
function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}

async function loadProfiles() {
  const el = document.getElementById('profiles');

  try {
    const res = await fetch('/api/dashboard-profiles', {
      credentials: 'same-origin',
      redirect: 'follow'
    });

    const contentType = res.headers.get('content-type') || '';

    if (!res.ok || !contentType.includes('application/json')) {
      el.innerHTML = `
        <div class="card">
          <h2>Existing dashboards could not be loaded</h2>
          <div class="muted">
            The dashboard management page could not read profile data. Your login session may have expired.
          </div>
          <div class="meta">
            <span>HTTP Status</span><span>${escapeHtml(res.status)}</span>
            <span>Content Type</span><span>${escapeHtml(contentType || 'unknown')}</span>
          </div>
          <br>
          <a href="/logout">Sign out and back in</a>
        </div>
      `;
      return;
    }

    const data = await res.json();
    const profiles = data.profiles || [];

    if (!profiles.length) {
      el.innerHTML = `
        <div class="card">
          <h2>No dashboards have been created yet</h2>
          <div class="muted">
            Use the Create New Dashboard section below to add your first NCM customer/account profile.
          </div>
        </div>
      `;
      return;
    }

    el.innerHTML = profiles.map(p => {
      const logo = p.logo_path
        ? `<img class="logo" src="${escapeHtml(p.logo_path)}">`
        : `<div class="placeholder">${escapeHtml((p.name || '?').slice(0,1).toUpperCase())}</div>`;

      return `
        <div class="card profile">
          ${logo}
          <div>
            <h2>${escapeHtml(p.name)} ${p.is_default ? '<span class="pill">Active Default</span>' : ''} ${p.polling_paused ? '<span class="pill paused">Polling Paused</span>' : ''}</h2>
            <div class="muted">${escapeHtml(p.company_name || p.description || 'No company name set')}</div>
            <div class="meta">
              <span>Purpose</span><span>${escapeHtml(p.purpose || '—')}</span>
              <span>Description</span><span>${escapeHtml(p.description || '—')}</span>
              <span>Base URL</span><span>${escapeHtml(p.base_url || '—')}</span>
              <span>Created</span><span>${escapeHtml(p.created_at || '—')}</span>
              <span>Updated</span><span>${escapeHtml(p.updated_at || '—')}</span>
            </div>
            <div class="fileline"><input type="file" id="logo_${p.id}" accept="image/*"></div>
          </div>
          <div class="row-actions">
            <button onclick="uploadLogo(${p.id})">Upload Logo</button>
            <button class="secondary" onclick='openEditModal(${JSON.stringify(p).replace(/'/g, "&#39;")})'>Edit</button>
            <button class="secondary" onclick="setDefault(${p.id})">Switch / Set Default</button>
            <button class="${p.polling_paused ? 'secondary' : 'danger'}" onclick="togglePause(${p.id}, ${p.polling_paused ? 0 : 1})">${p.polling_paused ? 'Resume Polling' : 'Pause Polling'}</button>
          </div>
        </div>`;
    }).join('');

  } catch (err) {
    el.innerHTML = `
      <div class="card">
        <h2>Dashboard management error</h2>
        <div class="muted">The page hit a browser-side error while loading dashboard profiles.</div>
        <pre style="white-space:pre-wrap;color:#fecaca;">${escapeHtml(String(err))}</pre>
      </div>
    `;
  }
}

function val(id) {
  const el = document.getElementById(id);
  return el ? el.value.trim() : '';
}

function setCreateProfileStatus(kind, message) {
  const el = document.getElementById('create_profile_status');
  if (!el) return;

  const styles = {
    checking: {
      bg: 'rgba(59,130,246,.14)',
      border: '1px solid rgba(96,165,250,.35)',
      color: '#bfdbfe',
      icon: '⏳'
    },
    success: {
      bg: 'rgba(34,197,94,.14)',
      border: '1px solid rgba(74,222,128,.38)',
      color: '#bbf7d0',
      icon: '✅'
    },
    error: {
      bg: 'rgba(239,68,68,.14)',
      border: '1px solid rgba(248,113,113,.40)',
      color: '#fecaca',
      icon: '⚠️'
    }
  };

  const style = styles[kind] || styles.checking;
  el.style.display = 'block';
  el.style.background = style.bg;
  el.style.border = style.border;
  el.style.color = style.color;
  el.innerHTML = `<span style="margin-right:8px;">${style.icon}</span>${escapeHtml(message)}`;
}

async function readApiError(res) {
  const text = await res.text();
  try {
    const parsed = JSON.parse(text);
    if (parsed && parsed.detail) return String(parsed.detail);
    if (parsed && parsed.message) return String(parsed.message);
  } catch (e) {}
  return text || `HTTP ${res.status}`;
}

async function uploadLogoFile(profileId, fileInputId) {
  const input = document.getElementById(fileInputId);
  if (!input || !input.files || !input.files[0]) return;

  const fd = new FormData();
  fd.append('file', input.files[0]);

  const res = await fetch(`/api/dashboard-profiles/${profileId}/logo`, {
    method: 'POST',
    body: fd,
    credentials: 'same-origin'
  });

  if (!res.ok) {
    alert(`Dashboard was created, but logo upload failed. HTTP ${res.status}: ${await res.text()}`);
  }
}


async function createProfile() {
    const payload = {
      name: val('name'),
      company_name: val('company_name'),
      base_url: val('base_url'),
      purpose: val('purpose'),
      description: val('description'),
      api_id: val('api_id'),
      api_key: val('api_key'),
      cp_api_id: val('cp_api_id'),
      cp_api_key: val('cp_api_key')
    };

    setCreateProfileStatus('checking', 'Checking API keys against NCM...');

    let res;
    try {
      res = await fetch('/api/dashboard-profiles', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        credentials:'same-origin',
        body: JSON.stringify(payload)
      });
    } catch (err) {
      setCreateProfileStatus('error', `Could not reach the local NCM Monitor service: ${String(err)}`);
      return;
    }

    if (!res.ok) {
      const msg = await readApiError(res);
      setCreateProfileStatus('error', msg);
      return;
    }

    const created = await res.json();
    setCreateProfileStatus('success', 'API keys validated. Dashboard created successfully.');

    if (created && created.profile_id) {
      await uploadLogoFile(created.profile_id, 'create_logo');
    }

    ['name','company_name','purpose','api_id','api_key','cp_api_id','cp_api_key','description'].forEach(id => {
      const field = document.getElementById(id);
      if (field) field.value = '';
    });

    const logoInput = document.getElementById('create_logo');
    if (logoInput) logoInput.value = '';

    await loadProfiles();
  }

  async function uploadLogo(id) {
  const file = document.getElementById('logo_' + id).files[0];
  if (!file) return alert('Choose a logo first.');

  const fd = new FormData();
  fd.append('file', file);

  const res = await fetch(`/api/dashboard-profiles/${id}/logo`, { method:'POST', body: fd, credentials:'same-origin' });
  if (!res.ok) alert(await res.text());
  await loadProfiles();
}

async function setDefault(id) {
  await fetch(`/api/dashboard-profiles/${id}/set-default`, { method:'POST' });
  localStorage.setItem('ncm_active_profile_id', String(id));
  await loadProfiles();
}

async function togglePause(id, paused) {
  const reason = paused ? prompt('Pause reason?') || 'Paused from Dashboard Management page.' : '';

  const res = await fetch(`/api/dashboard-profiles/${id}/pause`, {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    credentials:'same-origin',
    body: JSON.stringify({paused: !!paused, reason})
  });

  if (!res.ok) {
    alert(await res.text());
    return;
  }

  const result = await res.json();
  alert(result.polling_paused ? 'Polling paused for this dashboard.' : 'Polling resumed for this dashboard.');

  await loadProfiles();
}


function openEditModal(p) {
  document.getElementById('edit_id').value = p.id || '';
  document.getElementById('edit_name').value = p.name || '';
  document.getElementById('edit_company_name').value = p.company_name || '';
  document.getElementById('edit_base_url').value = p.base_url || '';
  document.getElementById('edit_purpose').value = p.purpose || '';
  document.getElementById('edit_description').value = p.description || '';

  // API keys are intentionally not echoed back into the browser.
  document.getElementById('edit_api_id').value = '';
  document.getElementById('edit_api_key').value = '';
  document.getElementById('edit_cp_api_id').value = '';
  document.getElementById('edit_cp_api_key').value = '';

  document.getElementById('editModalBack').style.display = 'flex';
}

function closeEditModal() {
  document.getElementById('editModalBack').style.display = 'none';
}

async function saveProfileEdit() {
  const id = document.getElementById('edit_id').value;

  const payload = {
    name: document.getElementById('edit_name').value,
    company_name: document.getElementById('edit_company_name').value,
    base_url: document.getElementById('edit_base_url').value,
    purpose: document.getElementById('edit_purpose').value,
    description: document.getElementById('edit_description').value
  };

  const api_id = document.getElementById('edit_api_id').value;
  const api_key = document.getElementById('edit_api_key').value;
  const cp_api_id = document.getElementById('edit_cp_api_id').value;
  const cp_api_key = document.getElementById('edit_cp_api_key').value;

  if (api_id) payload.api_id = api_id;
  if (api_key) payload.api_key = api_key;
  if (cp_api_id) payload.cp_api_id = cp_api_id;
  if (cp_api_key) payload.cp_api_key = cp_api_key;

  const res = await fetch(`/api/dashboard-profiles/${id}`, {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  });

  if (!res.ok) {
    alert(await res.text());
    return;
  }

  closeEditModal();
  await loadProfiles();
}

loadProfiles();
</script>
<script src="/api/profile-header.js"></script>
</body>
</html>
    """




@app.get("/api/dashboard-profile/{profile_id}")
async def get_dashboard_profile(profile_id: int):
    ensure_dashboard_profile_tables()

    with global_db() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("""
            SELECT id, name, company_name, description, purpose, logo_path, base_url,
                   is_default, polling_paused, pause_reason, paused_at, created_at, updated_at
            FROM dashboard_profiles
            WHERE id = ?
        """, (profile_id,)).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Dashboard profile not found.")

    return dict(row)


@app.get("/api/dashboard-profiles")
async def list_dashboard_profiles():
    ensure_stock_setup_tables()
    ensure_dashboard_profile_tables()

    with global_db() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT id, name, company_name, description, purpose, logo_path, base_url, is_default,
                   polling_paused, pause_reason, paused_at, created_at, updated_at
            FROM dashboard_profiles
            ORDER BY is_default DESC, name ASC
        """).fetchall()

    return {"profiles": [dict(r) for r in rows], "default_profile_id": get_default_profile_id()}


@app.post("/api/dashboard-profiles")
async def create_dashboard_profile(payload: dict = Body(default={})):
    ensure_dashboard_profile_tables()

    name = str(payload.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Dashboard name is required.")

    company_name = str(payload.get("company_name") or "").strip()
    description = str(payload.get("description") or "").strip()
    purpose = str(payload.get("purpose") or "").strip()
    base_url = str(payload.get("base_url") or "").strip().rstrip("/") or "https://www.us0.cradlepointecm.com"
    api_id = str(payload.get("api_id") or "").strip()
    api_key = str(payload.get("api_key") or "").strip()
    cp_api_id = str(payload.get("cp_api_id") or "").strip()
    cp_api_key = str(payload.get("cp_api_key") or "").strip()
    logo_path = str(payload.get("logo_path") or "").strip()

    missing_fields = []
    if not base_url:
        missing_fields.append("Base URL")
    if not api_id:
        missing_fields.append("X-ECM-API-ID")
    if not api_key:
        missing_fields.append("X-ECM-API-KEY")
    if not cp_api_id:
        missing_fields.append("X-CP-API-ID")
    if not cp_api_key:
        missing_fields.append("X-CP-API-KEY")
    if missing_fields:
        raise HTTPException(
            status_code=400,
            detail="Missing required NCM API credential fields: " + ", ".join(missing_fields)
        )

    credential_check = await validate_ncm_credentials_direct(
        base_url,
        api_id,
        api_key,
        cp_api_id,
        cp_api_key,
    )
    if not credential_check.get("ok"):
        raise HTTPException(
            status_code=400,
            detail=credential_check.get("message") or "NCM API credential validation failed.",
        )

    ts = now_utc()

    with global_db() as conn:
        cur = conn.execute("""
            INSERT INTO dashboard_profiles
            (name, company_name, description, purpose, logo_path, base_url,
             api_id, api_key, cp_api_id, cp_api_key, is_default, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
        """, (name, company_name, description, purpose, logo_path, base_url,
              api_id, api_key, cp_api_id, cp_api_key, ts, ts))
        profile_id = cur.lastrowid

    return {"ok": True, "profile_id": profile_id, "name": name}


@app.post("/api/dashboard-profiles/{profile_id}/pause")
async def pause_dashboard_profile(profile_id: int, payload: dict = Body(default={})):
    ensure_stock_setup_tables()
    ensure_dashboard_profile_tables()

    paused = 1 if payload.get("paused") else 0
    reason = str(payload.get("reason") or "").strip()
    ts = now_utc() if paused else None

    with global_db() as conn:
        conn.execute("""
            UPDATE dashboard_profiles
            SET polling_paused = ?,
                pause_reason = ?,
                paused_at = ?,
                updated_at = ?
            WHERE id = ?
        """, (
            paused,
            reason if paused else None,
            ts,
            now_utc(),
            profile_id,
        ))

        row = conn.execute("""
            SELECT id, name, polling_paused, pause_reason, paused_at, updated_at
            FROM dashboard_profiles
            WHERE id = ?
        """, (profile_id,)).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Dashboard profile not found.")

    return {
        "ok": True,
        "profile_id": profile_id,
        "polling_paused": paused,
        "pause_reason": reason if paused else None,
        "paused_at": ts,
    }



@app.post("/api/pools/{pool_name}/pause")
async def pause_pool_polling(pool_name: str, payload: dict = Body(default={})):
    ensure_dashboard_profile_tables()

    paused = 1 if payload.get("paused") else 0
    reason = str(payload.get("reason") or "").strip()
    paused_at = now_utc() if paused else None
    profile_id = 1

    with db() as conn:
        conn.execute("""
            UPDATE monitoring_pools
            SET polling_paused = ?, pause_reason = ?, paused_at = ?
            WHERE name = ? AND COALESCE(profile_id, 1) = ?
        """, (paused, reason, paused_at, pool_name, profile_id))

    return {"ok": True, "pool": pool_name, "profile_id": profile_id, "polling_paused": paused}


@app.post("/api/routers/{router_id}/pause")
async def pause_router_polling(router_id: str, payload: dict = Body(default={})):
    ensure_dashboard_profile_tables()

    paused = 1 if payload.get("paused") else 0
    reason = str(payload.get("reason") or "").strip()
    paused_at = now_utc() if paused else None
    profile_id = 1

    with db() as conn:
        conn.execute("""
            UPDATE routers
            SET polling_paused = ?, pause_reason = ?, paused_at = ?
            WHERE CAST(id AS TEXT) = ? AND COALESCE(profile_id, 1) = ?
        """, (paused, reason, paused_at, str(router_id), profile_id))

    return {"ok": True, "router_id": router_id, "profile_id": profile_id, "polling_paused": paused}


def should_skip_polling(router_id=None, pool_name=None, profile_id=None):
    """Returns (skip_bool, reason). Background refresh workers should call this before NCM API calls."""
    ensure_dashboard_profile_tables()

    profile_id = 1

    try:
        with db() as conn:
            prof = conn.execute("""
                SELECT polling_paused, pause_reason
                FROM dashboard_profiles
                WHERE id = ?
            """, (profile_id,)).fetchone()

            if prof and int(prof[0] or 0):
                return True, prof[1] or "Dashboard polling is paused."

            if pool_name:
                pool = conn.execute("""
                    SELECT polling_paused, pause_reason
                    FROM monitoring_pools
                    WHERE name = ? AND COALESCE(profile_id, 1) = ?
                """, (pool_name, profile_id)).fetchone()

                if pool and int(pool[0] or 0):
                    return True, pool[1] or "Pool polling is paused."

            if router_id:
                router = conn.execute("""
                    SELECT polling_paused, pause_reason
                    FROM routers
                    WHERE CAST(id AS TEXT) = ? AND COALESCE(profile_id, 1) = ?
                """, (str(router_id), profile_id)).fetchone()

                if router and int(router[0] or 0):
                    return True, router[1] or "Router polling is paused."

    except Exception:
        return False, ""

    return False, ""




def ensure_api_call_counter_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_call_counter (
            profile_id INTEGER PRIMARY KEY,
            lifetime_count INTEGER NOT NULL DEFAULT 0,
            month_key TEXT,
            month_count INTEGER NOT NULL DEFAULT 0,
            today_date TEXT,
            today_count INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT
        )
    """)


def record_api_call(count=1, profile_id=None):
    try:
        now = datetime.now(timezone.utc)
        today = now.date().isoformat()
        month_key = now.strftime("%Y-%m")
        count = int(count or 1)
        profile_id = normalize_profile_id(profile_id)

        with sqlite3.connect(DB_PATH, timeout=2, check_same_thread=False) as conn:
            conn.execute("PRAGMA busy_timeout=2000")
            ensure_api_call_counter_table(conn)

            row = conn.execute("""
                SELECT lifetime_count, month_key, month_count, today_date, today_count
                FROM api_call_counter
                WHERE profile_id = ?
            """, (profile_id,)).fetchone()

            if not row:
                conn.execute("""
                    INSERT INTO api_call_counter
                    (profile_id, lifetime_count, month_key, month_count, today_date, today_count, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (profile_id, count, month_key, count, today, count, now.isoformat()))
                return

            lifetime_count, stored_month, month_count, stored_today, today_count = row

            if stored_month != month_key:
                month_count = 0
            if stored_today != today:
                today_count = 0

            conn.execute("""
                UPDATE api_call_counter
                SET lifetime_count = ?,
                    month_key = ?,
                    month_count = ?,
                    today_date = ?,
                    today_count = ?,
                    updated_at = ?
                WHERE profile_id = ?
            """, (
                int(lifetime_count or 0) + count,
                month_key,
                int(month_count or 0) + count,
                today,
                int(today_count or 0) + count,
                now.isoformat(),
                profile_id,
            ))
    except Exception as exc:
        try:
            print(f"API odometer record failed: {exc}")
        except Exception:
            pass


def get_api_call_counter(profile_id=None):
    try:
        profile_id = normalize_profile_id(profile_id)

        with sqlite3.connect(DB_PATH, timeout=2, check_same_thread=False) as conn:
            conn.execute("PRAGMA busy_timeout=2000")
            ensure_api_call_counter_table(conn)

            row = conn.execute("""
                SELECT lifetime_count, month_key, month_count, today_date, today_count, updated_at
                FROM api_call_counter
                WHERE profile_id = ?
            """, (profile_id,)).fetchone()

            now = datetime.now(timezone.utc)
            current_month = now.strftime("%Y-%m")
            today = now.date().isoformat()

            if not row:
                return {
                    "lifetime": 0,
                    "month": 0,
                    "month_key": current_month,
                    "today": 0,
                    "today_date": today,
                    "updated_at": None,
                }

            lifetime, month_key, month_count, today_date, today_count, updated_at = row

            return {
                "lifetime": int(lifetime or 0),
                "month": int(month_count or 0) if month_key == current_month else 0,
                "month_key": current_month,
                "today": int(today_count or 0) if today_date == today else 0,
                "today_date": today,
                "updated_at": updated_at,
            }
    except Exception:
        return {
            "lifetime": 0,
            "month": 0,
            "month_key": None,
            "today": 0,
            "today_date": None,
            "updated_at": None,
        }


@app.get("/api/odometer")
async def api_odometer(profile_id: int = Query(default=None)):
    return get_api_call_counter(profile_id=profile_id)



@app.get("/api/profile-header.js")
async def profile_header_js():
    js = """
async function loadActiveProfileHeader() {
  try {
    const params = new URLSearchParams(window.location.search);
    const pid = params.get('profile_id') || '1';
    localStorage.setItem('ncm_active_profile_id', pid);
  function currentProfileId() {
    const params = new URLSearchParams(window.location.search);
    return params.get('profile_id') || localStorage.getItem('ncm_active_profile_id') || '1';
  }

  function profileUrl(path) {
    const sep = path.includes('?') ? '&' : '?';
    return path + sep + 'profile_id=' + encodeURIComponent(currentProfileId());
  }


    const res = await fetch('/api/dashboard-profile/' + encodeURIComponent(pid), { cache: 'no-store' });
    if (!res.ok) return;

    const p = await res.json();

    const nameEl = document.getElementById('activeProfileName');
    const companyEl = document.getElementById('activeProfileCompany');
    const purposeEl = document.getElementById('activeProfilePurpose');
    const logoBox = document.getElementById('activeProfileLogoBox');

    if (nameEl) nameEl.textContent = p.name || 'Dashboard';
    if (companyEl) companyEl.textContent = p.company_name || '';
    if (purposeEl) purposeEl.textContent = p.purpose || p.description || '';

    if (logoBox) {
      if (p.logo_path) {
        logoBox.innerHTML = '<img src="' + p.logo_path + '" style="width:100%;height:100%;object-fit:contain;padding:7px;box-sizing:border-box;">';
      } else {
        logoBox.textContent = String(p.name || '?').slice(0,1).toUpperCase();
      }
    }

    document.title = (p.name || 'NCM Monitor') + ' - NCM Monitor';
  } catch (e) {}
}

loadActiveProfileHeader();
"""
    return Response(content=js, media_type="application/javascript")



@app.get("/api/odometer.js")
async def api_odometer_js():
    js = """
async function refreshApiOdometer() {
  try {
    const params = new URLSearchParams(window.location.search);
    const pid = params.get('profile_id') || localStorage.getItem('ncm_active_profile_id') || '';
    const res = await fetch('/api/odometer' + (pid ? '?profile_id=' + encodeURIComponent(pid) : ''), { cache: 'no-store' });
    const data = await res.json();

    const monthEl = document.getElementById('odoMonth');
    const todayEl = document.getElementById('odoToday');
    const lifeEl = document.getElementById('odoLifetime');

    if (monthEl) monthEl.textContent = Number(data.month || 0).toLocaleString();
    if (todayEl) todayEl.textContent = Number(data.today || 0).toLocaleString();
    if (lifeEl) lifeEl.textContent = Number(data.lifetime || 0).toLocaleString();
  } catch (e) {}
}

refreshApiOdometer();
setInterval(refreshApiOdometer, 30000);
"""
    return Response(content=js, media_type="application/javascript")




def get_profile_ncm_context(profile_id=None):
    """Return base URL + headers for the selected dashboard profile.

    Falls back to global NCM_BASE_URL/HEADERS for the original/default dashboard.
    """
    profile_id = normalize_profile_id(profile_id)

    try:
        with global_db() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("""
                SELECT base_url, api_id, api_key, cp_api_id, cp_api_key
                FROM dashboard_profiles
                WHERE id = ?
            """, (profile_id,)).fetchone()

        if row and row["api_id"] and row["api_key"] and row["cp_api_id"] and row["cp_api_key"]:
            base_url = (row["base_url"] or NCM_BASE_URL or "").rstrip("/")
            headers = {
                "X-ECM-API-ID": row["api_id"],
                "X-ECM-API-KEY": row["api_key"],
                "X-CP-API-ID": row["cp_api_id"],
                "X-CP-API-KEY": row["cp_api_key"],
                "Accept": "application/json",
            }
            return base_url, headers, profile_id
    except Exception:
        pass

    return NCM_BASE_URL.rstrip("/"), HEADERS, profile_id


async def ncm_get(path: str, params=None, profile_id=None):
    base_url, headers, active_profile_id = get_profile_ncm_context(profile_id)
    url = f"{base_url}{path}"

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
        record_api_call(profile_id=active_profile_id)  # api odometer
        response = await client.get(url, headers=headers, params=params)

    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=response.text)

    return response.json()



def get_polling_profile_ids(preferred_profile_id=None):
    """Return enabled dashboard profile IDs, with preferred profile first."""
    ensure_dashboard_profile_tables()
    preferred = normalize_profile_id(preferred_profile_id)
    ids = []

    try:
        with global_db() as conn:
            rows = conn.execute("""
                SELECT id
                FROM dashboard_profiles
                WHERE COALESCE(polling_paused, 0) = 0
                  AND api_id IS NOT NULL AND TRIM(api_id) != ''
                  AND api_key IS NOT NULL AND TRIM(api_key) != ''
                  AND cp_api_id IS NOT NULL AND TRIM(cp_api_id) != ''
                  AND cp_api_key IS NOT NULL AND TRIM(cp_api_key) != ''
                ORDER BY CASE WHEN id = ? THEN 0 ELSE 1 END, id
            """, (preferred,)).fetchall()
            ids = [int(r[0]) for r in rows]
    except Exception as e:
        print(f"[profile-fallback] Unable to list polling profiles: {e}")

    if preferred not in ids:
        ids.insert(0, preferred)

    return ids


async def ncm_get_with_profile_fallback(path: str, params=None, preferred_profile_id=None):
    """
    Try the selected dashboard profile first, then other configured profiles.

    Returns: (payload, used_profile_id, errors)
    """
    errors = []
    for pid in get_polling_profile_ids(preferred_profile_id):
        try:
            payload = await ncm_get(path, params=params, profile_id=pid)
            return payload, pid, errors
        except Exception as e:
            msg = str(e)
            errors.append({"profile_id": pid, "error": msg})
            print(f"[profile-fallback] profile={pid} failed for {path}: {msg}")

    raise HTTPException(
        status_code=502,
        detail={
            "message": "NCM request failed for all configured dashboard profiles.",
            "path": path,
            "errors": errors,
        },
    )


async def ncm_get_all(path: str, params=None, max_pages: int = 30, profile_id=None):
    """Fetch paginated NCM v2 data and follow meta.next safely."""
    base_url, headers, active_profile_id = get_profile_ncm_context(profile_id)
    url = f"{base_url}{path}"
    all_rows = []
    page_count = 0

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
        while url and page_count < max_pages:
            record_api_call(profile_id=active_profile_id)  # api odometer
            response = await client.get(url, headers=headers, params=params if page_count == 0 else None)
            if response.status_code >= 400:
                raise HTTPException(status_code=response.status_code, detail=response.text)
            payload = response.json()
            all_rows.extend(payload.get("data", []))
            url = (payload.get("meta") or {}).get("next")
            params = None
            page_count += 1

    return all_rows


def clamp_usage_window(days: int):
    allowed = [7, 15, 30, 90]
    if days not in allowed:
        raise HTTPException(status_code=400, detail="days must be one of 7, 15, 30, or 90")

    # NCM samples top out around 90 days. Use 89d 23h as a safe ceiling to avoid edge-case range errors.
    requested_start = datetime.now(timezone.utc) - timedelta(days=days)
    retention_floor = datetime.now(timezone.utc) - timedelta(days=89, hours=23)
    safe_start = max(requested_start, retention_floor, MONITORING_START_LOCAL.astimezone(timezone.utc))
    return safe_start.isoformat(), now_utc(), safe_start != requested_start


def sum_bytes(rows):
    total_in = sum(float(r.get("bytes_in") or 0) for r in rows)
    total_out = sum(float(r.get("bytes_out") or 0) for r in rows)
    return {"bytes_in": total_in, "bytes_out": total_out, "total_bytes": total_in + total_out}


def bytes_to_mb(value):
    return round(float(value or 0) / (1024 ** 2), 2)


def bytes_to_gb(value):
    return round(float(value or 0) / (1024 ** 3), 3)


def human_bytes(value):
    """Return a human-friendly byte quantity. Uses MB for small report values instead of tiny GB decimals."""
    try:
        num = float(value or 0)
    except Exception:
        num = 0.0

    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    for unit in units:
        if abs(num) < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{num:,.0f} {unit}"
            return f"{num:,.2f} {unit}"
        num /= 1024


def percent(part, whole):
    try:
        part = float(part or 0)
        whole = float(whole or 0)
        return round((part / whole) * 100, 2) if whole else 0
    except Exception:
        return 0


def traffic_direction(bytes_in, bytes_out):
    try:
        b_in = float(bytes_in or 0)
        b_out = float(bytes_out or 0)
    except Exception:
        return "n/a"
    total = b_in + b_out
    if total <= 0:
        return "No usage observed"
    if b_in > b_out * 1.5:
        return "Mostly inbound to the router/site"
    if b_out > b_in * 1.5:
        return "Mostly outbound from the router/site"
    return "Balanced inbound/outbound"


def analyze_router_states(state_rows):
    total_online = 0.0
    total_offline = 0.0
    offline_events = 0
    online_events = 0
    longest_offline = 0.0

    for row in state_rows:
        state = (row.get("state") or "").lower()
        period = float(row.get("period") or 0)
        if state == "offline":
            offline_events += 1
            total_offline += period
            longest_offline = max(longest_offline, period)
        elif state == "online":
            online_events += 1
            total_online += period

    total = total_online + total_offline
    return {
        "online_events": online_events,
        "offline_events": offline_events,
        "online_hours": round(total_online / 3600, 2),
        "offline_hours": round(total_offline / 3600, 2),
        "longest_offline_minutes": round(longest_offline / 60, 1),
        "availability_pct": round((total_online / total) * 100, 2) if total else None,
    }


def usage_story(total_wan, ncm_total, state_summary, avg_signal):
    uncategorized = max(total_wan - ncm_total, 0)
    ncm_pct = round((ncm_total / total_wan) * 100, 2) if total_wan else 0
    uncategorized_pct = round((uncategorized / total_wan) * 100, 2) if total_wan else 0

    avg_rsrp = avg_signal.get("avg_rsrp")
    avg_sinr = avg_signal.get("avg_sinr")
    poor_signal = False
    try:
        poor_signal = (avg_rsrp is not None and float(avg_rsrp) <= -111) or (avg_sinr is not None and float(avg_sinr) < 7)
    except Exception:
        poor_signal = False

    reconnect_churn = state_summary.get("offline_events", 0) >= 5 or state_summary.get("offline_hours", 0) >= 1

    if total_wan == 0:
        narrative = "No WAN usage samples were returned for this window."
    elif ncm_pct >= 25:
        narrative = "NCM/router stream traffic is a meaningful portion of observed WAN usage in this window."
    elif reconnect_churn and poor_signal:
        narrative = "Most usage is uncategorized WAN traffic, but offline churn plus poor RF may be increasing NCM reconnection overhead."
    elif reconnect_churn:
        narrative = "Most usage is uncategorized WAN traffic. NCM state churn is present and may contribute some reconnect overhead."
    else:
        narrative = "Most observed WAN usage is not NCM/router stream traffic. Encapsulated or customer/application traffic is the likely driver."

    return {
        "ncm_percent_of_wan": ncm_pct,
        "uncategorized_percent_of_wan": uncategorized_pct,
        "uncategorized_bytes": uncategorized,
        "uncategorized_gb": bytes_to_gb(uncategorized),
        "reconnect_churn": reconnect_churn,
        "poor_signal": poor_signal,
        "narrative": narrative,
    }


def load_router_lists():
    mapping = {
        "No SDK2": "no_sdk2.txt",
        "S400_7_26_20": "s400_7_26_20.txt",
        "E100_7_26_20": "e100_7_26_20.txt",
        "E100 Swaps": "e100_swaps.txt",
    }

    loaded = []

    with db() as conn:
        for bucket, filename in mapping.items():
            path = os.path.join(ROUTER_LIST_DIR, filename)
            conn.execute(
                """
                INSERT OR IGNORE INTO monitoring_pools(name, description, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (bucket, "Loaded from router list text file.", now_utc(), now_utc()),
            )

            if not os.path.exists(path):
                continue

            with open(path, "r") as f:
                for line in f:
                    router_id = line.strip()
                    if not router_id or router_id.startswith("#"):
                        continue

                    conn.execute(
                        """
                        INSERT OR REPLACE INTO routers(router_id, bucket, last_seen_utc)
                        VALUES (?, ?, COALESCE((SELECT last_seen_utc FROM routers WHERE router_id = ?), ?))
                        """,
                        (router_id, bucket, router_id, now_utc()),
                    )
                    loaded.append({"router_id": router_id, "bucket": bucket})

    return loaded




def ensure_router_inventory_record(router_id: str, profile_id=None, bucket: str = None):
    """
    Ensure a router exists in the selected dashboard/profile router inventory.
    """
    profile_id = normalize_profile_id(profile_id)
    router_id = str(router_id).strip()
    if not router_id:
        return

    bucket = bucket or "Unassigned"

    with db() as conn:
        existing = conn.execute(
              "SELECT bucket FROM routers WHERE router_id = ? AND COALESCE(profile_id, 1) = ?",
              (router_id, profile_id),
        ).fetchone()

        if existing:
            conn.execute(
                """
                UPDATE routers
                  SET last_seen_utc = ?
                  WHERE router_id = ? AND COALESCE(profile_id, 1) = ?
                """,
                  (now_utc(), router_id, profile_id),
            )
        else:
            conn.execute(
                """
                INSERT INTO routers(router_id, bucket, last_seen_utc, profile_id)
                VALUES (?, ?, ?, ?)
                """,
                (router_id, bucket, now_utc(), profile_id),
            )


def backfill_router_inventory_from_local_data(profile_id=None):
    """
    Backfill missing routers from profile-local data tables.

    Useful when a profile has net_devices or net_device_metrics for a router,
    but no row in routers, which prevents global cellular polling from seeing it.
    """
    profile_id = 1
    inserted = 0

    with db() as conn:
        rows = conn.execute("""
            SELECT DISTINCT router_id
            FROM (
                SELECT router_id FROM net_devices WHERE router_id IS NOT NULL AND TRIM(router_id) != ''
                UNION
                SELECT router_id FROM net_device_metrics WHERE router_id IS NOT NULL AND TRIM(router_id) != ''
                UNION
                SELECT router_id FROM alerts WHERE router_id IS NOT NULL AND TRIM(router_id) != ''
                UNION
                SELECT router_id FROM locations WHERE router_id IS NOT NULL AND TRIM(router_id) != ''
            )
        """).fetchall()

        for row in rows:
            router_id = str(row[0]).strip()
            if not router_id:
                continue

            existing = conn.execute(
                "SELECT 1 FROM routers WHERE router_id = ?",
                (router_id,),
            ).fetchone()

            if existing:
                continue

            conn.execute(
                """
                INSERT INTO routers(router_id, bucket, last_seen_utc, profile_id)
                VALUES (?, ?, ?, ?)
                """,
                (router_id, "Auto-discovered", now_utc(), profile_id),
            )
            inserted += 1

    return inserted


async def poll_metrics(router_id: str, net_device_id: str, profile_id=None, radio_context=None):
    """Poll latest net device metrics and persist cell/signal context.

    Important:
    - net_device_metrics must be queried by net_device ID.
    - Results are stored in the selected dashboard/profile DB.
    """
    metrics = await ncm_get(
        "/api/v2/net_device_metrics/",
        {
            "net_device": net_device_id,
            "limit": 20,
        },
        profile_id=profile_id,
    )

    rows = metrics.get("data", []) if isinstance(metrics, dict) else []
    if not rows:
        return {"net_device_id": net_device_id, "saved": False, "reason": "no_metrics_returned"}

    # Prefer the exact matching row when NCM returns more than one.
    row = None
    for candidate in rows:
        if str(candidate.get("id") or "") == str(net_device_id):
            row = candidate
            break
        if str(net_device_id) in str(candidate.get("net_device") or ""):
            row = candidate
            break

    if row is None:
        row = rows[0]

    # net_device_metrics provides signal/cell identity, but some low-level
    # radio attributes are only present on /api/v2/net_devices/.
    # Merge those values into the metric row before storing/event comparison.
    if radio_context:
        for key in RADIO_CONTEXT_FIELDS:
            value = radio_context.get(key)
            if value not in (None, ""):
                row[key] = value

    # If this metric appears to represent a cell/radio change, make sure the
    # signal values attached to the event are fresh enough relative to update_ts.
    row = await maybe_enrich_metric_with_fresh_signal(
        router_id=str(router_id),
        net_device_id=str(net_device_id),
        metric=row,
        profile_id=profile_id,
        stale_threshold_seconds=180,
    )

    with db() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO net_device_metrics(
                net_device_id,
                router_id,
                mcc,
                mnc,
                tac,
                cell_id,
                service_type,
                dbm,
                rsrp,
                rsrq,
                sinr,
                signal_strength,
                rfband,
                rfband5g,
                rfchannel,
                ltebandwidth,
                mtu,
                update_ts
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(net_device_id),
            str(router_id),
            row.get("mcc"),
            row.get("mnc"),
            row.get("tac"),
            row.get("cell_id"),
            row.get("service_type"),
            row.get("dbm"),
            row.get("rsrp"),
            row.get("rsrq"),
            row.get("sinr"),
            row.get("signal_strength"),
            row.get("rfband"),
            row.get("rfband5g"),
            row.get("rfchannel"),
            row.get("ltebandwidth"),
            row.get("mtu"),
            row.get("update_ts") or now_utc(),
        ))

        # v5 Signal History snapshot:
        # net_device_metrics stores only the latest reading. The router graphs read
        # signal_samples, so every successful metric poll should also create a
        # lightweight historical sample.
        try:
            metric_ts = row.get("update_ts") or now_utc()
            sample_id = f"{net_device_id}:{metric_ts}"
            sim_row = conn.execute(
                "SELECT sim_label, uptime FROM net_devices WHERE id = ? LIMIT 1",
                (str(net_device_id),),
            ).fetchone()
            sample_sim_label = None
            sample_uptime = None
            if sim_row:
                try:
                    sample_sim_label = sim_row["sim_label"]
                    sample_uptime = sim_row["uptime"] if "uptime" in sim_row.keys() else None
                except Exception:
                    sample_sim_label = sim_row[0]
                    sample_uptime = sim_row[1] if len(sim_row) > 1 else None

            conn.execute("""
                INSERT OR IGNORE INTO signal_samples(
                    created_at_timeuuid,
                    router_id,
                    net_device_id,
                    sim_label,
                    created_at,
                    dbm,
                    rsrp,
                    rsrq,
                    sinr,
                    signal_percent,
                    uptime
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                sample_id,
                str(router_id),
                str(net_device_id),
                sample_sim_label,
                metric_ts,
                row.get("dbm"),
                row.get("rsrp"),
                row.get("rsrq"),
                row.get("sinr"),
                row.get("signal_strength"),
                sample_uptime,
            ))
        except Exception as exc:
            print(f"[signal-history] Failed to snapshot metric for {net_device_id}: {exc}")

        try:
            cellular_result = record_cellular_metric_event(
                conn,
                router_id=str(router_id),
                net_device_id=str(net_device_id),
                metric=row,
                profile_id=profile_id,
            )
        except Exception as exc:
            cellular_result = {"status": "error", "error": str(exc)}
            print(f"[cellular-monitor] Failed to record event for {net_device_id}: {exc}")

    return {
        "net_device_id": net_device_id,
        "saved": True,
        "cellular_monitor": cellular_result,
    }


async def poll_signal_samples(router_id: str, net_device_id: str, sim_label: str, profile_id=None, days: int = 30):
    """
    v5.0.1:
    Backfill signal history using a true rolling window and pagination.
    A single limit=250 page may only cover part of the 30-day window.
    """
    try:
        days = int(days or 30)
    except Exception:
        days = 30
    days = max(1, min(days, 90))

    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    max_pages = max(4, min(30, int((days + 6) / 7) * 4))

    rows = await ncm_get_all(
        "/api/v2/net_device_signal_samples/",
        {
            "net_device": net_device_id,
            "created_at__gt": since,
            "limit": 250,
        },
        max_pages=max_pages,
        profile_id=profile_id,
    )

    # Defensive local window filter in case API pagination includes older data.
    rows = [
        row for row in rows
        if str(row.get("created_at") or "") >= str(since)
    ]

    saved = 0
    with db() as conn:
        for s in rows:
            conn.execute(
                """
                INSERT OR IGNORE INTO signal_samples(
                    created_at_timeuuid, router_id, net_device_id, sim_label,
                    created_at, dbm, rsrp, rsrq, sinr, signal_percent, uptime
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    s.get("created_at_timeuuid") or s.get("id") or f"{net_device_id}:signal:{s.get('created_at')}",
                    router_id,
                    net_device_id,
                    sim_label,
                    s.get("created_at"),
                    s.get("dbm"),
                    s.get("rsrp"),
                    s.get("rsrq"),
                    s.get("sinr"),
                    s.get("signal_percent"),
                    s.get("uptime"),
                ),
            )
            saved += 1

    return {
        "router_id": str(router_id),
        "net_device_id": str(net_device_id),
        "profile_id": normalize_profile_id(profile_id),
        "days": days,
        "rows_returned": len(rows),
        "rows_saved_attempted": saved,
    }


async def poll_router_stream_usage_samples(router_id: str, profile_id=None, days: int = 30):
    """Poll NCM/router cloud traffic history and cache it locally.

    Endpoint:
      /api/v2/router_stream_usage_samples/?router=<router_id>

    This is router-scoped NCM/cloud traffic, not SIM/carrier usage.
    """
    try:
        days = int(days or 30)
    except Exception:
        days = 30
    days = max(1, min(days, 90))

    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    max_pages = max(1, min(20, int((days + 29) / 30) * 4))

    rows = await ncm_get_all(
        "/api/v2/router_stream_usage_samples/",
        {"router": router_id, "created_at__gt": since, "limit": 250},
        max_pages=max_pages,
        profile_id=profile_id,
    )

    # Some NCM router_stream_usage_samples queries return no rows when
    # created_at__gt is supplied. Retry unfiltered and apply the date window locally.
    if not rows:
        unfiltered = await ncm_get_all(
            "/api/v2/router_stream_usage_samples/",
            {"router": router_id, "limit": 250},
            max_pages=max_pages,
            profile_id=profile_id,
        )
        rows = [
            row for row in unfiltered
            if str(row.get("created_at") or "") >= str(since)
        ]

    saved = 0
    with db() as conn:
        for r in rows:
            created_at = r.get("created_at") or r.get("time") or r.get("timestamp")
            if not created_at:
                continue

            sample_id = str(
                r.get("created_at_timeuuid")
                or r.get("id")
                or f"{router_id}:router_stream:{created_at}"
            )

            bytes_in = float(r.get("bytes_in") or r.get("rx_bytes") or r.get("in_bytes") or r.get("rx") or 0)
            bytes_out = float(r.get("bytes_out") or r.get("tx_bytes") or r.get("out_bytes") or r.get("tx") or 0)

            conn.execute("""
                INSERT OR IGNORE INTO router_stream_usage_samples(
                    created_at_timeuuid,
                    router_id,
                    created_at,
                    bytes_in,
                    bytes_out,
                    total_bytes,
                    period,
                    uptime
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                sample_id,
                str(router_id),
                created_at,
                bytes_in,
                bytes_out,
                bytes_in + bytes_out,
                r.get("period"),
                r.get("uptime"),
            ))
            saved += 1

    return {
        "router_id": str(router_id),
        "profile_id": normalize_profile_id(profile_id),
        "days": days,
        "rows_returned": len(rows),
        "rows_saved": saved,
    }


async def poll_usage_samples(router_id: str, net_device_id: str, sim_label: str, profile_id=None, days: int = 30):
    """
    v5.0.1:
    Backfill carrier/SIM usage using a true rolling window and pagination.
    A single limit=250 page can truncate the visible 30-day usage graph.
    """
    try:
        days = int(days or 30)
    except Exception:
        days = 30
    days = max(1, min(days, 90))

    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    max_pages = max(4, min(30, int((days + 6) / 7) * 4))

    rows = await ncm_get_all(
        "/api/v2/net_device_usage_samples/",
        {
            "net_device": net_device_id,
            "created_at__gt": since,
            "limit": 250,
        },
        max_pages=max_pages,
        profile_id=profile_id,
    )

    # Defensive local window filter in case API pagination includes older data.
    rows = [
        row for row in rows
        if str(row.get("created_at") or row.get("time") or row.get("timestamp") or row.get("update_ts") or "") >= str(since)
    ]

    saved = 0
    with db() as conn:
        for u in rows:
            created_at = u.get("created_at") or u.get("time") or u.get("timestamp") or u.get("update_ts")
            if not created_at:
                continue

            sample_id = str(u.get("created_at_timeuuid") or u.get("id") or f"{net_device_id}:{created_at}")
            bytes_in = u.get("bytes_in") or u.get("rx_bytes") or u.get("in_bytes") or u.get("rx") or 0
            bytes_out = u.get("bytes_out") or u.get("tx_bytes") or u.get("out_bytes") or u.get("tx") or 0

            try:
                total_bytes = float(bytes_in or 0) + float(bytes_out or 0)
            except Exception:
                total_bytes = 0

            conn.execute(
                """
                INSERT OR IGNORE INTO usage_samples(
                    id, router_id, net_device_id, sim_label, created_at, bytes_in, bytes_out, total_bytes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (sample_id, router_id, net_device_id, sim_label, created_at, bytes_in, bytes_out, total_bytes),
            )
            saved += 1

    return {
        "router_id": str(router_id),
        "net_device_id": str(net_device_id),
        "profile_id": normalize_profile_id(profile_id),
        "days": days,
        "rows_returned": len(rows),
        "rows_saved_attempted": saved,
    }


async def reverse_geocode_location(router_id: str, latitude, longitude):
    """Best-effort city/state label for dashboard cards. Falls back gracefully if offline."""
    if latitude is None or longitude is None:
        return
    try:
        async with httpx.AsyncClient(timeout=8.0, headers={"User-Agent": "NCM-Monitor/4.0"}) as client:
            r = await client.get(
                "https://nominatim.openstreetmap.org/reverse",
                params={"format": "jsonv2", "lat": latitude, "lon": longitude, "zoom": 10, "addressdetails": 1},
            )
        if r.status_code >= 400:
            return
        data = r.json()
        addr = data.get("address") or {}
        city = addr.get("city") or addr.get("town") or addr.get("village") or addr.get("hamlet") or addr.get("county")
        state = addr.get("state") or addr.get("region")
        if not city and not state:
            return
        label = ", ".join([x for x in [city, state] if x])
        with db() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO location_labels(router_id, latitude, longitude, city, state, label, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (router_id, latitude, longitude, city, state, label, now_utc()),
            )
    except Exception:
        return


async def poll_router(router_id: str, include_signal: bool = False, profile_id=None):
    target_profile_id = normalize_profile_id(profile_id)
    source_profile_id = target_profile_id
    ensure_router_inventory_record(router_id, profile_id=target_profile_id)

    # Stock build router identity hydration:
    # Pull the router-level product name from NCM, normalize it to a base model,
    # and store the matching local image path for UI rendering.
    try:
        router_payload, source_profile_id, fallback_errors = await ncm_get_with_profile_fallback(
            f"/api/v2/routers/{router_id}/",
            preferred_profile_id=profile_id,
        )
        if source_profile_id != target_profile_id:
            print(f"[profile-fallback] router {router_id} target_profile={target_profile_id} hydrated using source_profile={source_profile_id}")

        router_obj = router_payload
        if isinstance(router_payload, dict):
            data_obj = router_payload.get("data")
            if isinstance(data_obj, dict):
                router_obj = data_obj
            elif isinstance(data_obj, list) and data_obj:
                router_obj = data_obj[0]

        if isinstance(router_obj, dict):
            full_product_name = (
                router_obj.get("full_product_name")
                or router_obj.get("product_name")
                or router_obj.get("model")
                or router_obj.get("product")
            )

            router_model = normalize_router_model(full_product_name)
            router_image_path = router_image_for_product(full_product_name)

            with db() as conn:
                conn.execute(
                    """
                    UPDATE routers
                    SET product_name = ?,
                        router_model = ?,
                        router_image_path = ?,
                        last_seen_utc = ?
                      WHERE router_id = ? AND COALESCE(profile_id, 1) = ?
                    """,
                      (full_product_name, router_model, router_image_path, now_utc(), router_id, target_profile_id),
                )
    except Exception as e:
        print(f"[router-product] Unable to hydrate product info for router {router_id}: {e}")

    backfill_since_utc = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

    alerts = await ncm_get("/api/v2/alerts/", {"router": router_id, "created_at__gt": backfill_since_utc, "limit": 250}, profile_id=source_profile_id)
    net_devices = await ncm_get("/api/v2/net_devices/", {"router": router_id, "limit": 20}, profile_id=source_profile_id)
    locations = await ncm_get("/api/v2/locations/", {"router": router_id, "limit": 1}, profile_id=source_profile_id)

    mdms = []

    with db() as conn:
        conn.execute(
            "UPDATE routers SET last_seen_utc = ? WHERE router_id = ? AND COALESCE(profile_id, 1) = ?",
            (now_utc(), router_id, target_profile_id),
        )

        for item in alerts.get("data", []):
            alert_ts = item.get("created_at") or item.get("detected_at")
            parsed_alert_ts = parse_dt(alert_ts)
            if parsed_alert_ts and parsed_alert_ts.isoformat() < backfill_since_utc:
                continue
            conn.execute(
                """
                INSERT OR IGNORE INTO alerts(
                    created_at_timeuuid, router_id, type, friendly_info, detected_at, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    item.get("created_at_timeuuid"),
                    router_id,
                    item.get("type"),
                    item.get("friendly_info"),
                    item.get("detected_at"),
                    item.get("created_at"),
                ),
            )

        # Replace stale local WAN/SIM interface inventory for this router only.
        # This prevents old modem/module rows from a previous refresh from being
        # rendered as if they are current.
        conn.execute(
            """
            DELETE FROM net_device_metrics
            WHERE router_id = ?
               OR net_device_id IN (
                    SELECT id FROM net_devices WHERE router_id = ?
               )
            """,
            (router_id, router_id),
        )
        conn.execute("DELETE FROM net_devices WHERE router_id = ?", (router_id,))

        for item in net_devices.get("data", []):
            if item.get("type") != "mdm":
                continue

            mfg_product = item.get("mfg_product") or item.get("model") or ""

            # Stock build scope guard:
            # Removable/insertable MC400-style modem modules can expose duplicate
            # SIM1/SIM2 interfaces alongside internal radios. This standard build
            # is intended for fixed router inventory analysis, so skip MC400 module
            # interfaces rather than rendering them as normal WAN/SIM state.
            if "MC400" in mfg_product.upper():
                print(f"[net-devices] Skipping unsupported removable module net_device {item.get('id')} for router {router_id}: {mfg_product}")
                continue

            if "SIM1" in mfg_product.upper():
                sim_label = "SIM1"
            elif "SIM2" in mfg_product.upper():
                sim_label = "SIM2"
            else:
                sim_label = "UNKNOWN"

            net_device_id = str(item.get("id"))

            conn.execute(
                """
                INSERT OR REPLACE INTO net_devices(
                    id, router_id, sim_label, carrier, connection_state,
                    service_type, mfg_product, updated_at, uptime
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    net_device_id,
                    router_id,
                    sim_label,
                    item.get("carrier"),
                    item.get("connection_state"),
                    item.get("service_type"),
                    item.get("mfg_product"),
                    item.get("updated_at"),
                    item.get("uptime"),
                ),
            )

            radio_context = {
                "rfband": item.get("rfband"),
                "rfband5g": item.get("rfband5g"),
                "rfchannel": item.get("rfchannel"),
                "ltebandwidth": item.get("ltebandwidth"),
                "mtu": item.get("mtu"),
            }

            mdms.append((net_device_id, sim_label, radio_context))

        loc_data = locations.get("data", [])
        location_to_label = None
        if loc_data:
            loc = loc_data[0]
            location_to_label = (loc.get("latitude"), loc.get("longitude"))
            conn.execute(
                """
                INSERT OR REPLACE INTO locations(
                    router_id, latitude, longitude, accuracy, method, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    router_id,
                    loc.get("latitude"),
                    loc.get("longitude"),
                    loc.get("accuracy"),
                    loc.get("method"),
                    loc.get("updated_at"),
                ),
            )

    if location_to_label:
        try:
            await reverse_geocode_location(router_id, location_to_label[0], location_to_label[1])
        except Exception:
            pass

    for net_device_id, sim_label, radio_context in mdms:
        try:
            # Use the same source profile that successfully read router/net_device data.
            # This prevents profile 1/test credentials from breaking signal metrics for
            # routers owned by another dashboard profile.
            await poll_metrics(router_id, net_device_id, profile_id=source_profile_id, radio_context=radio_context)
        except Exception as exc:
            print(f"[metrics] Failed polling net_device_metrics router={router_id} net_device={net_device_id} profile={source_profile_id}: {exc}")

        if include_signal:
            try:
                await poll_signal_samples(router_id, net_device_id, sim_label, profile_id=source_profile_id)
            except Exception as exc:
                print(f"[signal-samples] Failed polling historical samples router={router_id} net_device={net_device_id} profile={source_profile_id}: {exc}")

            try:
                await poll_usage_samples(router_id, net_device_id, sim_label, profile_id=source_profile_id)
            except Exception as exc:
                print(f"[usage-samples] Failed polling usage samples router={router_id} net_device={net_device_id} profile={source_profile_id}: {exc}")

    if include_signal:
        try:
            await poll_router_stream_usage_samples(router_id, profile_id=source_profile_id, days=30)
        except Exception as exc:
            print(f"[router-stream-usage] Failed polling NCM cloud traffic router={router_id} profile={source_profile_id}: {exc}")

    evaluate_router_issues(router_id)
    return {"router_id": router_id, "status": "polled", "include_signal": include_signal, "mdms": len(mdms)}






def get_cellular_monitor_profile_ids():
    """
    Return all dashboard profile IDs that should be considered by the cellular monitor.
    Paused profiles are returned too; cellular_global_monitor_once() will skip them
    cleanly and report the pause reason.
    """
    ensure_dashboard_profile_tables()

    profile_ids = []

    try:
        with global_db() as conn:
            rows = conn.execute("""
                SELECT id
                FROM dashboard_profiles
                ORDER BY id
            """).fetchall()

            profile_ids = [int(row[0]) for row in rows if row and row[0] is not None]
    except Exception as exc:
        print(f"[cellular-monitor] Failed to load dashboard profiles: {exc}")

    if not profile_ids:
        profile_ids = [int(get_default_profile_id())]

    return profile_ids


async def cellular_global_monitor_once(profile_id=None, include_signal: bool = False):
    """
    Poll all eligible routers once.

    Cellular event detection happens inside poll_metrics(), so this worker only
    needs to trigger normal router polling.
    """
    profile_id = 1
    ensure_cellular_monitor_tables(profile_id)

    routers_to_poll = []

    # Check profile-level pause from the global profile DB.
    try:
        with global_db() as gconn:
            profile = gconn.execute("""
                SELECT polling_paused, pause_reason
                FROM dashboard_profiles
                WHERE id = ?
            """, (profile_id,)).fetchone()

            if profile and int(profile[0] or 0):
                return {
                    "ok": True,
                    "profile_id": profile_id,
                    "status": "skipped",
                    "reason": profile[1] or "Dashboard polling is paused.",
                    "routers": 0,
                    "polled": 0,
                    "errors": 0,
                }
    except Exception:
        pass

    with db() as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute("""
            SELECT
                r.router_id,
                r.bucket,
                COALESCE(r.polling_paused, 0) AS router_paused,
                r.pause_reason AS router_pause_reason,
                COALESCE(mp.polling_paused, 0) AS pool_paused,
                mp.pause_reason AS pool_pause_reason
            FROM routers r
            LEFT JOIN monitoring_pools mp
              ON mp.name = r.bucket
             AND COALESCE(mp.profile_id, 1) = ?
            WHERE r.router_id IS NOT NULL
              AND TRIM(r.router_id) != ''
              AND COALESCE(r.profile_id, 1) = ?
            ORDER BY r.bucket, r.router_id
        """, (profile_id, profile_id)).fetchall()

        for row in rows:
            if int(row["router_paused"] or 0):
                continue
            if int(row["pool_paused"] or 0):
                continue

            routers_to_poll.append({
                "router_id": str(row["router_id"]),
                "bucket": row["bucket"],
            })

    total_routers = len(routers_to_poll)
    batch_size = max(1, int(CELLULAR_GLOBAL_BATCH_SIZE or 50))

    with db() as conn:
        cursor_row = conn.execute(
            "SELECT value FROM poll_state WHERE key = ?",
            ("cellular_global_monitor_cursor",),
        ).fetchone()

    try:
        cursor = int(cursor_row[0]) if cursor_row else 0
    except Exception:
        cursor = 0

    if total_routers == 0:
        selected = []
        next_cursor = 0
    else:
        cursor = cursor % total_routers
        selected = []
        for i in range(min(batch_size, total_routers)):
            selected.append(routers_to_poll[(cursor + i) % total_routers])
        next_cursor = (cursor + len(selected)) % total_routers

    result = {
        "ok": True,
        "profile_id": profile_id,
        "status": "complete",
        "routers_available": total_routers,
        "batch_size": batch_size,
        "cursor_start": cursor,
        "cursor_next": next_cursor,
        "polled": 0,
        "errors": 0,
        "details": [],
    }

    completed_cursor = cursor

    for index, item in enumerate(selected):
        router_id = item["router_id"]

        try:
            poll_result = await asyncio.wait_for(
                poll_router(
                    router_id,
                    include_signal=include_signal,
                    profile_id=profile_id,
                ),
                timeout=CELLULAR_ROUTER_POLL_TIMEOUT_SECONDS,
            )
            result["polled"] += 1
            result["details"].append(poll_result)

        except asyncio.CancelledError:
            # Persist progress before allowing shutdown/restart to continue.
            with db() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO poll_state(key, value) VALUES (?, ?)",
                    ("cellular_global_monitor_cursor", str(completed_cursor)),
                )
                conn.execute(
                    "INSERT OR REPLACE INTO poll_state(key, value) VALUES (?, ?)",
                    ("cellular_global_monitor_last_cancelled", now_utc()),
                )
            print("[cellular-monitor] Global batch cancelled cleanly during shutdown")
            raise

        except asyncio.TimeoutError:
            result["errors"] += 1
            result["details"].append({
                "router_id": router_id,
                "status": "timeout",
                "error": f"poll_router exceeded {CELLULAR_ROUTER_POLL_TIMEOUT_SECONDS}s",
            })
            print(f"[cellular-monitor] Global poll timed out for router {router_id}")

        except Exception as exc:
            result["errors"] += 1
            result["details"].append({
                "router_id": router_id,
                "status": "error",
                "error": str(exc),
            })
            print(f"[cellular-monitor] Global poll failed for router {router_id}: {exc}")

        completed_cursor = (cursor + index + 1) % total_routers if total_routers else 0

        # Persist progress after every router so restarts never lose the cursor.
        with db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO poll_state(key, value) VALUES (?, ?)",
                ("cellular_global_monitor_cursor", str(completed_cursor)),
            )
            conn.execute(
                "INSERT OR REPLACE INTO poll_state(key, value) VALUES (?, ?)",
                ("cellular_global_monitor_last_progress", now_utc()),
            )

        # Small throttle so we do not burst the NCM API too aggressively.
        try:
            await asyncio.sleep(0.25)
        except asyncio.CancelledError:
            print("[cellular-monitor] Global batch cancelled cleanly during throttle")
            raise

    with db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO poll_state(key, value) VALUES (?, ?)",
            ("cellular_global_monitor_cursor", str(next_cursor)),
        )
        conn.execute(
            "INSERT OR REPLACE INTO poll_state(key, value) VALUES (?, ?)",
            ("cellular_global_monitor_last_run", now_utc()),
        )
        conn.execute(
            "INSERT OR REPLACE INTO poll_state(key, value) VALUES (?, ?)",
            ("cellular_global_monitor_last_result", str({
                "routers_available": result["routers_available"],
                "batch_size": result["batch_size"],
                "cursor_start": result["cursor_start"],
                "cursor_next": result["cursor_next"],
                "polled": result["polled"],
                "errors": result["errors"],
            })),
        )

    return result


async def cellular_global_monitor_loop():
    await asyncio.sleep(15)

    while True:
        try:
            if CELLULAR_MONITOR_ENABLED and CELLULAR_GLOBAL_MONITOR_ENABLED:
                profile_ids = get_cellular_monitor_profile_ids()

                print(f"[cellular-monitor] Starting global cellular monitor cycle for profiles={profile_ids}")

                for profile_id in profile_ids:
                    try:
                        print(f"[cellular-monitor] Starting cellular batch for profile {profile_id}")
                        result = await cellular_global_monitor_once(profile_id=profile_id, include_signal=False)

                        print(
                            "[cellular-monitor] Profile batch complete: "
                            f"profile={profile_id} "
                            f"status={result.get('status')} "
                            f"available={result.get('routers_available', result.get('routers'))} "
                            f"batch={result.get('batch_size')} "
                            f"cursor={result.get('cursor_start')}->{result.get('cursor_next')} "
                            f"polled={result.get('polled')} "
                            f"errors={result.get('errors')} "
                            f"reason={result.get('reason', '')}"
                        )

                    except asyncio.CancelledError:
                        print(f"[cellular-monitor] Global monitor cancelled while processing profile {profile_id}")
                        raise

                    except Exception as exc:
                        print(f"[cellular-monitor] Profile {profile_id} batch failed: {exc}")

                    # Tiny pause between profiles so multi-profile cycles do not burst all at once.
                    await asyncio.sleep(1)

        except asyncio.CancelledError:
            print("[cellular-monitor] Global monitor loop cancelled cleanly")
            raise

        except Exception as exc:
            print(f"[cellular-monitor] Global monitor loop failed: {exc}")

        await asyncio.sleep(CELLULAR_POLL_INTERVAL_SECONDS)


def get_recent_counts(conn, router_id: str):
    since_12h = (datetime.now(timezone.utc) - timedelta(hours=12)).isoformat()
    since_30d = max((datetime.now(timezone.utc) - timedelta(days=30)).isoformat(), MONITORING_START_UTC)

    reboot_12h = conn.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE router_id = ?
          AND created_at >= ?
          AND type = 'reboot_status_change'
    """, (router_id, since_12h)).fetchone()[0]

    wan_disc_12h = conn.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE router_id = ?
          AND created_at >= ?
          AND type = 'modem_wan_disconnected'
    """, (router_id, since_12h)).fetchone()[0]

    offline_recent = conn.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE router_id = ?
          AND created_at >= ?
          AND type = 'connection_state'
          AND LOWER(friendly_info) LIKE '%offline%'
    """, (router_id, since_12h)).fetchone()[0]

    latest_alert = conn.execute("""
        SELECT type, friendly_info, created_at, detected_at
        FROM alerts
        WHERE router_id = ?
          AND created_at >= ?
        ORDER BY created_at DESC
        LIMIT 1
    """, (router_id, MONITORING_START_UTC)).fetchone()

    reboot_30d = conn.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE router_id = ?
          AND created_at >= ?
          AND type = 'reboot_status_change'
    """, (router_id, since_30d)).fetchone()[0]

    return {
        "reboot_12h": reboot_12h,
        "wan_disc_12h": wan_disc_12h,
        "offline_recent": offline_recent,
        "latest_alert": latest_alert,
        "reboot_30d": reboot_30d,
    }


def store_power_cycle_indicators(conn, router_id: str):
    """
    Deprecated/disabled.

    Store power-cycle inference was too customer/site-pattern specific and could
    create misleading conclusions. Keep this function as a no-op so older call
    sites do not break, but stop generating new store power-cycle indicators.
    """
    return {
        "enabled": False,
        "status": "disabled",
        "reason": "store_power_cycle_indicators deprecated"
    }

def overnight_offline_store_power_indicator(conn, router_id: str):
    """
    Detects recurring operational timing patterns:
    - connection_state offline during evening/night local time
    - next online state occurs the following morning
    - offline duration is roughly overnight, default 7-14 hours
    """
    since_30d = max((datetime.now(timezone.utc) - timedelta(days=30)).isoformat(), MONITORING_START_UTC)

    rows = conn.execute("""
        SELECT type, friendly_info, created_at, detected_at
        FROM alerts
        WHERE router_id = ?
          AND created_at >= ?
          AND type = 'connection_state'
        ORDER BY created_at ASC
    """, (router_id, since_30d)).fetchall()

    events = []
    for row in rows:
        info = (row[1] or '').lower()
        state = None
        if 'offline' in info:
            state = 'offline'
        elif 'online' in info:
            state = 'online'
        if not state:
            continue
        dt = parse_dt(row[2]) or parse_dt(row[3])
        if not dt:
            continue
        local_dt = dt.astimezone(LOCAL_TZ)
        events.append({
            'state': state,
            'utc': dt,
            'local': local_dt,
            'display': local_dt.strftime('%Y-%m-%d %H:%M:%S %Z'),
        })

    pairs = []
    last_offline = None
    for event in events:
        if event['state'] == 'offline':
            last_offline = event
        elif event['state'] == 'online' and last_offline:
            duration_hours = (event['utc'] - last_offline['utc']).total_seconds() / 3600
            off_hour = last_offline['local'].hour
            on_hour = event['local'].hour
            crosses_day = event['local'].date() > last_offline['local'].date()
            if crosses_day and 7 <= duration_hours <= 14 and (18 <= off_hour or off_hour <= 2) and 5 <= on_hour <= 11:
                pairs.append({
                    'offline': last_offline['display'],
                    'online': event['display'],
                    'duration_hours': round(duration_hours, 1),
                })
            last_offline = None

    return {
        'likely': len(pairs) >= 1,
        'count': len(pairs),
        'examples': pairs[-5:],
    }


def likely_store_power_cycle(conn, router_id: str):
    """
    Deprecated/disabled.

    Store power-cycle inference is intentionally disabled because it was too
    customer/site-pattern specific.
    """
    return False


def upsert_issue(conn, router_id, issue_type, severity, summary):
    if issue_type == "store_power_cycle_indicators" or severity == "store_power_cycle":
        return

    existing = conn.execute("""
        SELECT id FROM issues
        WHERE router_id = ?
          AND issue_type = ?
          AND status = 'open'
        LIMIT 1
    """, (router_id, issue_type)).fetchone()

    ts = now_utc()
    if existing:
        conn.execute("""
            UPDATE issues
            SET severity = ?, summary = ?, last_seen = ?
            WHERE id = ?
        """, (severity, summary, ts, existing[0]))
    else:
        conn.execute("""
            INSERT INTO issues(router_id, issue_type, severity, status, summary, first_seen, last_seen)
            VALUES (?, ?, ?, 'open', ?, ?, ?)
        """, (router_id, issue_type, severity, summary, ts, ts))


def evaluate_router_issues(router_id: str):
    with db() as conn:
        conn.row_factory = sqlite3.Row

        sims = conn.execute("""
            SELECT connection_state FROM net_devices
            WHERE router_id = ?
        """, (router_id,)).fetchall()

        has_any_wan = len(sims) > 0
        has_connected_wan = any((s["connection_state"] or "").lower() == "connected" for s in sims)
        counts = get_recent_counts(conn, router_id)
        store_cycle_info = store_power_cycle_indicators(conn, router_id)
        overnight_info = overnight_offline_store_power_indicator(conn, router_id)
        store_cycle = store_cycle_info.get("likely", False) or overnight_info.get("likely", False)

        if store_cycle:
            summary_parts = []
            if store_cycle_info.get("likely"):
                part = (
                    f"Recurring morning reboot pattern: {store_cycle_info.get('count', 0)} reboot events "
                    f"across {store_cycle_info.get('distinct_days', 0)} local days."
                )
                summary_parts.append(part)
            if overnight_info.get("likely"):
                ex = overnight_info.get("examples", [])[-1]
                if ex:
                    summary_parts.append(
                        f"Overnight offline-to-morning-online pattern detected; last observed duration was approximately {ex.get('duration_hours')} hours."
                    )
                else:
                    summary_parts.append("Overnight offline-to-morning-online pattern detected")

            summary = "Operational timing indicators: " + " | ".join(summary_parts)
            upsert_issue(conn, router_id, "store_power_cycle_indicators", "store_power_cycle", summary)

        # Needs Review: fully offline / no connected WAN.
        # This replaces the old "Critical" language.
        if has_any_wan and not has_connected_wan:
            upsert_issue(
                conn,
                router_id,
                "no_connected_wan",
                "needs_review",
                "No modem WAN is currently connected."
            )

        # Needs Review: daytime reboot during broad business window, unless the router already
        # has recurring store-power-cycle indicators. A 9-11 AM reboot can be normal store opening
        # behavior when it repeats consistently across days.
        latest_reboot = conn.execute("""
            SELECT created_at FROM alerts
            WHERE router_id = ?
              AND type = 'reboot_status_change'
            ORDER BY created_at DESC
            LIMIT 1
        """, (router_id,)).fetchone()

        if latest_reboot and not store_cycle:
            hour = to_local_hour(latest_reboot[0])
            if hour is not None and 9 <= hour <= 15:
                upsert_issue(
                    conn,
                    router_id,
                    "business_hours_reboot",
                    "needs_review",
                    "Reboot occurred during the 9 AM - 3 PM local review window."
                )

        # Watch/Needs Review: repeated reboots. If the pattern matches store-power-cycle indicators,
        # keep it out of Watch/Needs Review and classify it separately.
        if counts["reboot_12h"] > 2 and not store_cycle:
            summary = f"{counts['reboot_12h']} reboots detected in the last 12 hours."
            upsert_issue(conn, router_id, "repeated_reboots_12h", "needs_review", summary)

        if counts["wan_disc_12h"] > 3 and has_connected_wan:
            upsert_issue(
                conn,
                router_id,
                "repeated_wan_disconnects_12h",
                "watch",
                f"{counts['wan_disc_12h']} modem WAN disconnect alerts detected in the last 12 hours."
            )


async def refresh_population(include_signal: bool = False):
    with db() as conn:
        router_ids = [r[0] for r in conn.execute("SELECT router_id FROM routers ORDER BY bucket, router_id").fetchall()]

    results = []
    # Keep this sequential to avoid API spikes.
    for router_id in router_ids:
        try:
            results.append(await poll_router(router_id, include_signal=include_signal))
        except Exception as e:
            results.append({"router_id": router_id, "status": "error", "error": str(e)})

    with db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO poll_state(key, value) VALUES (?, ?)",
            ("last_refresh_all_signal" if include_signal else "last_refresh_all_fast", now_utc()),
        )

    return {"count": len(results), "include_signal": include_signal, "results": results[:25]}


def parse_router_ids(text_or_list):
    """Accept pasted text, CSV-ish text, or a JSON list and return unique router IDs."""
    if isinstance(text_or_list, list):
        raw_items = [str(x) for x in text_or_list]
    else:
        raw = str(text_or_list or "")
        for ch in [",", ";", "\t", "\r"]:
            raw = raw.replace(ch, "\n")
        raw_items = raw.split("\n")

    seen = set()
    router_ids = []
    for item in raw_items:
        rid = item.strip()
        if not rid or rid.startswith("#"):
            continue
        rid = rid.split()[0].strip()
        if rid and rid not in seen:
            seen.add(rid)
            router_ids.append(rid)
    return router_ids


def pool_counts(conn, profile_id=None):
    """Return monitoring pool counts scoped to the selected dashboard/profile."""
    conn.row_factory = sqlite3.Row
    profile_id_filter = normalize_profile_id(profile_id)

    rows = conn.execute("""
        WITH raw_pool_names AS (
            SELECT
                name,
                COALESCE(description, '') AS description,
                created_at,
                updated_at
            FROM monitoring_pools
            WHERE COALESCE(profile_id, 1) = ?

            UNION ALL

            SELECT
                bucket AS name,
                '' AS description,
                NULL AS created_at,
                NULL AS updated_at
            FROM routers
            WHERE COALESCE(profile_id, 1) = ?
              AND bucket IS NOT NULL
              AND bucket != ''
        ),
        pool_names AS (
            SELECT
                name,
                MAX(description) AS description,
                MAX(created_at) AS created_at,
                MAX(updated_at) AS updated_at
            FROM raw_pool_names
            WHERE name IS NOT NULL AND name != ''
            GROUP BY name
        )
        SELECT
            pn.name,
            pn.description,
            pn.created_at,
            pn.updated_at,
            COUNT(DISTINCT r.router_id) AS router_count
        FROM pool_names pn
        LEFT JOIN routers r
          ON r.bucket = pn.name
         AND COALESCE(r.profile_id, 1) = ?
        GROUP BY pn.name, pn.description, pn.created_at, pn.updated_at
        ORDER BY pn.name COLLATE NOCASE
    """, (profile_id_filter, profile_id_filter, profile_id_filter)).fetchall()

    return [dict(r) for r in rows]


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    if not setup_complete():
        return RedirectResponse(url="/setup", status_code=303)
    if not login_required(request):
        return RedirectResponse(url="/login", status_code=303)
    return RedirectResponse(url="/launcher", status_code=303)


@app.get("/health")
async def health():
    return {
        "app": "ok",
        "base_url": NCM_BASE_URL,
        "local_timezone": LOCAL_TZ_NAME,
        "monitoring_start_local": MONITORING_START_LOCAL.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "monitoring_start_utc": MONITORING_START_UTC,
        "auth_headers_present": all(HEADERS.values()),
    }


@app.get("/test/router/{router_id}")
async def test_router(router_id: int):
    return await ncm_get(f"/api/v2/routers/{router_id}/")


@app.get("/test/alerts/{router_id}")
async def test_alerts(router_id: int):
    return await ncm_get("/api/v2/alerts/", {"router": router_id, "created_at__gt": MONITORING_START_UTC, "limit": 5})


@app.get("/test/net-devices/{router_id}")
async def test_net_devices(router_id: int, profile_id: int = Query(default=None)):
    profile_id_filter = normalize_profile_id(profile_id)
    return await ncm_get(
        "/api/v2/net_devices/",
        {"router": router_id, "limit": 20},
        profile_id=profile_id_filter,
    )


@app.get("/test/location/{router_id}")
async def test_location(router_id: int):
    return await ncm_get("/api/v2/locations/", {"router": router_id, "limit": 5})


@app.get("/test/net-device-metrics/{net_device_id}")
async def test_net_device_metrics(net_device_id: int, profile_id: int = Query(default=None)):
    profile_id_filter = normalize_profile_id(profile_id)
    return await ncm_get(
        "/api/v2/net_device_metrics/",
        {"net_device": net_device_id, "limit": 20},
        profile_id=profile_id_filter,
    )


@app.get("/test/router-logs/{router_id}")
async def test_router_logs(
    router_id: int,
    days: int = Query(7, ge=1, le=90),
    profile_id: int = Query(default=None),
):
    profile_id_filter = normalize_profile_id(profile_id)
    since_dt = datetime.now(timezone.utc) - timedelta(days=days)
    since = since_dt.isoformat().replace("+00:00", "Z")

    return await ncm_get(
        "/api/v2/router_logs/",
        {
            "router": router_id,
            "created_at__gt": since,
            "limit": 20,
        },
        profile_id=profile_id_filter,
    )


def router_log_days_to_since(days: int):
    """Convert allowed router-log date windows into a UTC created_at lower bound."""
    allowed_days = {1, 7, 14, 30, 90}
    if int(days) not in allowed_days:
        raise HTTPException(status_code=400, detail="days must be one of: 1, 7, 14, 30, 90")

    since_dt = datetime.now(timezone.utc) - timedelta(days=int(days))
    return since_dt.isoformat().replace("+00:00", "Z")


def normalize_router_log_row(row: dict):
    """Return a UI/export-friendly router log row."""
    return {
        "reported_at": row.get("reported_at"),
        "reported_at_local": to_local_string(row.get("reported_at")),
        "created_at": row.get("created_at"),
        "created_at_local": to_local_string(row.get("created_at")),
        "level": row.get("level"),
        "source": row.get("source"),
        "message": row.get("message"),
        "exception": row.get("exception"),
        "sequence": row.get("sequence"),
        "created_at_timeuuid": row.get("created_at_timeuuid"),
    }


def parse_router_log_dt(value):
    """Parse NCM/router ISO timestamps safely as UTC-aware datetimes."""
    if not value:
        return None
    try:
        raw = str(value).strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def router_log_cache_key(profile_id, router_id, row: dict) -> str:
    """Build a stable local dedupe key for router logs."""
    explicit = row.get("created_at_timeuuid") or row.get("id") or row.get("uuid")
    if explicit:
        return str(explicit)

    raw = "|".join([
        str(profile_id or ""),
        str(router_id or ""),
        str(row.get("reported_at") or ""),
        str(row.get("created_at") or ""),
        str(row.get("level") or ""),
        str(row.get("source") or ""),
        str(row.get("sequence") or ""),
        str(row.get("message") or ""),
    ])
    return hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()


def store_router_log_rows(raw_rows, profile_id, router_id):
    """Cache router logs locally so graph event context can be queried later."""
    if not raw_rows:
        return 0

    profile_id = normalize_profile_id(profile_id)
    router_id = str(router_id)
    fetched_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    records = []
    for row in raw_rows:
        if not isinstance(row, dict):
            continue
        records.append((
            profile_id,
            router_log_cache_key(profile_id, router_id, row),
            router_id,
            row.get("reported_at"),
            row.get("created_at"),
            row.get("level"),
            row.get("source"),
            row.get("message"),
            row.get("exception"),
            str(row.get("sequence")) if row.get("sequence") is not None else None,
            row.get("created_at_timeuuid"),
            fetched_at,
        ))

    if not records:
        return 0

    with db() as conn:
        before = conn.total_changes
        conn.executemany("""
            INSERT OR IGNORE INTO router_logs (
                profile_id,
                log_key,
                router_id,
                reported_at,
                created_at,
                level,
                source,
                message,
                exception,
                sequence,
                created_at_timeuuid,
                fetched_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, records)
        return conn.total_changes - before


async def fetch_and_cache_router_logs_window(
    router_id,
    profile_id,
    since,
    until=None,
    limit=1000,
    max_pages=25,
):
    """Fetch router logs from NCM with offset paging and cache each page.

    NCM can return the earliest rows in a requested window. On noisy routers, a
    single 500/1000-row response may not reach the newest logs for the day.
    This helper walks pages using offset where supported and stops if the API
    repeats a page.
    """
    profile_id_filter = normalize_profile_id(profile_id)
    router_id_str = str(router_id)

    # NCM router_logs appears to cap responses at 500 rows even when a higher
    # limit is requested. Use 500 as the effective page size so offset paging
    # can continue instead of stopping after the first capped response.
    page_limit = 500

    all_rows = []
    total_cached = 0
    seen_page_signatures = set()
    last_meta = {}
    live_fetch_error = None

    for page in range(int(max_pages or 1)):
        params = {
            "router": router_id_str,
            "created_at__gt": since,
            "limit": page_limit,
        }
        if until:
            params["created_at__lt"] = until
        if page > 0:
            params["offset"] = page * page_limit

        try:
            payload = await ncm_get(
                "/api/v2/router_logs/",
                params,
                profile_id=profile_id_filter,
            )
        except Exception as exc:
            live_fetch_error = str(exc)
            break

        rows = payload.get("data", []) if isinstance(payload, dict) else []
        last_meta = payload.get("meta", {}) if isinstance(payload, dict) else {}

        if not rows:
            break

        # Detect repeated pages in case the endpoint ignores offset.
        first = rows[0] if isinstance(rows[0], dict) else {}
        last = rows[-1] if isinstance(rows[-1], dict) else {}
        signature = (
            str(first.get("created_at_timeuuid") or first.get("id") or first.get("uuid") or ""),
            str(first.get("reported_at") or ""),
            str(first.get("created_at") or ""),
            str(first.get("message") or "")[:120],
            str(last.get("created_at_timeuuid") or last.get("id") or last.get("uuid") or ""),
            str(last.get("reported_at") or ""),
            str(last.get("created_at") or ""),
            str(last.get("message") or "")[:120],
            str(len(rows)),
        )
        if signature in seen_page_signatures:
            break
        seen_page_signatures.add(signature)

        all_rows.extend(rows)
        total_cached += store_router_log_rows(rows, profile_id_filter, router_id_str)

        if len(rows) < page_limit:
            break

    return {
        "rows": all_rows,
        "fetched_count": len(all_rows),
        "cached_count": total_cached,
        "pages": len(seen_page_signatures),
        "meta": last_meta,
        "live_fetch_error": live_fetch_error,
    }


def normalize_cached_router_log_row(row, event_dt=None):
    """Return cached router log with local time and optional event delta."""
    item = dict(row)
    log_dt = parse_router_log_dt(item.get("reported_at") or item.get("created_at"))

    item["reported_at_local"] = to_local_string(item.get("reported_at"))
    item["created_at_local"] = to_local_string(item.get("created_at"))
    item["log_time"] = (log_dt.isoformat().replace("+00:00", "Z") if log_dt else (item.get("reported_at") or item.get("created_at")))
    item["log_time_local"] = to_local_string(item.get("reported_at") or item.get("created_at"))

    if event_dt and log_dt:
        item["delta_seconds"] = int((log_dt - event_dt).total_seconds())
    else:
        item["delta_seconds"] = None

    item["closest"] = False
    item["closest_before"] = False
    item["closest_after"] = False
    return item


@app.get("/router-logs/{router_id}")
async def api_router_logs(
    router_id: int,
    days: int = Query(7, ge=1, le=90),
    profile_id: int = Query(default=None),
    limit: int = Query(250, ge=20, le=1000),
):
    """Fetch latest available router logs for the selected dashboard profile.

    The live NCM response is cached first, then the modal is populated from the
    local router_logs cache. This keeps the standalone Router Logs button aligned
    with Event Context, which already relies on cached rows and local timestamp
    filtering.
    """
    profile_id_filter = normalize_profile_id(profile_id)
    since = router_log_days_to_since(days)
    since_dt = parse_router_log_dt(since)

    fetched_live_count = 0
    cached_count = 0
    live_fetch_error = None
    meta = {}

    fetch_result = await fetch_and_cache_router_logs_window(
        router_id=router_id,
        profile_id=profile_id_filter,
        since=since,
        until=None,
        limit=max(int(limit or 1000), 1000),
        max_pages=25,
    )
    fetched_live_count = fetch_result.get("fetched_count", 0)
    cached_count = fetch_result.get("cached_count", 0)
    meta = fetch_result.get("meta", {}) or {}
    live_fetch_error = fetch_result.get("live_fetch_error")

    with db() as conn:
        conn.row_factory = sqlite3.Row
        candidate_rows = conn.execute("""
            SELECT
                profile_id,
                log_key,
                router_id,
                reported_at,
                created_at,
                level,
                source,
                message,
                exception,
                sequence,
                created_at_timeuuid,
                fetched_at
            FROM router_logs
            WHERE profile_id = ?
              AND router_id = ?
            ORDER BY COALESCE(reported_at, created_at) DESC
            LIMIT ?
        """, (
            profile_id_filter,
            str(router_id),
            int(max(limit, 1000)),
        )).fetchall()

    filtered_rows = []
    for row in candidate_rows:
        reported_dt = parse_router_log_dt(row["reported_at"])
        created_dt = parse_router_log_dt(row["created_at"])

        timestamps = [dt for dt in (reported_dt, created_dt) if dt]
        if not timestamps:
            continue

        if since_dt and not any(dt >= since_dt for dt in timestamps):
            continue

        filtered_rows.append(row)

    normalized_logs = [normalize_cached_router_log_row(r) for r in filtered_rows[:int(limit)]]

    return {
        "router_id": router_id,
        "profile_id": profile_id_filter,
        "days": days,
        "since_utc": since,
        "count": len(normalized_logs),
        "fetched_live_count": fetched_live_count,
        "cached_count": cached_count,
        "cache_candidate_count": len(candidate_rows),
        "live_fetch_error": live_fetch_error,
        "logs": normalized_logs,
        "meta": meta,
    }


@app.get("/event-context/logs")
async def api_event_context_logs(
    router_id: str,
    event_time_utc: str,
    profile_id: int = Query(default=None),
    before_minutes: int = Query(10, ge=1, le=4320),
    after_minutes: int = Query(10, ge=0, le=4320),
    limit: int = Query(1000, ge=20, le=5000),
    live_fetch: int = Query(1, ge=0, le=1),
):
    """Return cached router logs around a clicked graph event timestamp.

    The clicked timestamp is treated as an anchor. Logs are context only.
    The response highlights the closest log, closest prior log, and closest following log.
    """
    profile_id_filter = normalize_profile_id(profile_id)
    event_dt = parse_router_log_dt(event_time_utc)
    if not event_dt:
        raise HTTPException(status_code=400, detail="event_time_utc must be an ISO UTC timestamp.")

    # Event Context supports two timestamp styles:
    # - point-in-time events: use before/after minutes around the anchor
    # - daily graph dots: UI currently sends a large before/after window around a
    #   daily bucket anchor. For daily buckets, use the selected local calendar day.
    now_utc = datetime.now(timezone.utc)

    is_daily_bucket = int(before_minutes or 0) >= 720 and int(after_minutes or 0) >= 720

    if is_daily_bucket:
        local_event = event_dt.astimezone(LOCAL_TZ)
        local_now = now_utc.astimezone(LOCAL_TZ)

        local_start = local_event.replace(hour=0, minute=0, second=0, microsecond=0)

        if local_event.date() == local_now.date():
            local_end = local_now
        else:
            local_end = local_event.replace(hour=23, minute=59, second=59, microsecond=0)

        window_start = local_start.astimezone(timezone.utc)
        requested_window_end = local_end.astimezone(timezone.utc)
        window_end = requested_window_end
        future_capped = local_event.date() == local_now.date()
    else:
        window_start = event_dt - timedelta(minutes=int(before_minutes))
        requested_window_end = event_dt + timedelta(minutes=int(after_minutes))
        window_end = min(requested_window_end, now_utc)
        future_capped = requested_window_end > now_utc

    fetched_live_count = 0
    live_fetch_error = None
    live_fetch_mode = "cache_only"

    # Never call NCM with an invalid/inverted window.
    if window_start >= window_end:
        live_fetch = 0
        live_fetch_error = "Invalid log window skipped: start time is greater than or equal to end time."


    if int(live_fetch or 0) == 1:
        since = window_start.isoformat().replace("+00:00", "Z")
        until = window_end.isoformat().replace("+00:00", "Z")

        try:
            raw_rows = []

            # Strategy 1: bounded by created_at, with paging.
            live_fetch_mode = "created_at_bounded_paged"
            fetch_result = await fetch_and_cache_router_logs_window(
                router_id=router_id,
                profile_id=profile_id_filter,
                since=since,
                until=until,
                limit=max(int(limit or 1000), 1000),
                max_pages=25,
            )
            raw_rows = fetch_result.get("rows", []) or []
            fetched_live_count = fetch_result.get("fetched_count", 0)
            if fetch_result.get("live_fetch_error"):
                live_fetch_error = fetch_result.get("live_fetch_error")

            # Strategy 2: broad fallback. Router logs API does not support
            # reported_at filters, so use created_at__gt broadly and filter locally
            # by parsed reported_at/created_at timestamps.
            if len(raw_rows) == 0 and not live_fetch_error:
                live_fetch_mode = "broad_since_paged"
                fetch_result = await fetch_and_cache_router_logs_window(
                    router_id=router_id,
                    profile_id=profile_id_filter,
                    since=since,
                    until=None,
                    limit=5000,
                    max_pages=25,
                )
                raw_rows = fetch_result.get("rows", []) or []
                fetched_live_count = fetch_result.get("fetched_count", 0)
                if fetch_result.get("live_fetch_error"):
                    live_fetch_error = fetch_result.get("live_fetch_error")

        except Exception as exc:
            # Event Context should not fail completely just because the live
            # NCM router_logs API has an issue for a specific router/date/window.
            # Continue with any locally cached logs and surface the warning to UI.
            live_fetch_error = str(exc)

    # Pull candidate rows from local cache and filter timestamps in Python instead
    # of relying on SQLite string comparisons across mixed ISO formats.
    candidate_start = window_start - timedelta(days=3)
    candidate_end = window_end + timedelta(days=3)

    with db() as conn:
        conn.row_factory = sqlite3.Row
        candidate_rows = conn.execute("""
            SELECT
                profile_id,
                log_key,
                router_id,
                reported_at,
                created_at,
                level,
                source,
                message,
                exception,
                sequence,
                created_at_timeuuid,
                fetched_at
            FROM router_logs
            WHERE profile_id = ?
              AND router_id = ?
            ORDER BY COALESCE(reported_at, created_at) ASC
            LIMIT ?
        """, (
            profile_id_filter,
            str(router_id),
            int(max(limit, 10000)),
        )).fetchall()

    filtered_rows = []
    candidate_count = 0
    candidate_min = None
    candidate_max = None

    for row in candidate_rows:
        reported_dt = parse_router_log_dt(row["reported_at"])
        created_dt = parse_router_log_dt(row["created_at"])

        # Router logs can be fetched from NCM by created_at while the router-reported
        # timestamp still falls slightly outside the selected local day. For daily
        # chart context, treat either timestamp as a valid match for the selected day.
        timestamps = [dt for dt in (reported_dt, created_dt) if dt]
        if not timestamps:
            continue

        candidate_match = any(candidate_start <= dt <= candidate_end for dt in timestamps)
        window_match = any(window_start <= dt <= window_end for dt in timestamps)

        # Keep min/max based on all timestamps we considered so the UI diagnostic
        # reflects the real checked range, not only reported_at.
        for dt in timestamps:
            if candidate_start <= dt <= candidate_end:
                candidate_count += 1
                if candidate_min is None or dt < candidate_min:
                    candidate_min = dt
                if candidate_max is None or dt > candidate_max:
                    candidate_max = dt

        if window_match:
            filtered_rows.append(row)

    # Event Context should show logs nearest to the clicked graph anchor, not
    # simply the first rows in a noisy daily window. For high-volume routers,
    # the first 1000 logs of a day can be hours away from the selected point.
    normalized_all_logs = [normalize_cached_router_log_row(r, event_dt=event_dt) for r in filtered_rows]

    normalized_all_logs.sort(
        key=lambda item: (
            abs(item.get("delta_seconds")) if item.get("delta_seconds") is not None else 999999999,
            item.get("reported_at") or item.get("created_at") or "",
        )
    )

    logs = normalized_all_logs[:int(limit)]

    logs.sort(
        key=lambda item: (
            parse_router_log_dt(item.get("reported_at") or item.get("created_at")) or datetime.min.replace(tzinfo=timezone.utc)
        )
    )

    closest_index = None
    closest_before_index = None
    closest_after_index = None

    for idx, item in enumerate(logs):
        delta = item.get("delta_seconds")
        if delta is None:
            continue

        if closest_index is None or abs(delta) < abs(logs[closest_index]["delta_seconds"]):
            closest_index = idx

        if delta <= 0:
            if closest_before_index is None or delta > logs[closest_before_index]["delta_seconds"]:
                closest_before_index = idx

        if delta >= 0:
            if closest_after_index is None or delta < logs[closest_after_index]["delta_seconds"]:
                closest_after_index = idx

    if closest_index is not None:
        logs[closest_index]["closest"] = True
    if closest_before_index is not None:
        logs[closest_before_index]["closest_before"] = True
    if closest_after_index is not None:
        logs[closest_after_index]["closest_after"] = True

    return {
        "router_id": str(router_id),
        "profile_id": profile_id_filter,
        "event_time_utc": event_dt.isoformat().replace("+00:00", "Z"),
        "event_time_local": to_local_string(event_dt.isoformat().replace("+00:00", "Z")),
        "window_start_utc": window_start.isoformat().replace("+00:00", "Z"),
        "window_end_utc": window_end.isoformat().replace("+00:00", "Z"),
        "window_start_local": to_local_string(window_start.isoformat().replace("+00:00", "Z")),
        "window_end_local": to_local_string(window_end.isoformat().replace("+00:00", "Z")),
        "requested_window_end_utc": requested_window_end.isoformat().replace("+00:00", "Z"),
        "requested_window_end_local": to_local_string(requested_window_end.isoformat().replace("+00:00", "Z")),
        "future_capped": bool(future_capped),
        "is_daily_bucket": bool(is_daily_bucket),
        "retention_note": _event_context_router_logs_retention_note(),
        "before_minutes": int(before_minutes),
        "after_minutes": int(after_minutes),
        "count": len(logs),
        "fetched_live_count": fetched_live_count,
        "live_fetch_mode": live_fetch_mode,
        "cached_candidate_count": candidate_count,
        "cached_candidate_min_utc": candidate_min.isoformat().replace("+00:00", "Z") if candidate_min else None,
        "cached_candidate_max_utc": candidate_max.isoformat().replace("+00:00", "Z") if candidate_max else None,
        "cached_candidate_min_local": to_local_string(candidate_min.isoformat().replace("+00:00", "Z")) if candidate_min else None,
        "cached_candidate_max_local": to_local_string(candidate_max.isoformat().replace("+00:00", "Z")) if candidate_max else None,
        "live_fetch_error": live_fetch_error,
        "logs": logs,
    }


@app.get("/event-context/logs/export.csv")
async def api_event_context_logs_export_csv(
    router_id: str,
    event_time_utc: str,
    profile_id: int = Query(default=None),
    before_minutes: int = Query(10, ge=1, le=4320),
    after_minutes: int = Query(10, ge=0, le=4320),
    limit: int = Query(5000, ge=20, le=10000),
    live_fetch: int = Query(1, ge=0, le=1),
):
    """Export Event Context router logs as a CSV with metadata header rows."""
    import csv
    from io import StringIO

    profile_id_filter = normalize_profile_id(profile_id)
    event_dt = parse_router_log_dt(event_time_utc)
    if not event_dt:
        raise HTTPException(status_code=400, detail="event_time_utc must be an ISO UTC timestamp.")

    window_start = event_dt - timedelta(minutes=int(before_minutes))
    requested_window_end = event_dt + timedelta(minutes=int(after_minutes))
    now_utc = datetime.now(timezone.utc)
    window_end = min(requested_window_end, now_utc)
    future_capped = requested_window_end > now_utc

    fetched_live_count = 0
    live_fetch_error = None

    if int(live_fetch or 0) == 1:
        since = window_start.isoformat().replace("+00:00", "Z")
        try:
            payload = await ncm_get(
                "/api/v2/router_logs/",
                {
                    "router": router_id,
                    "created_at__gt": since,
                    "created_at__lt": window_end.isoformat().replace("+00:00", "Z"),
                    "limit": limit,
                },
                profile_id=profile_id_filter,
            )
            raw_rows = payload.get("data", []) if isinstance(payload, dict) else []
            fetched_live_count = len(raw_rows)
            store_router_log_rows(raw_rows, profile_id_filter, router_id)
        except Exception as exc:
            live_fetch_error = str(exc)

    with db() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT
                profile_id,
                log_key,
                router_id,
                reported_at,
                created_at,
                level,
                source,
                message,
                exception,
                sequence,
                created_at_timeuuid,
                fetched_at
            FROM router_logs
            WHERE profile_id = ?
              AND router_id = ?
              AND COALESCE(reported_at, created_at) >= ?
              AND COALESCE(reported_at, created_at) <= ?
            ORDER BY COALESCE(reported_at, created_at) ASC
            LIMIT ?
        """, (
            profile_id_filter,
            str(router_id),
            window_start.isoformat().replace("+00:00", "Z"),
            window_end.isoformat().replace("+00:00", "Z"),
            int(limit),
        )).fetchall()

    logs = [normalize_cached_router_log_row(r, event_dt=event_dt) for r in rows]

    closest_index = None
    closest_before_index = None
    closest_after_index = None

    for idx, item in enumerate(logs):
        delta = item.get("delta_seconds")
        if delta is None:
            continue

        if closest_index is None or abs(delta) < abs(logs[closest_index]["delta_seconds"]):
            closest_index = idx

        if delta <= 0:
            if closest_before_index is None or delta > logs[closest_before_index]["delta_seconds"]:
                closest_before_index = idx

        if delta >= 0:
            if closest_after_index is None or delta < logs[closest_after_index]["delta_seconds"]:
                closest_after_index = idx

    if closest_index is not None:
        logs[closest_index]["closest"] = True
    if closest_before_index is not None:
        logs[closest_before_index]["closest_before"] = True
    if closest_after_index is not None:
        logs[closest_after_index]["closest_after"] = True

    output = StringIO()
    writer = csv.writer(output)

    event_utc = event_dt.isoformat().replace("+00:00", "Z")
    window_start_utc = window_start.isoformat().replace("+00:00", "Z")
    window_end_utc = window_end.isoformat().replace("+00:00", "Z")
    requested_window_end_utc = requested_window_end.isoformat().replace("+00:00", "Z")

    writer.writerow(["NCM Monitor Event Context Export"])
    writer.writerow(["Router ID", str(router_id)])
    writer.writerow(["Profile ID", profile_id_filter])
    writer.writerow(["Event / Anchor Time UTC", event_utc])
    writer.writerow(["Event / Anchor Time Local", to_local_string(event_utc)])
    writer.writerow(["Window Start UTC", window_start_utc])
    writer.writerow(["Window Start Local", to_local_string(window_start_utc)])
    writer.writerow(["Window End UTC", window_end_utc])
    writer.writerow(["Window End Local", to_local_string(window_end_utc)])
    writer.writerow(["Requested Window End UTC", requested_window_end_utc])
    writer.writerow(["Requested Window End Local", to_local_string(requested_window_end_utc)])
    writer.writerow(["Future Window Capped", "Yes" if future_capped else "No"])
    writer.writerow(["Local Time Zone", LOCAL_TZ_NAME])
    nearest_log = next((log for log in logs if log.get("closest")), None)

    writer.writerow(["Logs Found", len(logs)])
    writer.writerow(["Nearest Log Local", nearest_log.get("log_time_local") if nearest_log else ""])
    writer.writerow(["Nearest Log UTC", nearest_log.get("log_time") if nearest_log else ""])
    writer.writerow(["Nearest Log Delta Seconds", nearest_log.get("delta_seconds") if nearest_log and nearest_log.get("delta_seconds") is not None else ""])
    writer.writerow(["Live NCM Rows Fetched", fetched_live_count])
    writer.writerow(["Live NCM Fetch Error", live_fetch_error or ""])
    writer.writerow([])
    writer.writerow([
        "Anchor Marker",
        "Log Time Local",
        "Log Time UTC",
        "Delta From Anchor Seconds",
        "Context Marker",
        "Level",
        "Source",
        "Sequence",
        "Message",
        "Exception",
        "Reported At UTC",
        "Created At UTC",
        "Fetched At UTC",
        "Log Key",
    ])

    for log in logs:
        markers = []
        if log.get("closest"):
            markers.append("nearest_to_anchor")
        if log.get("closest_before"):
            markers.append("nearest_before_anchor")
        if log.get("closest_after"):
            markers.append("nearest_after_anchor")

        anchor_marker = "ANCHOR_NEAREST_LOG" if log.get("closest") else ""

        if log.get("closest"):
            writer.writerow([])
            writer.writerow([
                ">>> SELECTED CHART ANCHOR / NEAREST LOG BELOW <<<",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
            ])

        writer.writerow([
            anchor_marker,
            log.get("log_time_local") or "",
            log.get("log_time") or "",
            log.get("delta_seconds") if log.get("delta_seconds") is not None else "",
            "; ".join(markers),
            log.get("level") or "",
            log.get("source") or "",
            log.get("sequence") or "",
            log.get("message") or "",
            log.get("exception") or "",
            log.get("reported_at") or "",
            log.get("created_at") or "",
            log.get("fetched_at") or "",
            log.get("log_key") or "",
        ])

    safe_event = event_dt.strftime("%Y%m%d-%H%M%SZ")
    filename = f"event-context-router-{router_id}-{safe_event}.csv"

    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )


@app.get("/router-logs/{router_id}/export.xlsx")
async def api_router_logs_export_xlsx(
    router_id: int,
    days: int = Query(7, ge=1, le=90),
    profile_id: int = Query(default=None),
    limit: int = Query(1000, ge=20, le=5000),
):
    """Export router logs to a polished XLSX workbook."""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Border, Side, Alignment
        from openpyxl.utils import get_column_letter
        from openpyxl.worksheet.table import Table, TableStyleInfo
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"openpyxl is required for XLSX export: {exc}")

    from io import BytesIO

    profile_id_filter = normalize_profile_id(profile_id)
    since = router_log_days_to_since(days)

    payload = await ncm_get(
        "/api/v2/router_logs/",
        {
            "router": router_id,
            "created_at__gt": since,
            "limit": limit,
        },
        profile_id=profile_id_filter,
    )

    raw_rows = payload.get("data", []) if isinstance(payload, dict) else []
    store_router_log_rows(raw_rows, profile_id_filter, router_id)
    logs = [normalize_router_log_row(r) for r in raw_rows]

    wb = Workbook()
    ws = wb.active
    ws.title = "Router Logs"

    title_fill = PatternFill("solid", fgColor="1E293B")
    subtitle_fill = PatternFill("solid", fgColor="334155")
    header_fill = PatternFill("solid", fgColor="CBD5E1")
    white_font = Font(color="FFFFFF", bold=True)
    title_font = Font(color="FFFFFF", bold=True, size=16)
    header_font = Font(color="0F172A", bold=True)
    thin_gray = Side(style="thin", color="CBD5E1")
    border = Border(left=thin_gray, right=thin_gray, top=thin_gray, bottom=thin_gray)

    ws.merge_cells("A1:H1")
    ws["A1"] = f"Router Logs — Router {router_id}"
    ws["A1"].fill = title_fill
    ws["A1"].font = title_font
    ws["A1"].alignment = Alignment(horizontal="center")

    ws.merge_cells("A2:H2")
    ws["A2"] = f"Profile ID: {profile_id_filter} | Date Window: Last {days} Day(s) | Since UTC: {since} | Exported Local: {to_local_string(now_utc())}"
    ws["A2"].fill = subtitle_fill
    ws["A2"].font = white_font
    ws["A2"].alignment = Alignment(horizontal="center")

    ws.append([])
    headers = [
        "Reported At Local",
        "Reported At UTC",
        "Created At Local",
        "Created At UTC",
        "Level",
        "Source",
        "Message",
        "Exception",
        "Sequence",
    ]
    ws.append(headers)

    header_row = 4
    for cell in ws[header_row]:
        cell.fill = header_fill
        cell.font = header_font
        cell.border = border
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    for log in logs:
        ws.append([
            log.get("reported_at_local") or "",
            log.get("reported_at") or "",
            log.get("created_at_local") or "",
            log.get("created_at") or "",
            log.get("level") or "",
            log.get("source") or "",
            log.get("message") or "",
            log.get("exception") or "",
            log.get("sequence") if log.get("sequence") is not None else "",
        ])

    for row in ws.iter_rows(min_row=5, max_row=ws.max_row, min_col=1, max_col=9):
        for cell in row:
            cell.border = border
            cell.alignment = Alignment(vertical="top", wrap_text=True)

    widths = {
        "A": 24,
        "B": 30,
        "C": 24,
        "D": 30,
        "E": 12,
        "F": 24,
        "G": 100,
        "H": 30,
        "I": 12,
    }
    for col, width in widths.items():
        ws.column_dimensions[col].width = width

    ws.freeze_panes = "A5"
    ws.auto_filter.ref = f"A4:I{max(ws.max_row, 4)}"

    if ws.max_row >= 5:
        table_ref = f"A4:I{ws.max_row}"
        table = Table(displayName="RouterLogsTable", ref=table_ref)
        style = TableStyleInfo(
            name="TableStyleMedium2",
            showFirstColumn=False,
            showLastColumn=False,
            showRowStripes=True,
            showColumnStripes=False,
        )
        table.tableStyleInfo = style
        ws.add_table(table)

    summary = wb.create_sheet("Summary")
    summary["A1"] = "Router Logs Export Summary"
    summary["A1"].font = Font(bold=True, size=16)
    summary["A3"] = "Router ID"
    summary["B3"] = router_id
    summary["A4"] = "Profile ID"
    summary["B4"] = profile_id_filter
    summary["A5"] = "Date Window"
    summary["B5"] = f"Last {days} Day(s)"
    summary["A6"] = "Since UTC"
    summary["B6"] = since
    summary["A7"] = "Exported Local"
    summary["B7"] = to_local_string(now_utc())
    summary["A8"] = "Rows Exported"
    summary["B8"] = len(logs)

    for row in summary.iter_rows(min_row=3, max_row=8, min_col=1, max_col=2):
        for cell in row:
            cell.border = border
            cell.alignment = Alignment(vertical="top")
        row[0].font = Font(bold=True)

    summary.column_dimensions["A"].width = 24
    summary.column_dimensions["B"].width = 50

    out = BytesIO()
    wb.save(out)
    out.seek(0)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"router_{router_id}_logs_{days}d_{timestamp}.xlsx"

    return StreamingResponse(
        out,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/load-router-lists")
async def api_load_router_lists():
    loaded = load_router_lists()
    return {"loaded_count": len(loaded), "routers": loaded[:20]}


@app.get("/pools")
async def api_get_pools(profile_id: int = Query(default=None)):
    profile_id_filter = normalize_profile_id(profile_id)
    with db() as conn:
        return {"pools": pool_counts(conn, profile_id_filter)}


@app.post("/pools")
async def api_create_pool(profile_id: int = Query(default=None), payload: dict = Body(default={})):
    name = (payload.get("name") or "").strip()
    description = (payload.get("description") or "").strip()
    profile_id = payload_profile_id(payload, profile_id)

    if not name:
        raise HTTPException(status_code=400, detail="Pool name is required.")

    ts = now_utc()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO monitoring_pools(name, description, created_at, updated_at, profile_id)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(profile_id, name) DO UPDATE SET
                description = excluded.description,
                updated_at = excluded.updated_at,
                profile_id = excluded.profile_id
            """,
            (name, description, ts, ts, profile_id),
        )

    return {"status": "saved", "name": name, "profile_id": profile_id}


@app.post("/pools/rename")
async def api_rename_pool(payload: dict = Body(default={})):
    old_name = (payload.get("old_name") or "").strip()
    new_name = (payload.get("new_name") or "").strip()
    description = payload.get("description")
    profile_id = payload_profile_id(payload)
    if not old_name or not new_name:
        raise HTTPException(status_code=400, detail="old_name and new_name are required.")

    ts = now_utc()
    with db() as conn:
        existing = conn.execute(
            "SELECT name, description, created_at FROM monitoring_pools WHERE name = ? AND COALESCE(profile_id, 1) = ?",
            (old_name, profile_id),
        ).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Pool not found.")
        desc = existing[1] if description is None else str(description).strip()
        conn.execute(
            "DELETE FROM monitoring_pools WHERE name = ? AND COALESCE(profile_id, 1) = ?",
            (old_name, profile_id),
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO monitoring_pools(name, description, created_at, updated_at, profile_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (new_name, desc, existing[2], ts, profile_id),
        )
        conn.execute(
            "UPDATE routers SET bucket = ? WHERE bucket = ? AND COALESCE(profile_id, 1) = ?",
            (new_name, old_name, profile_id),
        )
    return {"status": "renamed", "old_name": old_name, "new_name": new_name}


@app.post("/pools/delete")
async def api_delete_pool(payload: dict = Body(default={})):
    name = (payload.get("name") or "").strip()
    remove_routers = bool(payload.get("remove_routers", False))
    profile_id = payload_profile_id(payload)
    if not name:
        raise HTTPException(status_code=400, detail="Pool name is required.")

    with db() as conn:
        if remove_routers:
            conn.execute(
                "DELETE FROM routers WHERE bucket = ? AND COALESCE(profile_id, 1) = ?",
                (name, profile_id),
            )
        else:
            conn.execute(
                "UPDATE routers SET bucket = 'Unassigned' WHERE bucket = ? AND COALESCE(profile_id, 1) = ?",
                (name, profile_id),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO monitoring_pools(name, description, created_at, updated_at)
                VALUES ('Unassigned', 'Routers moved here when their pool was deleted.', ?, ?)
                """,
                (now_utc(), now_utc()),
            )
        conn.execute(
            "DELETE FROM monitoring_pools WHERE name = ? AND COALESCE(profile_id, 1) = ?",
            (name, profile_id),
        )
    return {"status": "deleted", "name": name, "remove_routers": remove_routers}


@app.get("/monitoring-targets-ui", response_class=HTMLResponse)
async def monitoring_targets_ui(request: Request):
    """v5: simple browser UI for direct monitoring targets."""
    return HTMLResponse("""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Monitoring Targets</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #0f172a;
      color: #e5e7eb;
      margin: 0;
      padding: 24px;
    }
    a { color: #93c5fd; }
    .wrap { max-width: 1200px; margin: 0 auto; }
    .card {
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 14px;
      padding: 18px;
      margin-bottom: 18px;
      box-shadow: 0 10px 30px rgba(0,0,0,.25);
    }
    h1 { margin: 0 0 8px; }
    h2 { margin-top: 0; }
    label {
      display: block;
      margin: 10px 0 5px;
      color: #cbd5e1;
      font-size: 14px;
    }
    input, select {
      width: 100%;
      box-sizing: border-box;
      padding: 10px;
      border-radius: 10px;
      border: 1px solid #374151;
      background: #020617;
      color: #e5e7eb;
    }
    button {
      border: 0;
      border-radius: 10px;
      padding: 10px 14px;
      background: #2563eb;
      color: white;
      cursor: pointer;
      font-weight: 600;
      margin-top: 12px;
    }
    button.secondary { background: #334155; }
    button.danger { background: #991b1b; }
    .row {
      display: grid;
      grid-template-columns: 1fr 1fr auto;
      gap: 12px;
      align-items: end;
    }
    .muted { color: #94a3b8; font-size: 13px; }
    .target {
      border-top: 1px solid #1f2937;
      padding: 14px 0;
    }
    .target:first-child { border-top: 0; }
    .target-head {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
    }
    .router-id { font-size: 18px; font-weight: 700; }
    .pill {
      display: inline-block;
      border-radius: 999px;
      padding: 3px 8px;
      margin: 0 0 8px 0;
      font-size: 12px;
      font-weight: 700;
      background: #1e293b;
      color: #cbd5e1;
    }
    .pill.on { background: #14532d; color: #bbf7d0; }
    .pill.off { background: #3f1d1d; color: #fecaca; }
    .pill.request { background: #4c1d95; color: #ddd6fe; }
    .pill.cached { background: #164e63; color: #cffafe; }
    .module-title {
      display: block;
      font-size: 14px;
      line-height: 1.25;
      margin-bottom: 8px;
      min-height: 34px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(185px, 1fr));
      gap: 8px;
      margin-top: 10px;
    }
    .module-box {
      background: #020617;
      border: 1px solid #1f2937;
      border-radius: 10px;
      padding: 12px;
      font-size: 13px;
    }
    .caution {
      margin: 12px 0;
      padding: 12px;
      border-radius: 12px;
      border: 1px solid #92400e;
      background: rgba(146, 64, 14, .18);
      color: #fed7aa;
      font-size: 13px;
      line-height: 1.45;
    }
    .target-footer {
      margin-top: 16px;
      padding-top: 14px;
      border-top: 1px solid #1f2937;
      display: flex;
      justify-content: flex-end;
      gap: 10px;
    }
    .module-box select {
      margin-top: 3px;
    }
    pre {
      white-space: pre-wrap;
      background: #020617;
      border: 1px solid #1f2937;
      border-radius: 10px;
      padding: 12px;
      color: #cbd5e1;
      max-height: 220px;
      overflow: auto;
    }
  </style>
</head>
<body>
<div class="wrap">
  <p><a href="/launcher">← Launcher</a> &nbsp; <a href="/pool-admin">Pool Admin</a></p>

  <h1>Monitoring Targets</h1>
  <p class="muted">
    Add routers directly to this dashboard without requiring a pool.
    This page only shows individually added routers. Pool-managed routers remain managed from Pool Administration.
  </p>

  <div class="card">
    <h2>Add Device</h2>
    <div class="row">
      <div>
        <label>Router ID</label>
        <input id="routerId" placeholder="Example: router ID">
      </div>
      <div>
        <label>Display name optional</label>
        <input id="displayName" placeholder="Example: Store 123 / Test router">
      </div>
      <div>
      </div>
    </div>
    <button onclick="addDevice()">Add Device</button>
    <button class="secondary" onclick="loadTargets()">Refresh</button>
    <p class="muted">
      <div class="small" style="margin-top:10px; line-height:1.5;">
        When you add a router, NCM Monitor will automatically query recent router details, SIM/interface details,
        current signal data, recent alerts, and up to 30 days of supported history where available.
        This may take a moment depending on API response time and the number of routers being added.
      </div>
      Lower polling intervals create more NCM API calls. For large dashboards, aggressive polling can consume API capacity quickly.
    </p>
    <pre id="resultBox" style="display:none;"></pre>
  </div>

  <div class="card">
    <h2>Added Routers</h2>
    <div id="summary" class="muted">Loading...</div>
    <p class="muted">
      Device basics are collected during add/discovery so the app can identify the router and its SIM interfaces.
      Configurable monitoring controls background polling and can increase NCM API usage depending on frequency.
    </p>
    <div class="caution">
      <strong>Recommended:</strong> The default monitoring settings work for most routers and most dashboards.
      Only change these parameters if you understand the polling behavior and API impact. More aggressive polling can increase NCM API usage.
    </div>
    <div id="targets"></div>
  </div>
</div>

<script>
function activeProfileId() {
  const params = new URLSearchParams(window.location.search);
  return params.get('profile_id') || localStorage.getItem('activeProfileId') || '1';
}

function moduleInfo(name) {
  const info = {
    metadata: {
      label: 'Device profile',
      purpose: 'Identifies the router model, product image, and basic inventory details. Usually cached and refreshed rarely.'
    },
    net_devices: {
      label: 'SIM/interface discovery',
      purpose: 'Internal discovery of modem/SIM interfaces. Normally runs during add/rediscovery only.'
    },
    signal_health: {
      label: 'Signal history',
      purpose: 'Builds the signal graph and helps identify weak signal, cell changes, and modem instability.'
    },
    router_state: {
      label: 'Online/offline status',
      purpose: 'Tracks availability changes so the dashboard can show recent disconnects or reconnect patterns.'
    },
    alerts: {
      label: 'Alerts',
      purpose: 'Pulls recent NCM alerts for operational review, including failover and connectivity events.'
    },
    router_stream_usage: {
      label: 'NCM cloud traffic',
      purpose: 'Tracks router-to-cloud management traffic for data usage investigations.'
    },
    sim_usage: {
      label: 'Carrier/SIM data usage',
      purpose: 'Pulls carrier interface usage by SIM. Best used on demand or at slower intervals.'
    },
    location: {
      label: 'Location',
      purpose: 'Caches the router location for map display. Usually does not need frequent polling.'
    },
    router_logs: {
      label: 'Router logs',
      purpose: 'Pulls NCM router logs when group logging is enabled. Best used on demand.'
    }
  };
  return info[name] || {label: name, purpose: ''};
}

function moduleStateText(m) {
  if (m.mode === 'on_demand') return 'On request';
  if (m.mode === 'cached') return m.enabled ? 'Cached' : 'Cache off';
  if (m.enabled) return 'Monitoring';
  return 'Off';
}

function modulePillClass(m) {
  if (m.mode === 'on_demand') return 'request';
  if (m.mode === 'cached') return m.enabled ? 'cached' : 'off';
  if (m.enabled) return 'on';
  return 'off';
}

function updateModulePill(routerId, moduleName) {
  const checkbox = document.getElementById(`enabled-${routerId}-${moduleName}`);
  const pill = document.getElementById(`pill-${routerId}-${moduleName}`);
  if (!checkbox || !pill) return;

  if (checkbox.checked) {
    pill.textContent = 'Monitoring';
    pill.className = 'pill on';
  } else {
    pill.textContent = 'Off';
    pill.className = 'pill off';
  }
}

function intervalOptions(current) {
  const opts = [
    ['', 'No interval'],
    ['5', 'Every 5 minutes'],
    ['15', 'Every 15 minutes'],
    ['30', 'Every 30 minutes'],
    ['60', 'Every 60 minutes'],
    ['360', 'Every 6 hours'],
    ['1440', 'Every 24 hours']
  ];

  return opts.map(([value, label]) => {
    const selected = String(current || '') === value ? 'selected' : '';
    return `<option value="${value}" ${selected}>${label}</option>`;
  }).join('');
}

function moduleCallCost(name) {
  const costs = {
    signal_health: 2,
    router_state: 1,
    alerts: 1,
    router_stream_usage: 1,
    location: 1
  };
  return costs[name] || 0;
}

function estimateModuleCalls(name, m) {
  if (!m || !m.enabled || (m.mode || '') !== 'passive') {
    return {hourly: 0, monthly: 0};
  }

  const interval = Number(m.interval_minutes || 0);
  const cost = moduleCallCost(name);

  if (!interval || !cost) {
    return {hourly: 0, monthly: 0};
  }

  const hourly = (60 / interval) * cost;
  const monthly = hourly * 24 * 30;

  return {
    hourly,
    monthly
  };
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({
    '&':'&amp;',
    '<':'&lt;',
    '>':'&gt;',
    '"':'&quot;',
    "'":'&#39;'
  }[ch]));
}

function formatCalls(value) {
  if (!value) return '0';
  if (value >= 1000) return Math.round(value).toLocaleString();
  return value % 1 === 0 ? String(value) : value.toFixed(1);
}

function estimateTargetCalls(modules) {
  let hourly = 0;
  let monthly = 0;

  Object.keys(modules || {}).forEach(name => {
    const est = estimateModuleCalls(name, modules[name]);
    hourly += est.hourly;
    monthly += est.monthly;
  });

  return {hourly, monthly};
}

async function saveModule(routerId, moduleName) {
  const enabledEl = document.getElementById(`enabled-${routerId}-${moduleName}`);
  const intervalEl = document.getElementById(`interval-${routerId}-${moduleName}`);
  const modeEl = document.getElementById(`mode-${routerId}-${moduleName}`);
  const savedEl = document.getElementById(`saved-${routerId}-${moduleName}`);

  const enabled = enabledEl && enabledEl.type === 'checkbox'
    ? enabledEl.checked
    : false;

  const intervalVal = intervalEl ? intervalEl.value : '';
  const mode = modeEl ? modeEl.value : 'passive';

  const body = {
    profile_id: Number(activeProfileId()),
    router_id: routerId,
    modules: {}
  };

  // Important: only send the one module the user clicked Save on.
  // Do not send the rest of the page state.
  body.modules[moduleName] = {
    enabled: enabled,
    mode: mode,
    interval_minutes: intervalVal ? Number(intervalVal) : null
  };

  const res = await fetch('/monitoring-targets/modules', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  });

  const data = await res.json();
  if (!res.ok) {
    alert(data.detail || 'Failed to save module settings.');
    return;
  }

  updateModulePill(routerId, moduleName);
  updateTargetEstimate(routerId);

  if (savedEl) {
    savedEl.textContent = 'Saved';
    savedEl.style.opacity = '1';
    setTimeout(() => {
      savedEl.style.opacity = '0';
    }, 1600);
  }
}

  function setAddDeviceStatus(kind, message) {
    const resultBox = document.getElementById('resultBox');
    if (!resultBox) return;

    const styles = {
      checking: {
        bg: 'rgba(59,130,246,.14)',
        border: '1px solid rgba(96,165,250,.35)',
        color: '#bfdbfe',
        icon: '⏳'
      },
      success: {
        bg: 'rgba(34,197,94,.14)',
        border: '1px solid rgba(74,222,128,.38)',
        color: '#bbf7d0',
        icon: '✅'
      },
      error: {
        bg: 'rgba(239,68,68,.14)',
        border: '1px solid rgba(248,113,113,.40)',
        color: '#fecaca',
        icon: '⚠️'
      }
    };

    const style = styles[kind] || styles.checking;
    resultBox.style.display = 'block';
    resultBox.style.marginTop = '12px';
    resultBox.style.padding = '12px 14px';
    resultBox.style.borderRadius = '12px';
    resultBox.style.fontWeight = '700';
    resultBox.style.lineHeight = '1.4';
    resultBox.style.whiteSpace = 'pre-wrap';
    resultBox.style.background = style.bg;
    resultBox.style.border = style.border;
    resultBox.style.color = style.color;
    resultBox.textContent = `${style.icon} ${message}`;
  }

  async function addDevice() {
    const router_id = document.getElementById('routerId').value.trim();
    const display_name = document.getElementById('displayName').value.trim();
    const hydrate = true;
    const btn = document.querySelector('button[onclick="addDevice()"]');

    if (!router_id) {
      setAddDeviceStatus('error', 'Router ID is required.');
      return;
    }

    if (btn) {
      btn.disabled = true;
      btn.textContent = 'Checking router ID...';
    }

    setAddDeviceStatus('checking', 'Checking router ID and validating access in NCM...');

    let res;
    let data = {};

    try {
      res = await fetch('/monitoring-targets/add-device', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        credentials: 'same-origin',
        body: JSON.stringify({
          profile_id: Number(activeProfileId()),
          router_id,
          display_name,
          hydrate
        })
      });

      try {
        data = await res.json();
      } catch (e) {
        data = {};
      }
    } catch (err) {
      setAddDeviceStatus('error', `Could not reach the local NCM Monitor service: ${String(err)}`);
      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Add Individual Router';
      }
      return;
    }

    if (!res.ok) {
      setAddDeviceStatus('error', data.detail || data.message || 'Add device failed.');
      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Add Individual Router';
      }
      return;
    }

    setAddDeviceStatus('success', `Router ${router_id} validated, added, and initial hydration was started.`);

    document.getElementById('routerId').value = '';
    document.getElementById('displayName').value = '';

    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Add Individual Router';
    }

    await loadTargets();
  }

function updateTargetEstimate(routerId) {
  const estimateEl = document.getElementById(`estimate-${routerId}`);
  if (!estimateEl) return;

  let hourly = 0;
  let monthly = 0;

  const enabledEls = document.querySelectorAll(`[id^="enabled-${routerId}-"]`);

  enabledEls.forEach(enabledEl => {
    const moduleName = enabledEl.id.replace(`enabled-${routerId}-`, '');
    const modeEl = document.getElementById(`mode-${routerId}-${moduleName}`);
    const intervalEl = document.getElementById(`interval-${routerId}-${moduleName}`);

    const enabled = enabledEl.type === 'checkbox'
      ? enabledEl.checked
      : enabledEl.value === 'true';

    const mode = modeEl ? modeEl.value : '';
    const interval = intervalEl ? Number(intervalEl.value || 0) : 0;

    if (!enabled || mode !== 'passive' || !interval) return;

    const cost = moduleCallCost(moduleName);
    if (!cost) return;

    hourly += (60 / interval) * cost;
  });

  monthly = hourly * 24 * 30;

  estimateEl.textContent = `Estimated API volume: ${formatCalls(hourly)} calls/hour · ${formatCalls(monthly)} calls/month`;
}

async function loadTargets() {
  const profile_id = activeProfileId();

  const summaryRes = await fetch(`/monitoring-targets/summary?profile_id=${encodeURIComponent(profile_id)}`);
  const summary = await summaryRes.json();

  const res = await fetch(`/monitoring-targets?profile_id=${encodeURIComponent(profile_id)}&scope=direct`);
  const data = await res.json();

  document.getElementById('summary').textContent =
    `Profile ${summary.profile_id}: ${summary.target_count} target(s).`;

  const targetBox = document.getElementById('targets');
  if (!data.targets || data.targets.length === 0) {
    targetBox.innerHTML = '<p class="muted">No monitoring targets yet.</p>';
    return;
  }

  targetBox.innerHTML = data.targets.map(t => {
    const modules = t.modules || {};
    const bakedInModules = new Set(['metadata', 'net_devices']);
    const configurableNames = Object.keys(modules).filter(name => !bakedInModules.has(name) && (modules[name].mode || '') !== 'on_demand').sort();
    const onRequestNames = Object.keys(modules).filter(name => !bakedInModules.has(name) && (modules[name].mode || '') === 'on_demand').sort();

    const renderModule = (name, bakedIn=false) => {
      const m = modules[name];
      const info = moduleInfo(name);
      const stateText = moduleStateText(m);
      const cls = modulePillClass(m);
      const passive = (m.mode || 'passive') === 'passive';

      const controls = passive ? `
        <div style="margin-top:8px;">
          <label style="margin:6px 0 4px;">Polling frequency</label>
          <select id="interval-${t.router_id}-${name}" onchange="updateTargetEstimate('${t.router_id}')">
            ${intervalOptions(m.interval_minutes)}
          </select>
          <label style="display:flex;gap:6px;align-items:center;margin-top:8px;">
            <input id="enabled-${t.router_id}-${name}" type="checkbox" ${m.enabled ? 'checked' : ''} style="width:auto;" onchange="updateModulePill('${t.router_id}', '${name}'); updateTargetEstimate('${t.router_id}')">
            Monitor this data set
          </label>
          <input id="mode-${t.router_id}-${name}" type="hidden" value="${m.mode || 'passive'}">
          <button class="secondary" onclick="saveModule('${t.router_id}', '${name}')">Save</button>
          <span id="saved-${t.router_id}-${name}" class="muted" style="margin-left:8px;opacity:0;transition:opacity .2s;">Saved</span>
        </div>
      ` : `
        <div style="margin-top:8px;">
          <input id="enabled-${t.router_id}-${name}" type="hidden" value="${m.enabled ? 'true' : 'false'}">
          <input id="mode-${t.router_id}-${name}" type="hidden" value="${m.mode || 'disabled'}">
          <span class="muted">Runs only when requested from the related tool or workflow.</span>
        </div>
      `;

      return `
        <div class="module-box">
          <span id="pill-${t.router_id}-${name}" class="pill ${cls}">${stateText}</span>
          <strong class="module-title">${info.label}</strong>
          <p class="muted" style="margin:7px 0 0;">${info.purpose}</p>
          <p class="muted" style="margin:7px 0 0;">${bakedIn ? 'Collected during add/discovery.' : 'Mode: ' + (m.mode || 'disabled') + (m.interval_minutes ? ' · Current interval: ' + m.interval_minutes + ' min' : '')}</p>
          ${bakedIn ? '' : controls}
        </div>
      `;
    };

    const moduleHtml = configurableNames.map(name => renderModule(name, false)).join('');
    const onRequestHtml = onRequestNames.map(name => renderModule(name, false)).join('');

    const estimate = estimateTargetCalls(modules);
    const safeRouterId = escapeHtml(t.router_id || '');
    const safeDisplayName = escapeHtml(t.display_name || 'No display name');
    const safeBucket = escapeHtml(t.bucket || '');
    const scopeText = t.bucket ? 'Pool: ' + safeBucket : 'Direct';

    return `
      <details class="target" style="padding:0; overflow:hidden;">
        <summary style="
          list-style:none;
          cursor:pointer;
          padding:16px 18px;
          display:grid;
          grid-template-columns: 1.1fr 1.3fr .8fr .9fr .9fr auto;
          gap:12px;
          align-items:center;
        ">
          <div>
            <div class="muted" style="font-size:12px;">Router ID</div>
            <div class="router-id">${safeRouterId}</div>
          </div>

          <div>
            <div class="muted" style="font-size:12px;">Display Name</div>
            <div>${safeDisplayName}</div>
          </div>

          <div>
            <div class="muted" style="font-size:12px;">Scope</div>
            <div>${scopeText}</div>
          </div>

          <div>
            <div class="muted" style="font-size:12px;">Expected / Hour</div>
            <div>${formatCalls(estimate.hourly)}</div>
          </div>

          <div>
            <div class="muted" style="font-size:12px;">Expected / Month</div>
            <div>${formatCalls(estimate.monthly)}</div>
          </div>

          <div style="text-align:right;">
            <button onclick="event.preventDefault(); event.stopPropagation(); window.location.href='/router-view/' + encodeURIComponent('${t.router_id}') + '?profile_id=' + encodeURIComponent(activeProfileId())">Open Router</button>
          </div>
        </summary>

        <div style="border-top:1px solid #1f2937; padding:16px 18px 18px;">
          <div class="muted" style="margin-bottom:12px;">
            Polling attributes and thresholds are shown below. Click the row header again to collapse this router.
          </div>

          <div id="estimate-${t.router_id}" class="muted" style="margin-bottom:12px;">
            Estimated API volume: ${formatCalls(estimate.hourly)} calls/hour · ${formatCalls(estimate.monthly)} calls/month
          </div>

          <div class="card" style="margin-top:14px;background:#020617;">
            <h4 style="margin:0 0 8px;">Automatically handled</h4>
            <p class="muted" style="margin:0 0 8px;">
              NCM Monitor automatically pulls the device profile and discovers SIM/modem interfaces when the router is added.
              This allows router model, product image, carrier, SIM, and signal workflows to function correctly.
            </p>
            <p class="muted" style="margin:0;">
              This runs during add/discovery only. It is not treated as recurring monitoring.
            </p>
          </div>

          <h4 style="margin:18px 0 8px;">Configurable monitoring</h4>
          <p class="muted" style="margin:0 0 10px;">
            These data sets can run in the background. Lower polling intervals create more NCM API calls.
          </p>
          <div class="grid">${moduleHtml || '<p class="muted">No configurable monitoring modules found.</p>'}</div>

          <h4 style="margin:18px 0 8px;">On-request features</h4>
          <p class="muted" style="margin:0 0 10px;">
            These tools are available when needed, but are not designed to run continuously in the background.
          </p>
          <div class="grid">${onRequestHtml || '<p class="muted">No on-request modules found.</p>'}</div>
        </div>
      </details>
    `;
  }).join('');
}


loadTargets().catch(err => {
  const msg = err && err.message ? err.message : String(err);
  document.getElementById('summary').textContent = 'Failed to load monitoring targets: ' + msg;
  console.error(err);
});
</script>
</body>
</html>
""")


@app.post("/monitoring-targets/add-device")
async def api_add_individual_monitoring_target(payload: dict = Body(default={})):
    """
    v5.0.1: Add a router directly to a dashboard without assigning it to a pool.

    Direct targets are intentionally stored with monitoring_targets.pool_id = NULL.
    Pool-managed routers use monitoring_targets.pool_id = monitoring_pools.rowid.
    """
    profile_id = normalize_profile_id(payload.get("profile_id"))
    router_id = str(payload.get("router_id") or "").strip()
    display_name = str(payload.get("display_name") or "").strip() or None

    hydrate = payload.get("hydrate", True)
    if isinstance(hydrate, str):
        hydrate = hydrate.strip().lower() in {"1", "true", "yes", "on"}

    if not router_id:
        raise HTTPException(status_code=400, detail="router_id is required.")

    await require_valid_router_id(router_id, profile_id)

    ts = now_utc()

    with db() as conn:
        conn.row_factory = sqlite3.Row

        conn.execute(
            """
            INSERT INTO routers(router_id, bucket, last_seen_utc, profile_id)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(profile_id, router_id) DO UPDATE SET
                bucket = COALESCE(routers.bucket, excluded.bucket),
                last_seen_utc = excluded.last_seen_utc
            """,
            (router_id, "Individual", ts, profile_id),
        )

        # Direct/individual registration: pool_id intentionally NULL.
        ensure_monitoring_target(conn, profile_id, router_id, pool_id=None, display_name=display_name)
        ensure_monitoring_module_defaults(conn, profile_id, router_id)

        conn.commit()

    hydration_result = None
    hydration_error = None

    if hydrate:
        try:
            # Direct registration should match pool registration behavior:
            # hydrate identity, net_devices, current metrics, and rolling 30-day signal/usage.
            hydration_result = await poll_router(router_id, include_signal=True, profile_id=profile_id)
        except Exception as exc:
            hydration_error = str(exc)
            print(f"[direct-router-registration] Initial hydration failed for {router_id}: {exc}")

    return {
        "status": "added",
        "profile_id": profile_id,
        "router_id": router_id,
        "display_name": display_name,
        "scope": "direct",
        "hydrate": bool(hydrate),
        "hydration_result": hydration_result,
        "hydration_error": hydration_error,
    }


@app.post("/monitoring-targets/modules")
async def api_update_monitoring_target_modules(payload: dict = Body(default={})):
    """
    v5.0.1: Save configurable monitoring attributes for an individual/direct router target.
    This endpoint is used by /monitoring-targets-ui.
    """
    profile_id = normalize_profile_id(payload.get("profile_id"))
    router_id = str(payload.get("router_id") or "").strip()
    modules = payload.get("modules") or {}

    if not router_id:
        raise HTTPException(status_code=400, detail="router_id is required.")

    normalized = normalize_module_settings_from_payload(modules)
    ts = now_utc()

    with db() as conn:
        conn.row_factory = sqlite3.Row

        # Ensure the target exists. For individual registrations, pool_id remains NULL.
        ensure_monitoring_target(conn, profile_id, router_id, pool_id=None)
        ensure_monitoring_module_defaults(conn, profile_id, router_id)

        for module_name, cfg in normalized.items():
            conn.execute("""
                INSERT INTO monitoring_target_modules (
                    profile_id,
                    router_id,
                    module_name,
                    enabled,
                    interval_minutes,
                    mode,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(profile_id, router_id, module_name) DO UPDATE SET
                    enabled = excluded.enabled,
                    interval_minutes = excluded.interval_minutes,
                    mode = excluded.mode,
                    updated_at = excluded.updated_at
            """, (
                profile_id,
                router_id,
                module_name,
                cfg["enabled"],
                cfg["interval_minutes"],
                cfg["mode"],
                ts,
            ))

        conn.commit()

    return {
        "status": "saved",
        "profile_id": profile_id,
        "router_id": router_id,
        "modules_saved": len(normalized),
        "updated_at": ts,
    }


@app.get("/monitoring-targets/summary")
async def api_monitoring_targets_summary(profile_id: int = 1):
    """v5: compact summary of monitoring targets/modules for validation."""
    with db() as conn:
        conn.row_factory = sqlite3.Row

        target_count = conn.execute(
            """
            SELECT COUNT(*)
            FROM monitoring_targets
            WHERE profile_id = ?
            """,
            (profile_id,),
        ).fetchone()[0]

        module_rows = conn.execute(
            """
            SELECT
                module_name,
                COUNT(*) AS total,
                SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) AS enabled_count
            FROM monitoring_target_modules
            WHERE profile_id = ?
            GROUP BY module_name
            ORDER BY module_name
            """,
            (profile_id,),
        ).fetchall()

        recent_targets = conn.execute(
            """
            SELECT
                mt.router_id,
                mt.display_name,
                mt.enabled,
                r.bucket,
                mt.updated_at
            FROM monitoring_targets mt
            LEFT JOIN routers r
              ON r.profile_id = mt.profile_id
             AND r.router_id = mt.router_id
            WHERE mt.profile_id = ?
            ORDER BY mt.updated_at DESC
            LIMIT 10
            """,
            (profile_id,),
        ).fetchall()

    return {
        "profile_id": profile_id,
        "target_count": target_count,
        "modules": [
            {
                "module_name": row["module_name"],
                "total": row["total"],
                "enabled_count": row["enabled_count"] or 0,
            }
            for row in module_rows
        ],
        "recent_targets": [
            {
                "router_id": row["router_id"],
                "display_name": row["display_name"],
                "enabled": bool(row["enabled"]),
                "bucket": row["bucket"],
                "updated_at": row["updated_at"],
            }
            for row in recent_targets
        ],
    }


@app.get("/monitoring-targets")
async def api_monitoring_targets(profile_id: int = 1, scope: str = Query(default="all")):
    """
    v5: list monitoring targets and their module settings for a dashboard/profile.

    scope:
    - all: all targets
    - direct: only individually added targets where pool_id IS NULL
    - pool: only pool-managed targets where pool_id IS NOT NULL
    """
    scope = str(scope or "all").strip().lower()
    if scope not in {"all", "direct", "pool"}:
        scope = "all"

    where_extra = ""
    params = [profile_id]

    if scope == "direct":
        where_extra = " AND mt.pool_id IS NULL"
    elif scope == "pool":
        where_extra = " AND mt.pool_id IS NOT NULL"

    with db() as conn:
        conn.row_factory = sqlite3.Row

        targets = conn.execute(
            f"""
            SELECT
                mt.profile_id,
                mt.router_id,
                mt.pool_id,
                mt.display_name,
                mt.enabled,
                mt.created_at,
                mt.updated_at,
                r.bucket,
                r.product_name,
                r.router_model,
                r.router_image_path,
                r.last_seen_utc
            FROM monitoring_targets mt
            LEFT JOIN routers r
              ON r.profile_id = mt.profile_id
             AND r.router_id = mt.router_id
            WHERE mt.profile_id = ?
            {where_extra}
            ORDER BY COALESCE(r.bucket, ''), mt.router_id
            """,
            params,
        ).fetchall()

        modules = conn.execute(
            """
            SELECT
                profile_id,
                router_id,
                module_name,
                enabled,
                interval_minutes,
                mode,
                last_polled_at,
                next_poll_after,
                updated_at
            FROM monitoring_target_modules
            WHERE profile_id = ?
            ORDER BY router_id, module_name
            """,
            (profile_id,),
        ).fetchall()

    module_map = {}
    for row in modules:
        module_map.setdefault(row["router_id"], {})[row["module_name"]] = {
            "enabled": bool(row["enabled"]),
            "interval_minutes": row["interval_minutes"],
            "mode": row["mode"],
            "last_polled_at": row["last_polled_at"],
            "next_poll_after": row["next_poll_after"],
            "updated_at": row["updated_at"],
        }

    return {
        "profile_id": profile_id,
        "count": len(targets),
        "targets": [
            {
                "profile_id": row["profile_id"],
                "router_id": row["router_id"],
                "pool_id": row["pool_id"],
                "display_name": row["display_name"],
                "enabled": bool(row["enabled"]),
                "bucket": row["bucket"],
                "product_name": row["product_name"],
                "router_model": row["router_model"],
                "router_image_path": row["router_image_path"],
                "last_seen_utc": row["last_seen_utc"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "modules": module_map.get(row["router_id"], {}),
            }
            for row in targets
        ],
    }



def ensure_monitoring_pool_modules_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS monitoring_pool_modules (
            profile_id INTEGER NOT NULL,
            pool_id INTEGER NOT NULL,
            module_name TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            interval_minutes INTEGER,
            mode TEXT NOT NULL DEFAULT 'disabled',
            updated_at TEXT,
            PRIMARY KEY (profile_id, pool_id, module_name)
        )
    """)


def resolve_pool_id(conn, profile_id: int, pool_name: str):
    pool = conn.execute("""
        SELECT rowid
        FROM monitoring_pools
        WHERE profile_id = ?
          AND name = ?
        LIMIT 1
    """, (profile_id, pool_name)).fetchone()

    if not pool:
        return None

    return pool["rowid"] if hasattr(pool, "keys") else pool[0]


def normalize_module_settings_from_payload(modules: dict):
    if not isinstance(modules, dict):
        raise HTTPException(status_code=400, detail="modules must be an object.")

    normalized = {}

    for module_name, cfg in modules.items():
        if module_name not in MONITORING_MODULES:
            raise HTTPException(status_code=400, detail=f"Unknown module: {module_name}")

        if not isinstance(cfg, dict):
            raise HTTPException(status_code=400, detail=f"Invalid config for module: {module_name}")

        default_cfg = MONITORING_MODULES[module_name]

        enabled = cfg.get("enabled")
        if enabled is None:
            enabled = default_cfg.get("default_enabled", False)

        mode = cfg.get("mode") or default_cfg.get("default_mode", "disabled")
        interval_minutes = cfg.get("interval_minutes", default_cfg.get("default_interval_minutes"))

        if interval_minutes in ("", "null"):
            interval_minutes = None

        if interval_minutes is not None:
            try:
                interval_minutes = int(interval_minutes)
            except Exception:
                raise HTTPException(status_code=400, detail=f"Invalid interval for module: {module_name}")

            if interval_minutes < 1:
                raise HTTPException(status_code=400, detail=f"Interval must be at least 1 minute for module: {module_name}")

        normalized[module_name] = {
            "enabled": 1 if bool(enabled) else 0,
            "mode": mode,
            "interval_minutes": interval_minutes,
        }

    return normalized


def apply_pool_module_defaults_to_router(conn, profile_id: int, pool_name: str, router_id: str):
    ensure_monitoring_pool_modules_table(conn)

    # v5.0.1 fix:
    # monitoring_pools is keyed by (profile_id, name), but monitoring_pool_modules
    # stores the pool reference as pool_id. On clean v5.0.0 builds there is no
    # monitoring_pool_modules.pool_name column, so resolve the pool rowid first.
    pool = conn.execute("""
        SELECT rowid
        FROM monitoring_pools
        WHERE profile_id = ?
          AND name = ?
        LIMIT 1
    """, (profile_id, pool_name)).fetchone()

    if not pool:
        return 0

    pool_id = pool["rowid"] if hasattr(pool, "keys") else pool[0]

    rows = conn.execute("""
        SELECT module_name, enabled, interval_minutes, mode
        FROM monitoring_pool_modules
        WHERE profile_id = ?
          AND pool_id = ?
    """, (profile_id, pool_id)).fetchall()

    if not rows:
        return 0

    ts = now_utc()
    applied = 0

    for row in rows:
        # sqlite rows may be returned either as sqlite3.Row objects or plain tuples
        # depending on which connection helper opened the DB. Keep this tuple-safe
        # so adding routers to pools never crashes on row["column"] access.
        try:
            module_name = row["module_name"] if hasattr(row, "keys") else row[0]
            enabled = row["enabled"] if hasattr(row, "keys") else row[1]
        except (TypeError, KeyError, IndexError):
            module_name = row[0]
            enabled = row[1]
        interval_minutes = row["interval_minutes"] if hasattr(row, "keys") else row[2]
        mode = row["mode"] if hasattr(row, "keys") else row[3]

        conn.execute("""
            INSERT INTO monitoring_target_modules (
                profile_id,
                router_id,
                module_name,
                enabled,
                interval_minutes,
                mode,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(profile_id, router_id, module_name) DO UPDATE SET
                enabled = excluded.enabled,
                interval_minutes = excluded.interval_minutes,
                mode = excluded.mode,
                updated_at = excluded.updated_at
        """, (profile_id, router_id, module_name, enabled, interval_minutes, mode, ts))

        applied += 1

    return applied


@app.get("/pools/modules")
async def api_get_pool_modules(pool_name: str = Query(...), profile_id: int = Query(default=None)):
    profile_id_filter = normalize_profile_id(profile_id)
    pool_name = str(pool_name or "").strip()

    if not pool_name:
        raise HTTPException(status_code=400, detail="pool_name is required.")

    with db() as conn:
        conn.row_factory = sqlite3.Row
        ensure_monitoring_pool_modules_table(conn)

        pool_id = resolve_pool_id(conn, profile_id_filter, pool_name)
        if pool_id is None:
            raise HTTPException(status_code=404, detail="Pool not found.")

        saved = conn.execute("""
            SELECT module_name, enabled, interval_minutes, mode, updated_at
            FROM monitoring_pool_modules
            WHERE profile_id = ?
              AND pool_id = ?
        """, (profile_id_filter, pool_id)).fetchall()

    saved_map = {
        row["module_name"]: {
            "enabled": bool(row["enabled"]),
            "interval_minutes": row["interval_minutes"],
            "mode": row["mode"],
            "updated_at": row["updated_at"],
        }
        for row in saved
    }

    modules = {}
    for module_name, cfg in MONITORING_MODULES.items():
        modules[module_name] = {
            "enabled": bool(cfg.get("default_enabled", False)),
            "interval_minutes": cfg.get("default_interval_minutes"),
            "mode": cfg.get("default_mode", "disabled"),
            "label": cfg.get("label", module_name),
            "description": cfg.get("description", ""),
        }
        if module_name in saved_map:
            modules[module_name].update(saved_map[module_name])

    return {
        "profile_id": profile_id_filter,
        "pool_name": pool_name,
        "pool_id": pool_id,
        "modules": modules,
    }


@app.post("/pools/modules")
async def api_update_pool_modules(payload: dict = Body(default={})):
    profile_id = normalize_profile_id(payload.get("profile_id"))
    pool_name = str(payload.get("pool_name") or "").strip()
    modules = payload.get("modules") or {}

    if not pool_name:
        raise HTTPException(status_code=400, detail="pool_name is required.")

    normalized = normalize_module_settings_from_payload(modules)
    ts = now_utc()

    with db() as conn:
        conn.row_factory = sqlite3.Row
        ensure_monitoring_pool_modules_table(conn)

        pool_id = resolve_pool_id(conn, profile_id, pool_name)
        if pool_id is None:
            raise HTTPException(status_code=404, detail="Pool not found.")

        for module_name, cfg in normalized.items():
            conn.execute("""
                INSERT INTO monitoring_pool_modules (
                    profile_id,
                    pool_id,
                    module_name,
                    enabled,
                    interval_minutes,
                    mode,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(profile_id, pool_id, module_name) DO UPDATE SET
                    enabled = excluded.enabled,
                    interval_minutes = excluded.interval_minutes,
                    mode = excluded.mode,
                    updated_at = excluded.updated_at
            """, (
                profile_id,
                pool_id,
                module_name,
                cfg["enabled"],
                cfg["interval_minutes"],
                cfg["mode"],
                ts,
            ))

        router_rows = conn.execute("""
            SELECT router_id
            FROM routers
            WHERE COALESCE(profile_id, 1) = ?
              AND bucket = ?
        """, (profile_id, pool_name)).fetchall()

        applied = 0
        for row in router_rows:
            applied += apply_pool_module_defaults_to_router(conn, profile_id, pool_name, row["router_id"])

        conn.commit()

    return {
        "status": "pool_modules_updated",
        "profile_id": profile_id,
        "pool_name": pool_name,
        "pool_id": pool_id,
        "modules_saved": len(normalized),
        "routers_updated": len(router_rows),
        "module_settings_applied": applied,
    }


@app.post("/pools/add-routers")
async def api_add_routers_to_pool(payload: dict = Body(default={})):
    pool_name = (payload.get("pool_name") or "").strip()
    router_ids = parse_router_ids(payload.get("router_ids", payload.get("router_ids_text", "")))
    profile_id = payload_profile_id(payload)

    if not pool_name:
        raise HTTPException(status_code=400, detail="pool_name is required.")
    if not router_ids:
        raise HTTPException(status_code=400, detail="No router IDs provided.")

    validation_failures = []
    for rid in router_ids:
        validation = await validate_router_id_for_profile(rid, profile_id)
        if not validation.get("ok"):
            validation_failures.append({
                "router_id": rid,
                "error": validation.get("message") or "Router ID validation failed.",
            })

    if validation_failures:
        preview = "; ".join(f"{item['router_id']}: {item['error']}" for item in validation_failures[:5])
        if len(validation_failures) > 5:
            preview += f"; plus {len(validation_failures) - 5} more."
        raise HTTPException(status_code=400, detail=f"One or more router IDs could not be validated. {preview}")

    ts = now_utc()

    with db() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO monitoring_pools(name, description, created_at, updated_at, profile_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (pool_name, "Created automatically while adding routers.", ts, ts, profile_id),
        )

        conn.execute(
            """
            UPDATE monitoring_pools
            SET updated_at = ?
            WHERE name = ?
              AND COALESCE(profile_id, 1) = ?
            """,
            (ts, pool_name, profile_id),
        )

        pool_row = conn.execute("""
            SELECT rowid
            FROM monitoring_pools
            WHERE profile_id = ?
              AND name = ?
            LIMIT 1
        """, (profile_id, pool_name)).fetchone()

        pool_id = None
        if pool_row:
            pool_id = pool_row["rowid"] if hasattr(pool_row, "keys") else pool_row[0]

        for router_id in router_ids:
              conn.execute(
                  """
                  INSERT INTO routers(router_id, bucket, last_seen_utc, profile_id)
                  VALUES (?, ?, ?, ?)
                  ON CONFLICT(profile_id, router_id) DO UPDATE SET
                      bucket = excluded.bucket,
                      last_seen_utc = excluded.last_seen_utc
                  """,
                  (router_id, pool_name, ts, profile_id),
              )

              # v5: every added router becomes an explicit monitoring target.
              # Pool name remains stored in routers.bucket for v4 compatibility.
              # pool_id uses monitoring_pools.rowid for v5 monitoring_targets/module defaults.
              ensure_monitoring_target(conn, profile_id, router_id, pool_id=pool_id)
              ensure_monitoring_module_defaults(conn, profile_id, router_id)
              apply_pool_module_defaults_to_router(conn, profile_id, pool_name, router_id)

    hydration_results = []
    for router_id in router_ids:
        try:
            result = await poll_router(router_id, include_signal=True, profile_id=profile_id)
            hydration_results.append({
                "router_id": router_id,
                "status": "hydrated",
                "result": result if isinstance(result, dict) else None,
            })
        except Exception as e:
            print(f"[router-provision] Initial hydration failed for {router_id}: {e}")
            hydration_results.append({
                "router_id": router_id,
                "status": "hydration_failed",
                "error": str(e),
            })

    return {
        "status": "routers_added",
        "pool_name": pool_name,
        "profile_id": profile_id,
        "count": len(router_ids),
        "router_ids": router_ids[:25],
        "hydration_results": hydration_results[:25],
    }


@app.post("/pools/remove-router")
async def api_remove_router_from_pool(payload: dict = Body(default={})):
    router_id = (payload.get("router_id") or "").strip()
    delete_history = bool(payload.get("delete_history", False))
    profile_id = payload_profile_id(payload)
    if not router_id:
        raise HTTPException(status_code=400, detail="router_id is required.")

    with db() as conn:
        if delete_history:
            for table in ["routers", "net_devices", "alerts", "locations", "signal_samples", "net_device_metrics", "issues", "issue_comments"]:
                if table == "net_device_metrics":
                    conn.execute("DELETE FROM net_device_metrics WHERE router_id = ?", (router_id,))
                else:
                    conn.execute(f"DELETE FROM {table} WHERE router_id = ?", (router_id,))
        else:
            conn.execute(
                "UPDATE routers SET bucket = 'Unassigned' WHERE router_id = ? AND COALESCE(profile_id, 1) = ?",
                (router_id, profile_id),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO monitoring_pools(name, description, created_at, updated_at)
                VALUES ('Unassigned', 'Routers removed from a pool but retained with historical data.', ?, ?)
                """,
                (now_utc(), now_utc()),
            )
    return {"status": "router_removed", "router_id": router_id, "delete_history": delete_history}


@app.post("/refresh-all")
async def api_refresh_all(payload: dict = Body(default={})):
    include_signal = bool(payload.get("include_signal", False))
    return await refresh_population(include_signal=include_signal)


@app.post("/refresh-router/{router_id}")
async def api_refresh_router(router_id: str, payload: dict = Body(default={})):
    include_signal = bool(payload.get("include_signal", False))
    profile_id = payload_profile_id(payload)
    return await poll_router(router_id, include_signal=include_signal, profile_id=profile_id)






@app.post("/api/cellular/backfill-router-inventory")
async def api_cellular_backfill_router_inventory(profile_id: int = None):
    if profile_id is not None:
        inserted = backfill_router_inventory_from_local_data(profile_id=profile_id)
        return {
            "ok": True,
            "profile_id": int(profile_id),
            "inserted": inserted,
        }

    results = []
    for pid in get_cellular_monitor_profile_ids():
        inserted = backfill_router_inventory_from_local_data(profile_id=pid)
        results.append({
            "profile_id": pid,
            "inserted": inserted,
        })

    return {
        "ok": True,
        "profiles": results,
    }


@app.post("/api/cellular/global-poll")
async def api_cellular_global_poll(profile_id: int = None):
    return await cellular_global_monitor_once(profile_id=profile_id, include_signal=False)



@app.get("/api/cellular/router/{router_id}/summary")
async def api_router_cellular_summary(
    router_id: str,
    profile_id: int = None,
    hours: int = 168,
):
    profile_id = normalize_profile_id(profile_id)
    ensure_cellular_monitor_tables(profile_id)

    since = (datetime.now(timezone.utc) - timedelta(hours=int(hours))).isoformat()

    with db() as conn:
        conn.row_factory = sqlite3.Row

        current_rows = conn.execute("""
            SELECT *
            FROM cellular_current_state
            WHERE router_id = ?
              AND COALESCE(profile_id, 1) = ?
            ORDER BY last_seen_ts DESC
        """, (str(router_id), profile_id)).fetchall()

        total_changes = conn.execute("""
            SELECT COUNT(*) AS c
            FROM cellular_events
            WHERE router_id = ?
              AND COALESCE(profile_id, 1) = ?
              AND event_type != 'first_seen'
              AND detected_at >= ?
        """, (str(router_id), profile_id, since)).fetchone()["c"]

        changes_24h = conn.execute("""
            SELECT COUNT(*) AS c
            FROM cellular_events
            WHERE router_id = ?
              AND COALESCE(profile_id, 1) = ?
              AND event_type != 'first_seen'
              AND detected_at >= ?
        """, (
            str(router_id),
            profile_id,
            (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),
        )).fetchone()["c"]

        changes_7d = conn.execute("""
            SELECT COUNT(*) AS c
            FROM cellular_events
            WHERE router_id = ?
              AND COALESCE(profile_id, 1) = ?
              AND event_type != 'first_seen'
              AND detected_at >= ?
        """, (
            str(router_id),
            profile_id,
            (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(),
        )).fetchone()["c"]

        recent_events = conn.execute("""
            SELECT *
            FROM cellular_events
            WHERE router_id = ?
              AND COALESCE(profile_id, 1) = ?
            ORDER BY detected_at DESC
            LIMIT 25
        """, (str(router_id), profile_id)).fetchall()

        timeline = conn.execute("""
            SELECT
                substr(detected_at, 1, 13) || ':00:00+00:00' AS bucket_utc,
                event_type,
                COUNT(*) AS count
            FROM cellular_events
            WHERE router_id = ?
              AND COALESCE(profile_id, 1) = ?
              AND event_type != 'first_seen'
              AND detected_at >= ?
            GROUP BY bucket_utc, event_type
            ORDER BY bucket_utc ASC
        """, (str(router_id), profile_id, since)).fetchall()

    return {
        "profile_id": profile_id,
        "router_id": str(router_id),
        "hours": int(hours),
        "current": [dict(row) for row in current_rows],
        "changes_24h": changes_24h,
        "changes_7d": changes_7d,
        "changes_window": total_changes,
        "timeline": [dict(row) for row in timeline],
        "recent_events": [dict(row) for row in recent_events],
    }


@app.get("/api/cellular/router/{router_id}/timeline")
async def api_router_cellular_timeline(
    router_id: str,
    profile_id: int = None,
    hours: int = 168,
):
    profile_id = normalize_profile_id(profile_id)
    ensure_cellular_monitor_tables(profile_id)

    since = (datetime.now(timezone.utc) - timedelta(hours=int(hours))).isoformat()

    with db() as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute("""
            SELECT
                substr(detected_at, 1, 13) || ':00:00+00:00' AS bucket_utc,
                COUNT(*) AS change_count
            FROM cellular_events
            WHERE router_id = ?
              AND COALESCE(profile_id, 1) = ?
              AND event_type != 'first_seen'
              AND detected_at >= ?
            GROUP BY bucket_utc
            ORDER BY bucket_utc ASC
        """, (str(router_id), profile_id, since)).fetchall()

    return {
        "profile_id": profile_id,
        "router_id": str(router_id),
        "hours": int(hours),
        "data": [dict(row) for row in rows],
    }


@app.get("/api/cellular/events")
async def api_cellular_events(profile_id: int = None, limit: int = 100):
    profile_id = normalize_profile_id(profile_id)
    ensure_cellular_monitor_tables(profile_id)

    with db() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT *
            FROM cellular_events
            WHERE COALESCE(profile_id, 1) = ?
            ORDER BY detected_at DESC
            LIMIT ?
        """, (profile_id, int(limit))).fetchall()

    return {
        "profile_id": profile_id,
        "count": len(rows),
        "events": [dict(row) for row in rows],
    }

@app.get("/api/cellular/summary")
async def api_cellular_summary(profile_id: int = None):
    profile_id = normalize_profile_id(profile_id)
    ensure_cellular_monitor_tables(profile_id)

    with db() as conn:
        conn.row_factory = sqlite3.Row

        tracked = conn.execute("""
            SELECT COUNT(*) AS c
            FROM cellular_current_state
            WHERE COALESCE(profile_id, 1) = ?
        """, (profile_id,)).fetchone()["c"]

        events = conn.execute("""
            SELECT COUNT(*) AS c
            FROM cellular_events
            WHERE COALESCE(profile_id, 1) = ?
              AND event_type != 'first_seen'
        """, (profile_id,)).fetchone()["c"]

        first_seen = conn.execute("""
            SELECT COUNT(*) AS c
            FROM cellular_events
            WHERE COALESCE(profile_id, 1) = ?
              AND event_type = 'first_seen'
        """, (profile_id,)).fetchone()["c"]

        last_run = conn.execute("""
            SELECT value
            FROM poll_state
            WHERE key = 'cellular_global_monitor_last_run'
        """).fetchone()

    return {
        "profile_id": profile_id,
        "enabled": CELLULAR_MONITOR_ENABLED,
        "poll_interval_seconds": CELLULAR_POLL_INTERVAL_SECONDS,
        "tracked_cellular_devices": tracked,
        "first_seen_events": first_seen,
        "cell_change_events": events,
        "last_global_poll": last_run["value"] if last_run else None,
    }


@app.get("/poll/{router_id}")
async def api_poll_router(router_id: str):
    profile_id = get_default_profile_id()
    return await poll_router(router_id, include_signal=False, profile_id=profile_id)


@app.post("/issue/{issue_id}/comment")
async def add_issue_comment(issue_id: int, payload: dict = Body(...)):
    comment = (payload.get("comment") or "").strip()
    if not comment:
        raise HTTPException(status_code=400, detail="Comment is required")

    with db() as conn:
        conn.row_factory = sqlite3.Row
        issue = conn.execute("SELECT * FROM issues WHERE id = ?", (issue_id,)).fetchone()
        if not issue:
            raise HTTPException(status_code=404, detail="Issue not found")

        conn.execute("""
            INSERT INTO issue_comments(router_id, issue_id, comment, created_at)
            VALUES (?, ?, ?, ?)
        """, (issue["router_id"], issue_id, comment, now_utc()))

    return {"status": "comment_added"}


@app.post("/router/{router_id}/comment")
async def add_router_comment(router_id: str, payload: dict = Body(...)):
    comment = (payload.get("comment") or "").strip()
    if not comment:
        raise HTTPException(status_code=400, detail="Comment is required")

    with db() as conn:
        conn.execute("""
            INSERT INTO issue_comments(router_id, issue_id, comment, created_at)
            VALUES (?, NULL, ?, ?)
        """, (router_id, comment, now_utc()))

    return {"status": "comment_added"}


@app.post("/issue/{issue_id}/resolve")
async def resolve_issue(issue_id: int, payload: dict = Body(default={})):
    note = (payload.get("note") or "").strip()
    non_incident = bool(payload.get("non_incident", False))
    resolution = note or ("Resolved as non-incident." if non_incident else "Resolved.")

    with db() as conn:
        conn.execute("""
            UPDATE issues
            SET status = ?, resolved_at = ?, resolution_note = ?
            WHERE id = ?
        """, ("non_incident" if non_incident else "resolved", now_utc(), resolution, issue_id))

    return {"status": "resolved", "non_incident": non_incident}


@app.post("/issues/resolve-all")
async def resolve_all_issues(payload: dict = Body(default={})):
    note = (payload.get("note") or "Bulk resolved from dashboard.").strip()
    non_incident = bool(payload.get("non_incident", False))
    status = "non_incident" if non_incident else "resolved"

    with db() as conn:
        cur = conn.execute("""
            UPDATE issues
            SET status = ?, resolved_at = ?, resolution_note = ?
            WHERE status = 'open'
        """, (status, now_utc(), note))

    return {"status": status, "resolved_count": cur.rowcount}


@app.get("/notes/general")
async def get_general_notes():
    with db() as conn:
        conn.row_factory = sqlite3.Row
        notes = conn.execute("""
            SELECT * FROM general_notes
            ORDER BY created_at DESC
            LIMIT 100
        """).fetchall()

    out = []
    for n in notes:
        item = dict(n)
        item["created_at_local"] = to_local_string(item.get("created_at"))
        out.append(item)
    return {"notes": out}


@app.post("/notes/general")
async def add_general_note(payload: dict = Body(...)):
    note = (payload.get("note") or "").strip()
    if not note:
        raise HTTPException(status_code=400, detail="Note is required")

    with db() as conn:
        conn.execute("""
            INSERT INTO general_notes(note, created_at)
            VALUES (?, ?)
        """, (note, now_utc()))

    return {"status": "note_added"}


@app.post("/router/{router_id}/mark-expected-store-cycle")
async def mark_expected_store_cycle(router_id: str, payload: dict = Body(default={})):
    note = (payload.get("note") or "Marked as expected operational behavior.").strip()

    with db() as conn:
        conn.execute("""
            INSERT INTO issue_comments(router_id, issue_id, comment, created_at)
            VALUES (?, NULL, ?, ?)
        """, (router_id, note, now_utc()))

        conn.execute("""
            UPDATE issues
            SET status = 'non_incident',
                resolved_at = ?,
                resolution_note = ?
            WHERE router_id = ?
              AND status = 'open'
              AND issue_type IN ('business_hours_reboot', 'repeated_reboots_12h')
        """, (now_utc(), note, router_id))

    return {"status": "marked_expected_store_cycle"}


@app.post("/router/{router_id}/mark-review")
async def mark_router_for_review(router_id: str, payload: dict = Body(default={})):
    note = (payload.get("note") or "Manually marked for further review.").strip()

    with db() as conn:
        upsert_issue(
            conn,
            router_id,
            "manual_further_review",
            "manual_review",
            note or "Manually marked for further review."
        )
        conn.execute("""
            INSERT INTO issue_comments(router_id, issue_id, comment, created_at)
            VALUES (?, NULL, ?, ?)
        """, (router_id, note, now_utc()))

    return {"status": "marked_for_review"}


@app.get("/dashboard-data")
async def dashboard_data(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=5, le=100),
    tab: str = Query("Active Issues"),
    counter_filter: str = Query(""),
    search: str = Query(""),
    profile_id: int = Query(default=None),
):
    """Server-side paginated dashboard payload.

    The browser only receives the routers for the current page instead of the
    full monitoring population. Counts are still calculated server-side for the
    currently selected view/filter.
    """
    profile_id_filter = normalize_profile_id(profile_id)

    def build_where(selected_counter=None):
        clauses = ["COALESCE(r.profile_id, 1) = ?"]
        params = [profile_id_filter]

        q = (search or "").strip().lower()
        if q:
            clauses.append("LOWER(r.router_id) LIKE ?")
            params.append(f"%{q}%")

        filter_value = (selected_counter if selected_counter is not None else counter_filter or "").strip()

        if filter_value == "needs_review":
            clauses.append("""
                EXISTS (
                    SELECT 1 FROM issues i
                    WHERE i.router_id = r.router_id
                      AND i.status = 'open'
                      AND i.severity = 'needs_review'
                )
            """)
        elif filter_value == "manual_review":
            clauses.append("""
                EXISTS (
                    SELECT 1 FROM issues i
                    WHERE i.router_id = r.router_id
                      AND i.status = 'open'
                      AND i.severity = 'manual_review'
                )
            """)
        elif filter_value == "watch":
            clauses.append("""
                EXISTS (
                    SELECT 1 FROM issues i
                    WHERE i.router_id = r.router_id
                      AND i.status = 'open'
                      AND i.severity = 'watch'
                )
            """)
        elif filter_value == "active":
            clauses.append("""
                EXISTS (
                    SELECT 1 FROM issues i
                    WHERE i.router_id = r.router_id
                      AND i.status = 'open'
                      AND i.severity IN ('needs_review', 'manual_review', 'watch')
                )
            """)
        elif filter_value == "store_power_cycle":
            clauses.append("""
                EXISTS (
                    SELECT 1 FROM issues i
                    WHERE i.router_id = r.router_id
                      AND i.status = 'open'
                      AND i.severity = 'store_power_cycle'
                )
            """)
        elif filter_value == "connected":
            clauses.append("""
                EXISTS (
                    SELECT 1 FROM net_devices nd
                    WHERE nd.router_id = r.router_id
                      AND nd.connection_state = 'connected'
                )
            """)
        else:
            if tab == "Active Issues":
                clauses.append("""
                    EXISTS (
                        SELECT 1 FROM issues i
                        WHERE i.router_id = r.router_id
                          AND i.status = 'open'
                          AND i.severity IN ('needs_review', 'manual_review', 'watch')
                    )
                """)
            elif tab == "Needs Review":
                clauses.append("""
                    EXISTS (
                        SELECT 1 FROM issues i
                        WHERE i.router_id = r.router_id
                          AND i.status = 'open'
                          AND i.severity = 'needs_review'
                    )
                """)
            elif tab == "Marked for Review":
                clauses.append("""
                    EXISTS (
                        SELECT 1 FROM issues i
                        WHERE i.router_id = r.router_id
                          AND i.status = 'open'
                          AND i.severity = 'manual_review'
                    )
                """)
            elif tab == "Watch":
                clauses.append("""
                    EXISTS (
                        SELECT 1 FROM issues i
                        WHERE i.router_id = r.router_id
                          AND i.status = 'open'
                          AND i.severity = 'watch'
                    )
                """)
            elif tab == "Operational Timing Indicators":
                clauses.append("""
                    EXISTS (
                        SELECT 1 FROM issues i
                        WHERE i.router_id = r.router_id
                          AND i.status = 'open'
                          AND i.severity = 'store_power_cycle'
                    )
                """)
            elif tab == "All Routers":
                pass
            else:
                clauses.append("r.bucket = ?")
                params.append(tab)

        where_sql = "WHERE " + " AND ".join(f"({c})" for c in clauses) if clauses else ""
        return where_sql, params

    with db() as conn:
        conn.row_factory = sqlite3.Row

        where_sql, params = build_where()

        total_count = conn.execute(
            f"SELECT COUNT(*) AS c FROM routers r {where_sql}",
            params,
        ).fetchone()["c"]

        total_pages = max(1, (int(total_count) + page_size - 1) // page_size)
        page = min(page, total_pages)
        offset = (page - 1) * page_size

        routers = conn.execute(f"""
            SELECT
                r.router_id,
                r.bucket,
                r.last_seen_utc,
                l.latitude,
                l.longitude,
                l.method,
                l.updated_at AS location_updated_at,
                ll.label AS location_label,
                (
                    SELECT friendly_info
                    FROM alerts a
                    WHERE a.router_id = r.router_id
                      AND a.created_at >= ?
                    ORDER BY a.created_at DESC
                    LIMIT 1
                ) AS last_alert,
                (
                    SELECT created_at
                    FROM alerts a
                    WHERE a.router_id = r.router_id
                      AND a.created_at >= ?
                    ORDER BY a.created_at DESC
                    LIMIT 1
                ) AS last_alert_utc
            FROM routers r
            LEFT JOIN locations l ON l.router_id = r.router_id
            LEFT JOIN location_labels ll ON ll.router_id = r.router_id
            {where_sql}
            ORDER BY r.bucket, r.router_id
            LIMIT ? OFFSET ?
        """, (MONITORING_START_UTC, MONITORING_START_UTC, *params, page_size, offset)).fetchall()

        rows = []
        for router in routers:
            sims = conn.execute("""
                SELECT
                    sim_label,
                    carrier,
                    connection_state,
                    service_type,
                    uptime,
                    id AS net_device_id
                FROM net_devices
                WHERE router_id = ?
                ORDER BY sim_label
            """, (router["router_id"],)).fetchall()

            open_issues = conn.execute("""
                SELECT id, issue_type, severity, summary, first_seen, last_seen
                FROM issues
                WHERE router_id = ?
                  AND status = 'open'
                ORDER BY
                    CASE severity
                        WHEN 'needs_review' THEN 1
                        WHEN 'manual_review' THEN 2
                        WHEN 'watch' THEN 3
                        WHEN 'store_power_cycle' THEN 4
                        ELSE 5
                    END,
                    last_seen DESC
            """, (router["router_id"],)).fetchall()

            avg_signal = conn.execute("""
                SELECT
                    ROUND(AVG(rsrp), 1) AS avg_rsrp,
                    ROUND(AVG(rsrq), 1) AS avg_rsrq,
                    ROUND(AVG(sinr), 1) AS avg_sinr,
                    ROUND(AVG(dbm), 1) AS avg_dbm
                FROM signal_samples
                WHERE router_id = ?
                  AND created_at >= ?
            """, (router["router_id"], MONITORING_START_UTC)).fetchone()

            usage_30d = conn.execute("""
                SELECT COALESCE(SUM(total_bytes), 0) AS total_bytes
                FROM usage_samples
                WHERE router_id = ?
                  AND created_at >= ?
            """, (router["router_id"], MONITORING_START_UTC)).fetchone()

            d = dict(router)
            platform = platform_from_bucket(d.get("bucket"))
            d["platform_label"] = platform["label"]
            d["platform_image_url"] = platform["image_url"]
            d["last_seen_local"] = to_local_string(d.get("last_seen_utc"))
            d["last_alert_local"] = to_local_string(d.get("last_alert_utc"))
            d["sims"] = [dict(s) for s in sims]
            d["issues"] = [dict(i) for i in open_issues]
            d["avg_signal_30d"] = dict(avg_signal) if avg_signal else {}
            d["usage_30d_bytes"] = float(usage_30d["total_bytes"] if usage_30d else 0)
            rows.append(d)

        def count_for(filter_name: str):
            w, ps = build_where(filter_name)
            return conn.execute(f"SELECT COUNT(*) AS c FROM routers r {w}", ps).fetchone()["c"]

        summary = {
            "total": int(total_count),
            "needs_review": int(count_for("needs_review")),
            "manual_review": int(count_for("manual_review")),
            "watch": int(count_for("watch")),
            "active": int(count_for("active")),
            "store_power_cycle": int(count_for("store_power_cycle")),
            "connected": int(count_for("connected")),
        }

        pools = pool_counts(conn, profile_id_filter)

    return {
        "routers": rows,
        "pools": pools,
        "summary": summary,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": int(total_count),
            "total_pages": int(total_pages),
            "has_previous": page > 1,
            "has_next": page < total_pages,
        },
        "local_timezone": LOCAL_TZ_NAME,
        "monitoring_start_local": MONITORING_START_LOCAL.strftime("%Y-%m-%d %H:%M:%S %Z"),
    }


@app.get("/pool-admin-data")
async def pool_admin_data(profile_id: int = Query(default=None)):
    """Small admin payload for pool management, scoped to the selected dashboard/profile."""
    profile_id_filter = normalize_profile_id(profile_id)

    with db() as conn:
        conn.row_factory = sqlite3.Row
        routers = conn.execute("""
            SELECT
                r.router_id,
                r.bucket,
                r.last_seen_utc,
                (
                    SELECT a.friendly_info
                    FROM alerts a
                    WHERE a.router_id = r.router_id
                      AND a.created_at >= ?
                    ORDER BY a.created_at DESC
                    LIMIT 1
                ) AS last_alert
            FROM routers r
            WHERE COALESCE(r.profile_id, 1) = ?
            ORDER BY r.bucket, r.router_id
        """, (MONITORING_START_UTC, profile_id_filter)).fetchall()
        pools = pool_counts(conn, profile_id_filter)

    return {
        "profile_id": profile_id_filter,
        "routers": [dict(r) for r in routers],
        "pools": pools,
    }


@app.get("/router/{router_id}/detail")
async def router_detail(
    router_id: str,
    profile_id: int = Query(default=None),
    days: int = Query(default=30, ge=1, le=90),
    start_date: str = Query(default=None),
    end_date: str = Query(default=None),
    cache_only: bool = Query(default=False),
):
    profile_id_filter = normalize_profile_id(profile_id)
    monitoring_modules = {}

    range_mode = "preset"
    custom_start_date = None
    custom_end_date = None

    # Direct Python calls can leave FastAPI Query(...) defaults in these vars.
    # Treat anything that is not an actual string value as unset.
    if not isinstance(start_date, str):
        start_date = None
    if not isinstance(end_date, str):
        end_date = None

    if start_date and end_date:
        try:
            start_day = datetime.fromisoformat(str(start_date)[:10]).date()
            end_day = datetime.fromisoformat(str(end_date)[:10]).date()
        except Exception:
            raise HTTPException(status_code=400, detail="Custom date range must use YYYY-MM-DD dates.")

        if end_day < start_day:
            raise HTTPException(status_code=400, detail="Custom end date must be on or after start date.")

        selected_days = (end_day - start_day).days + 1
        if selected_days > 90:
            raise HTTPException(status_code=400, detail="Custom date range cannot exceed 90 days.")

        range_mode = "custom"
        custom_start_date = start_day.isoformat()
        custom_end_date = end_day.isoformat()
        start_dt = datetime.combine(start_day, datetime.min.time(), tzinfo=timezone.utc)
        end_exclusive_dt = datetime.combine(end_day + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc)
        detail_since_utc = start_dt.isoformat()
        detail_until_utc = end_exclusive_dt.isoformat()
    else:
        selected_days = int(days or 30)
        selected_days = max(1, min(selected_days, 90))
        now_dt = datetime.now(timezone.utc)
        detail_since_utc = (now_dt - timedelta(days=selected_days)).isoformat()
        detail_until_utc = (now_dt + timedelta(days=1)).isoformat()


    # router_detail_signal_backfill:
    # If the user requests a wider Signal chart range, pull signal samples for
    # that same range before querying daily_signal. This makes Last 90 Days
    # actually load 90-day signal data when NCM has samples available.
    if int(selected_days or 30) > 30 and not cache_only:
        try:
            with db() as sig_conn:
                sig_conn.row_factory = sqlite3.Row
                signal_devices = sig_conn.execute("""
                    SELECT id, COALESCE(sim_label, '') AS sim_label
                    FROM net_devices
                    WHERE router_id = ?
                    ORDER BY sim_label, id
                """, (router_id,)).fetchall()

            for nd in signal_devices:
                await poll_signal_samples(
                    router_id,
                    str(nd["id"]),
                    nd["sim_label"] or "",
                    profile_id=profile_id_filter,
                    days=int(selected_days or 30),
                )
        except Exception as exc:
            print(f"[router-detail-signal-backfill] router={router_id} days={selected_days} failed: {exc}")



    # router_detail_usage_backfill:
    # If the user requests a wider Usage chart range, pull SIM/WAN usage and
    # NCM/router-stream usage for that same range before querying daily_usage.
    if int(selected_days or 30) > 30 and not cache_only:
        try:
            with db() as usage_conn:
                usage_conn.row_factory = sqlite3.Row
                usage_devices = usage_conn.execute("""
                    SELECT id, COALESCE(sim_label, '') AS sim_label
                    FROM net_devices
                    WHERE router_id = ?
                    ORDER BY sim_label, id
                """, (router_id,)).fetchall()

            for nd in usage_devices:
                await poll_usage_samples(
                    router_id,
                    str(nd["id"]),
                    nd["sim_label"] or "",
                    profile_id=profile_id_filter,
                    days=int(selected_days or 30),
                )

            await poll_router_stream_usage_samples(
                router_id,
                profile_id=profile_id_filter,
                days=int(selected_days or 30),
            )
        except Exception as exc:
            print(f"[router-detail-usage-backfill] router={router_id} days={selected_days} failed: {exc}")


    with db() as conn:
        conn.row_factory = sqlite3.Row

        router = conn.execute(
            "SELECT * FROM routers WHERE router_id = ? AND COALESCE(profile_id, 1) = ?",
            (router_id, profile_id_filter),
        ).fetchone()

        sims = conn.execute("""
            WITH ranked_net_devices AS (
                SELECT
                    nd.*,
                    ROW_NUMBER() OVER (
                        PARTITION BY COALESCE(nd.sim_label, nd.mfg_product, nd.id)
                        ORDER BY
                            COALESCE(nd.updated_at, '') DESC,
                            CAST(nd.id AS INTEGER) DESC
                    ) AS rn
                FROM net_devices nd
                WHERE nd.router_id = ?
            )
            SELECT
                nd.*,
                m.mcc,
                m.mnc,
                m.tac,
                m.cell_id,

                COALESCE(m.dbm, latest_ss.dbm) AS dbm,
                COALESCE(m.rsrp, latest_ss.rsrp) AS rsrp,
                COALESCE(m.rsrq, latest_ss.rsrq) AS rsrq,
                COALESCE(m.sinr, latest_ss.sinr) AS sinr,

                m.signal_strength,
                COALESCE(m.update_ts, latest_ss.created_at, nd.updated_at) AS update_ts,

                CASE
                  WHEN m.rsrp IS NOT NULL OR m.rsrq IS NOT NULL OR m.sinr IS NOT NULL THEN 'net_device_metrics'
                  WHEN latest_ss.created_at IS NOT NULL THEN 'latest_signal_sample'
                  ELSE 'unavailable'
                END AS signal_source

            FROM ranked_net_devices nd
            LEFT JOIN net_device_metrics m ON m.net_device_id = nd.id
            LEFT JOIN signal_samples latest_ss
              ON latest_ss.created_at_timeuuid = (
                SELECT ss.created_at_timeuuid
                FROM signal_samples ss
                WHERE ss.router_id = nd.router_id
                  AND ss.net_device_id = nd.id
                ORDER BY ss.created_at DESC
                LIMIT 1
              )
            WHERE nd.rn = 1
            ORDER BY nd.sim_label
        """, (router_id,)).fetchall()

        alerts = conn.execute("""
            SELECT * FROM alerts
            WHERE router_id = ?
              AND created_at >= ?
              AND created_at < ?
            ORDER BY created_at DESC
            LIMIT 100
        """, (router_id, detail_since_utc, detail_until_utc)).fetchall()

        location = conn.execute(
            """
            SELECT l.*, ll.label AS location_label, ll.city, ll.state
            FROM locations l
            LEFT JOIN location_labels ll ON ll.router_id = l.router_id
            WHERE l.router_id = ?
            """,
            (router_id,),
        ).fetchone()

        issues = conn.execute("""
            SELECT * FROM issues
            WHERE router_id = ?
            ORDER BY
                CASE status
                    WHEN 'open' THEN 1
                    ELSE 2
                END,
                CASE severity
                    WHEN 'needs_review' THEN 1
                    WHEN 'manual_review' THEN 2
                    WHEN 'watch' THEN 3
                    WHEN 'store_power_cycle' THEN 4
                    ELSE 5
                END,
                last_seen DESC
        """, (router_id,)).fetchall()

        comments = conn.execute("""
            SELECT * FROM issue_comments
            WHERE router_id = ?
            ORDER BY created_at DESC
            LIMIT 50
        """, (router_id,)).fetchall()

        daily_signal = conn.execute("""
            SELECT
                substr(created_at, 1, 10) AS day,
                sim_label,
                ROUND(AVG(rsrp), 1) AS avg_rsrp,
                ROUND(AVG(rsrq), 1) AS avg_rsrq,
                ROUND(AVG(sinr), 1) AS avg_sinr,
                ROUND(AVG(dbm), 1) AS avg_dbm
            FROM signal_samples
            WHERE router_id = ?
              AND created_at >= ?
              AND created_at < ?
            GROUP BY day, sim_label
            ORDER BY day ASC, sim_label ASC
        """, (router_id, detail_since_utc, detail_until_utc)).fetchall()

        daily_alerts = conn.execute("""
            SELECT
                substr(created_at, 1, 10) AS day,
                type,
                COUNT(*) AS count
            FROM alerts
            WHERE router_id = ?
              AND created_at >= ?
              AND created_at < ?
            GROUP BY day, type
            ORDER BY day ASC, type ASC
        """, (router_id, detail_since_utc, detail_until_utc)).fetchall()

        daily_usage = conn.execute("""
            SELECT
                substr(created_at, 1, 10) AS day,
                sim_label,
                COALESCE(SUM(bytes_in), 0) AS bytes_in,
                COALESCE(SUM(bytes_out), 0) AS bytes_out,
                COALESCE(SUM(total_bytes), 0) AS total_bytes,
                ROUND(COALESCE(SUM(bytes_in), 0) / 1024.0 / 1024.0, 3) AS in_mb,
                ROUND(COALESCE(SUM(bytes_out), 0) / 1024.0 / 1024.0, 3) AS out_mb,
                ROUND(COALESCE(SUM(total_bytes), 0) / 1024.0 / 1024.0, 3) AS total_mb
            FROM usage_samples
            WHERE router_id = ?
              AND created_at >= ?
              AND created_at < ?
            GROUP BY day, sim_label
            ORDER BY day ASC, sim_label ASC
        """, (router_id, detail_since_utc, detail_until_utc)).fetchall()

        daily_ncm_usage = conn.execute("""
            SELECT
                substr(created_at, 1, 10) AS day,
                'NCM cloud traffic' AS sim_label,
                COALESCE(SUM(bytes_in), 0) AS bytes_in,
                COALESCE(SUM(bytes_out), 0) AS bytes_out,
                COALESCE(SUM(total_bytes), 0) AS total_bytes,
                ROUND(COALESCE(SUM(bytes_in), 0) / 1024.0 / 1024.0, 3) AS ncm_in_mb,
                ROUND(COALESCE(SUM(bytes_out), 0) / 1024.0 / 1024.0, 3) AS ncm_out_mb,
                ROUND(COALESCE(SUM(total_bytes), 0) / 1024.0 / 1024.0, 3) AS ncm_total_mb
            FROM router_stream_usage_samples
            WHERE router_id = ?
              AND created_at >= ?
              AND created_at < ?
            GROUP BY day
            ORDER BY day ASC
        """, (router_id, detail_since_utc, detail_until_utc)).fetchall()

    alerts_out = []
    for a in alerts:
        item = dict(a)
        item["created_at_local"] = to_local_string(item.get("created_at"))
        item["detected_at_local"] = to_local_string(item.get("detected_at"))
        alerts_out.append(item)

    issues_out = []
    for issue in issues:
        item = dict(issue)
        item["first_seen_local"] = to_local_string(item.get("first_seen"))
        item["last_seen_local"] = to_local_string(item.get("last_seen"))
        item["resolved_at_local"] = to_local_string(item.get("resolved_at"))
        issues_out.append(item)

    comments_out = []
    for c in comments:
        item = dict(c)
        item["created_at_local"] = to_local_string(item.get("created_at"))
        comments_out.append(item)

    router_out = dict(router) if router else None
    if router_out:
        router_out["last_seen_local"] = to_local_string(router_out.get("last_seen_utc"))

    if router_out is None:
        router_out = {"router_id": router_id, "bucket": "Unknown", "last_seen_local": ""}


    # Build router monitoring module settings for graph-level controls.
    with db() as module_conn:
        module_conn.row_factory = sqlite3.Row
        monitoring_module_rows = module_conn.execute("""
            SELECT module_name, enabled, interval_minutes, mode, updated_at
            FROM monitoring_target_modules
            WHERE profile_id = ?
              AND router_id = ?
        """, (profile_id_filter, router_id)).fetchall()

        monitoring_module_map = {row["module_name"]: dict(row) for row in monitoring_module_rows}
        monitoring_modules = {}

        for module_name, cfg in MONITORING_MODULES.items():
            if cfg.get("user_visible") is False:
                continue

            row = monitoring_module_map.get(module_name)
            monitoring_modules[module_name] = {
                "label": cfg.get("label", module_name),
                "enabled": bool(row["enabled"]) if row else bool(cfg.get("default_enabled", False)),
                "mode": row["mode"] if row else cfg.get("default_mode", "disabled"),
                "interval_minutes": row["interval_minutes"] if row else cfg.get("default_interval_minutes"),
                "default_enabled": bool(cfg.get("default_enabled", False)),
                "default_mode": cfg.get("default_mode", "disabled"),
                "default_interval_minutes": cfg.get("default_interval_minutes"),
                "updated_at": row["updated_at"] if row else None,
            }

    return {
        "profile_id": profile_id_filter,
        "router": router_out,
        "sims": [dict(s) for s in sims],
        "alerts": alerts_out,
        "location": dict(location) if location else None,
        "issues": issues_out,
        "comments": comments_out,
        "selected_days": int(selected_days),
        "range_mode": range_mode,
        "custom_start_date": custom_start_date,
        "custom_end_date": custom_end_date,
        "detail_since_utc": detail_since_utc,
        "detail_until_utc": detail_until_utc,
        "daily_signal": [dict(d) for d in daily_signal],
        "daily_alerts": [dict(d) for d in daily_alerts],
        "daily_usage": [dict(d) for d in daily_usage],
        "daily_ncm_usage": [dict(d) for d in daily_ncm_usage],
        "monitoring_modules": monitoring_modules,
        "local_timezone": LOCAL_TZ_NAME,
        "monitoring_start_local": MONITORING_START_LOCAL.strftime("%Y-%m-%d %H:%M:%S %Z"),
    }


@app.get("/ui", response_class=HTMLResponse)
async def ui():
    return """
<!DOCTYPE html>
<html>
<head>
  <title>NCM Monitor</title>
  <style>
    body { font-family: Arial, sans-serif; background: #0f172a; color: #e5e7eb; padding: 28px; }
    h1 { margin-bottom: 4px; }
    .sub { color: #94a3b8; margin-bottom: 20px; }
    .tabs button, .action {
      background: #1e293b; color: #e5e7eb; border: 1px solid #334155;
      border-radius: 999px; padding: 9px 13px; cursor: pointer; margin: 4px;
    }
    .tabs button.active, .action.primary { background: #2563eb; border-color: #60a5fa; }
    input {
      background: #020617; color: #e5e7eb; border: 1px solid #334155;
      border-radius: 10px; padding: 10px; width: 280px; margin: 12px 0;
    }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin: 20px 0; }
    .stat, .card {
      background: #111827; border: 1px solid #1f2937; border-radius: 18px;
      padding: 16px; box-shadow: 0 20px 35px rgba(0,0,0,.20);
    }
    .stat { cursor: pointer; }
    .stat:hover { border-color: #38bdf8; }
    .stat .num { font-size: 30px; font-weight: bold; }
    .stat .label, .small { color: #94a3b8; font-size: 13px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(390px, 1fr)); gap: 16px; }
    .bucket { color: #38bdf8; font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
    .router { font-size: 21px; font-weight: bold; margin: 8px 0; }
    .pill { display: inline-block; padding: 4px 9px; border-radius: 999px; background: #1e293b; margin: 3px; font-size: 13px; }
    .ok { color: #22c55e; } .watch { color: #facc15; } .review { color: #fb7185; } .store { color: #38bdf8; }
    .sig-excellent { color:#22c55e; font-weight:700; }
    .sig-good { color:#eab308; font-weight:700; }
    .sig-fair { color:#fb923c; font-weight:700; }
    .sig-poor { color:#fb7185; font-weight:700; }
    .card { cursor: pointer; position: relative; overflow: hidden; } .card:hover { border-color: #38bdf8; }
    .card-actions { margin-top:12px; display:flex; gap:8px; flex-wrap:wrap; }
    .logs-modal-back {
      display:none; position:fixed; inset:0; background:rgba(0,0,0,.72);
      z-index:1000000; align-items:center; justify-content:center; padding:24px;
    }
    .logs-modal {
      width:min(1180px,96vw); max-height:88vh; overflow:hidden;
      background:#111827; border:1px solid #334155; border-radius:22px;
      box-shadow:0 28px 90px rgba(0,0,0,.65); display:flex; flex-direction:column;
    }
    .logs-modal-top {
      display:flex; justify-content:space-between; align-items:flex-start; gap:14px;
      padding:18px 20px; border-bottom:1px solid #1f2937;
      background:linear-gradient(135deg,#172554,#0f172a);
    }
    .logs-modal-top h2 { margin:0; font-size:22px; }
    .logs-toolbar {
      display:flex; gap:10px; flex-wrap:wrap; align-items:center;
      padding:14px 20px; border-bottom:1px solid #1f2937;
    }
    .logs-toolbar select {
      background:#020617; color:#e5e7eb; border:1px solid #334155;
      border-radius:999px; padding:9px 12px;
    }
    .logs-body { overflow:auto; padding:0 20px 20px; }
    .logs-table {
      width:100%; border-collapse:collapse; margin-top:14px; font-size:13px;
    }
    .logs-table th {
      position:sticky; top:0; background:#1e293b; color:#e5e7eb;
      text-align:left; padding:10px; border-bottom:1px solid #334155; z-index:1;
    }
    .logs-table td {
      vertical-align:top; padding:9px 10px; border-bottom:1px solid #1f2937;
    }
    .logs-message { max-width:700px; white-space:pre-wrap; word-break:break-word; }
    .level-ERR, .level-ERROR, .level-CRIT, .level-CRITICAL { color:#fecdd3; font-weight:800; }
    .level-WARN, .level-WARNING { color:#fde68a; font-weight:800; }
    .level-NOTICE { color:#bfdbfe; font-weight:800; }
    .level-INFO { color:#bbf7d0; font-weight:800; }
    .level-DEBUG { color:#cbd5e1; font-weight:800; }
    .device-thumb {
      position: absolute; top: 14px; right: 14px; width: 92px; max-height: 62px;
      object-fit: contain; opacity: .86; filter: drop-shadow(0 12px 18px rgba(0,0,0,.35));
      pointer-events: none;
    }
    .card-body-pad { padding-right: 105px; }
    .topbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 16px; }
    .hero {
      background: radial-gradient(circle at top left, #1d4ed8 0, #0f172a 42%, #020617 100%);
      border: 1px solid #334155;
      border-radius: 22px;
      padding: 24px;
      margin-bottom: 18px;
      box-shadow: 0 24px 45px rgba(0,0,0,.28);
    }
    .hero h1 { margin: 0; font-size: 34px; letter-spacing: -0.03em; }
    .tagline { margin-top: 8px; color: #cbd5e1; font-size: 15px; }
    .version { margin-top: 10px; color: #94a3b8; font-size: 12px; }
    .danger { border-color: #fb7185 !important; }
    textarea {
      width: 100%; min-height: 70px; resize: vertical; box-sizing: border-box;
      background: #020617; color: #e5e7eb; border: 1px solid #334155;
      border-radius: 12px; padding: 10px; margin: 8px 0;
    }
    .general-notes { cursor: default; margin-bottom: 16px; }
    .router-deep-dive { cursor: default; margin-bottom: 16px; }
    .router-deep-dive-controls { display:flex; flex-wrap:wrap; align-items:center; gap:8px; margin:10px 0; }
    .router-deep-dive textarea { min-height:92px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    .deep-dive-options { display:flex; flex-wrap:wrap; gap:10px; margin:10px 0; }
    .deep-dive-options label { background:#020617; border:1px solid #334155; border-radius:999px; padding:8px 11px; cursor:pointer; }
    .deep-dive-options input { width:auto; margin:0 6px 0 0; }
    select { background:#020617; color:#e5e7eb; border:1px solid #334155; border-radius:10px; padding:9px; }
    .mini-table { width:100%; border-collapse:collapse; margin-top:10px; font-size:13px; }
    .mini-table th, .mini-table td { border-bottom:1px solid #1f2937; padding:8px; text-align:left; vertical-align:top; }
    .mini-table th { color:#cbd5e1; background:#0f172a; }
    .note-item { border-top: 1px solid #1f2937; padding-top: 8px; margin-top: 8px; }
    .pager {
      display:flex; flex-wrap:wrap; align-items:center; justify-content:center; gap:10px;
      margin:22px 0 8px 0; color:#94a3b8;
    }
    .pager select {
      background:#020617; color:#e5e7eb; border:1px solid #334155; border-radius:10px; padding:8px;
    }
  



#apiOdometer {
  position: fixed;
  top: 18px;
  right: 22px;
  z-index: 99999;
  width: 210px;
  background: linear-gradient(135deg, rgba(16,32,51,.97), rgba(24,50,80,.97));
  color: #fff;
  border: 1px solid rgba(255,255,255,.18);
  border-radius: 18px;
  padding: 12px 14px;
  box-shadow: 0 18px 40px rgba(0,0,0,.30);
  text-align: right;
  backdrop-filter: blur(8px);
}
#apiOdometer .odo-top {
  display: flex;
  justify-content: flex-end;
  align-items: center;
  gap: 7px;
  font-size: 11px;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: .06em;
  opacity: .88;
}
#apiOdometer .odo-dot {
  width: 8px;
  height: 8px;
  border-radius: 999px;
  background: #40d67d;
  box-shadow: 0 0 12px rgba(64,214,125,.9);
}
#apiOdometer .odo-main {
  margin-top: 3px;
  font-size: 28px;
  font-weight: 900;
  line-height: 1.05;
}
#apiOdometer .odo-sub {
  font-size: 11px;
  opacity: .72;
  margin-top: 2px;
}
#apiOdometer .odo-footer {
  margin-top: 7px;
  padding-top: 7px;
  border-top: 1px solid rgba(255,255,255,.14);
  font-size: 11px;
  opacity: .82;
}
@media (max-width: 900px) {
  #apiOdometer {
    position: static;
    width: auto;
    margin: 10px 0 16px 0;
    text-align: left;
  }
  #apiOdometer .odo-top {
    justify-content: flex-start;
  }
}

</style>
</head>
<body>
<div id="activeProfileBranding" style="margin:18px 18px 10px 18px;background:linear-gradient(135deg,#102042,#0b1220);border:1px solid #263449;border-radius:20px;padding:18px 20px;display:flex;align-items:center;gap:16px;box-shadow:0 18px 40px rgba(0,0,0,.28);">
  <div id="activeProfileLogoBox" style="width:76px;height:76px;border-radius:18px;background:#020617;border:1px solid #334155;display:flex;align-items:center;justify-content:center;overflow:hidden;font-size:32px;font-weight:900;color:#60a5fa;flex:0 0 auto;">?</div>
  <div>
    <div id="activeProfileName" style="font-size:28px;font-weight:900;line-height:1.1;">Dashboard</div>
    <div id="activeProfileCompany" style="font-size:14px;color:#93c5fd;margin-top:4px;"></div>
    <div id="activeProfilePurpose" style="font-size:13px;color:#cbd5e1;margin-top:6px;"></div>
  </div>
</div>

<a id="dashboardSwitcher" href="/launcher" style="position:fixed;top:18px;left:22px;z-index:999998;background:linear-gradient(135deg,#2563eb,#1d4ed8);color:white;text-decoration:none;border-radius:14px;padding:10px 14px;font-weight:800;font-size:13px;box-shadow:0 14px 30px rgba(0,0,0,.30);border:1px solid rgba(255,255,255,.16);">Switch Dashboard</a>

<div id="apiOdometer" aria-label="NCM API odometer" style="position:fixed;top:18px;right:22px;z-index:999999;width:230px;background:linear-gradient(135deg,rgba(15,23,42,.98),rgba(30,64,105,.98));color:#f8fafc;border:1px solid rgba(255,255,255,.18);border-radius:18px;padding:13px 15px;box-shadow:0 18px 42px rgba(0,0,0,.35);text-align:right;font-family:inherit;">
  <div style="font-size:11px;font-weight:800;letter-spacing:.07em;text-transform:uppercase;opacity:.82;">NCM API Odometer</div>
  <div id="odoMonth" style="margin-top:3px;font-size:30px;line-height:1;font-weight:900;">0</div>
  <div style="margin-top:3px;font-size:11px;opacity:.72;">This Month</div>
  <div style="margin-top:8px;padding-top:8px;border-top:1px solid rgba(255,255,255,.15);font-size:11px;opacity:.85;">Today: <span id="odoToday">0</span> · Lifetime: <span id="odoLifetime">0</span></div>
</div>






  <div class="hero">
    <h1>NCM Monitor Operations Center</h1>
    <div class="tagline">Fleet Health • Signal Analytics • Usage Intelligence • Operational Monitoring</div>
    <div class="version" id="monitoringScopeLine">Powered by NetCloud Manager APIs • Local view: MST/MDT • Monitoring scope: loading...</div>

    <div style="margin-top:18px;padding:16px 18px;border-radius:16px;background:rgba(37,99,235,.10);border:1px solid rgba(96,165,250,.24);color:#cbd5e1;line-height:1.55;">
      <strong style="color:#fff;">How to use this dashboard:</strong>
      This view summarizes router fleet health using NetCloud Manager API data. Use it to review router inventory,
      cellular signal quality, WAN usage, failover behavior, API consumption, and routers that may need deeper investigation.
      Some panels are populated by background polling, while others update when you run refreshes, reports, or deep-dive jobs.
    </div>
    <script>
      (async function hydrateMonitoringScope() {
        const line = document.getElementById('monitoringScopeLine');
        if (!line) return;

        const params = new URLSearchParams(window.location.search);
        const profileId = params.get('profile_id') || '1';

        function formatScopeDate(value) {
          if (!value) return 'dashboard creation date';
          const d = new Date(value);
          if (Number.isNaN(d.getTime())) return 'dashboard creation date';
          return d.toLocaleDateString(undefined, {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
          });
        }

        try {
          const res = await fetch(`/api/dashboard-profile/${profileId}`, { credentials: 'same-origin' });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);

          const profile = await res.json();
          const created = profile.created_at || profile.updated_at;
          const scopeDate = formatScopeDate(created);

          line.textContent = `Powered by NetCloud Manager APIs • Local view: MST/MDT • Monitoring scope: ${scopeDate} onward`;
        } catch (e) {
          line.textContent = 'Powered by NetCloud Manager APIs • Local view: MST/MDT • Monitoring scope: dashboard creation date onward';
        }
      })();
    </script>
  </div>

  <div class="topbar">
    <button class="action primary" onclick="refreshAll(false)">Refresh All Fast</button>
    <button class="action" onclick="refreshAll(true)">Refresh All + Signal</button>
    <button class="action" onclick="window.location='/pool-admin?profile_id=' + encodeURIComponent(new URLSearchParams(window.location.search).get('profile_id') || '1')">Pool Administration</button>
    <button class="action" onclick="window.location='/monitoring-targets-ui?profile_id=' + encodeURIComponent(new URLSearchParams(window.location.search).get('profile_id') || '1')">Add Individual Router</button>
    <button class="action danger" onclick="resolveAll(false)">Resolve All Open Issues</button>
    <button class="action" onclick="resolveAll(true)">Resolve All as Non-Incident</button>
    <span class="small" id="refreshStatus"></span>
  </div>

  <div class="router-deep-dive card">
    <h2>Data Analysis Center</h2>
    <div class="small">
      Launch scalable router investigations, track resumable batch jobs, and export completed results without holding a browser request open.
    </div>
    <div class="router-deep-dive-controls" style="margin-top: 12px;">
      <button class="action primary" onclick="const p=new URLSearchParams(window.location.search);const pid=p.get('profile_id')||localStorage.getItem('ncm_active_profile_id')||'1';localStorage.setItem('ncm_active_profile_id',pid);window.location='/deep-dive-jobs-ui?profile_id='+encodeURIComponent(pid);">Open Data Analysis Center</button>
    </div>
  </div>

  <div class="general-notes card">
    <h2>General Notes</h2>
    <textarea id="generalNote" placeholder="Add an operational note not tied to a specific router..."></textarea>
    <button class="action" onclick="addGeneralNote()">Save General Note</button>
    <div id="generalNotesList" class="small"></div>
  </div>

  <div class="tabs" id="tabs">
    <button class="active" onclick="setTab('Active Issues', this)">Active Issues</button>
    <button onclick="setTab('Needs Review', this)">Needs Review</button>
    <button onclick="setTab('Marked for Review', this)">Marked for Review</button>
    <button onclick="setTab('Watch', this)">Watch</button>
    <span id="poolTabs"></span>
    <button onclick="setTab('All Routers', this)">All Routers</button>
  </div>

  <input id="search" placeholder="Search router ID..." oninput="page=1; refresh()">

  <div class="summary" id="summary"></div>
  <div class="grid" id="content"></div>
  <div class="pager" id="paginationControls"></div>

<div id="routerLogsModalBack" class="logs-modal-back" onclick="closeRouterLogs(event)">
  <div class="logs-modal" onclick="event.stopPropagation()">
    <div class="logs-modal-top">
      <div>
        <h2 id="routerLogsTitle">Router Logs</h2>
        <div id="routerLogsSubtitle" class="small">Select a date range and refresh logs.</div>
      </div>
      <button class="action" onclick="closeRouterLogs()">Close</button>
    </div>

    <div class="logs-toolbar">
      <label class="small">Date window</label>
      <select id="routerLogsDays" onchange="loadRouterLogs()">
        <option value="1">Last 24 Hours</option>
        <option value="7" selected>Last 7 Days</option>
        <option value="14">Last 14 Days</option>
        <option value="30">Last 30 Days</option>
        <option value="90">Last 90 Days</option>
      </select>
      <button class="action" onclick="loadRouterLogs()">Refresh Logs</button>
      <button class="action" onclick="exportRouterLogs()">Export XLSX</button>
      <span id="routerLogsStatus" class="small"></span>
    </div>

    <div class="logs-body">
      <div id="routerLogsContent" class="small">No logs loaded yet.</div>
    </div>
  </div>
</div>

<script>
let routerLogsCurrentRouter = null;
let allPools = [];
let currentTab = 'Active Issues';
let counterFilter = null;
let page = 1;
let pageSize = 20;
let summaryCounts = {};
let pagination = {page: 1, page_size: 20, total: 0, total_pages: 1};

function hasOpenIssue(router, severity=null) {
  const issues = router.issues || [];
  if (severity) return issues.some(i => i.severity === severity);
  return issues.some(i => i.severity === 'needs_review' || i.severity === 'manual_review' || i.severity === 'watch');
}

function hasStorePowerCycleIndicator(router) {
  return (router.issues || []).some(i => i.severity === 'store_power_cycle');
}

function hasManualReview(router) {
  return (router.issues || []).some(i => i.severity === 'manual_review');
}

function hasConnectedWan(router) {
  return (router.sims || []).some(s => s.connection_state === 'connected');
}

function formatBytes(bytes) {
  const b = Number(bytes || 0);
  if (b >= 1024 ** 3) return `${(b / (1024 ** 3)).toFixed(2)} GB`;
  return `${(b / (1024 ** 2)).toFixed(1)} MB`;
}

function signalClass(metric, value) {
  if (value === null || value === undefined || value === 'n/a') return '';
  const v = Number(value);
  if (Number.isNaN(v)) return '';
  if (metric === 'rsrp') {
    if (v > -84) return 'sig-excellent';
    if (v >= -102) return 'sig-good';
    if (v >= -111) return 'sig-fair';
    return 'sig-poor';
  }
  if (metric === 'rsrq') {
    if (v > -5) return 'sig-excellent';
    if (v >= -9) return 'sig-good';
    if (v >= -12) return 'sig-fair';
    return 'sig-poor';
  }
  if (metric === 'sinr') {
    if (v > 12.5) return 'sig-excellent';
    if (v >= 10) return 'sig-good';
    if (v >= 7) return 'sig-fair';
    return 'sig-poor';
  }
  if (metric === 'dbm') {
    if (v > -65) return 'sig-excellent';
    if (v >= -75) return 'sig-good';
    if (v >= -85) return 'sig-fair';
    return 'sig-poor';
  }
  return '';
}

function formatUptime(seconds) {
  if (seconds === null || seconds === undefined || Number.isNaN(Number(seconds))) return 'n/a';
  const total = Math.floor(Number(seconds));
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const mins = Math.floor((total % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

function setTab(tab, btn) {
  currentTab = tab;
  counterFilter = null;
  page = 1;
  document.querySelectorAll('.tabs button').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  refresh();
}

async function refreshAll(includeSignal) {
  const s = document.getElementById('refreshStatus');
  s.innerText = includeSignal ? 'Refreshing all routers + signal...' : 'Refreshing all routers...';

  const res = await fetch('/refresh-all', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({include_signal: includeSignal, profile_id: activeProfileId()})
  });

  if (!res.ok) {
    s.innerText = 'Refresh failed.';
    return;
  }

  s.innerText = 'Refresh complete.';
  await refresh();
}

async function resolveAll(nonIncident) {
  const note = prompt(nonIncident ? 'Resolve all open issues as non-incident. Add a note:' : 'Resolve all open issues. Add a note:', nonIncident ? 'Bulk resolved as non-incident.' : 'Bulk resolved from dashboard.');
  if (note === null) return;
  const res = await fetch('/issues/resolve-all', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({note: note, non_incident: nonIncident})
  });
  const data = await res.json();
  document.getElementById('refreshStatus').innerText = `Resolved ${data.resolved_count || 0} issue(s).`;
  await refresh();
}

function deepDivePayload() {
  const modules = Array.from(document.querySelectorAll('.deepDiveModule:checked')).map(x => x.value);
  return {
    router_ids_text: document.getElementById('deepDiveRouters').value || '',
    days: Number(document.getElementById('deepDiveDays').value || 30),
    modules
  };
}

function selectAllDeepDiveModules(checked) {
  document.querySelectorAll('.deepDiveModule').forEach(x => x.checked = checked);
}

async function loadDeepDiveFile(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  const text = await file.text();
  const box = document.getElementById('deepDiveRouters');
  box.value = (box.value.trim() ? box.value.trim() + '\\n' : '') + text.trim();
}

async function runRouterDeepDive() {
  const status = document.getElementById('deepDiveStatus');
  const results = document.getElementById('deepDiveResults');
  const payload = deepDivePayload();
  if (!payload.router_ids_text.trim()) {
    alert('Paste or import at least one router ID/name first.');
    return;
  }
  if (!payload.modules.length) {
    alert('Select at least one investigation module.');
    return;
  }

  status.innerText = 'Running deep dive... this may take a bit for multiple routers.';
  results.innerHTML = '';

  const res = await fetch('/router-deep-dive', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  });

  if (!res.ok) {
    status.innerText = 'Deep dive failed.';
    results.innerText = await res.text();
    return;
  }

  const data = await res.json();
  status.innerText = `Complete: ${data.success_count || 0} succeeded, ${data.error_count || 0} failed.`;
  renderRouterDeepDiveResults(data);
}

function renderRouterDeepDiveResults(data) {
  const box = document.getElementById('deepDiveResults');
  const rows = data.results || [];
  if (!rows.length) {
    box.innerHTML = 'No results returned.';
    return;
  }

  box.innerHTML = `
    <table class="mini-table">
      <thead>
        <tr>
          <th>Router</th><th>Status</th><th>Signal</th><th>Location</th><th>Data Usage</th><th>Alerts</th><th>Summary</th>
        </tr>
      </thead>
      <tbody>
        ${rows.map(item => {
          if (item.error) {
            return `<tr><td>${escapeHtml(item.requested_identifier || item.router_id || '')}</td><td class="review">Error</td><td colspan="5">${escapeHtml(item.error)}</td></tr>`;
          }
          const r = item.report || {};
          const usage = r.data_usage || null;
          const signal = r.signal_health || null;
          const geo = r.geo_location || null;
          const alerts = r.alerts || null;
          const usageCell = usage ? `${escapeHtml((usage.totals || {}).wan_total_human || '0 B')}<br><span class="small">NCM ${escapeHtml((usage.totals || {}).ncm_total_human || '0 B')} / Uncat ${escapeHtml((usage.totals || {}).uncategorized_total_human || '0 B')}</span>` : '<span class="small">Not run</span>';
          const signalCell = signal ? `${escapeHtml(signal.overall || 'Unknown')}<br><span class="small">RSRP ${escapeHtml(signal.avg_rsrp ?? 'n/a')} / SINR ${escapeHtml(signal.avg_sinr ?? 'n/a')}</span>` : '<span class="small">Not run</span>';
          const geoCell = geo ? `${escapeHtml(geo.label || geo.method || 'Location returned')}<br><span class="small">${escapeHtml(geo.latitude ?? '')}, ${escapeHtml(geo.longitude ?? '')}</span>` : '<span class="small">Not run</span>';
          const alertsCell = alerts ? `${escapeHtml(alerts.total_alerts ?? 0)} alerts<br><span class="small">${escapeHtml(alerts.latest_type || 'No latest alert')}</span>` : '<span class="small">Not run</span>';
          return `<tr>
            <td><b>${escapeHtml(r.router_id)}</b><br><span class="small">${escapeHtml(r.router_name || '')}</span><br><button class="action" onclick="openRouterView('${escapeHtml(r.router_id)}', true)">Open</button></td>
            <td><span class="ok">OK</span></td>
            <td>${signalCell}</td>
            <td>${geoCell}</td>
            <td>${usageCell}</td>
            <td>${alertsCell}</td>
            <td>${escapeHtml(r.summary || '')}</td>
          </tr>`;
        }).join('')}
      </tbody>
    </table>
  `;
}

async function exportRouterDeepDiveXlsx() {
  const status = document.getElementById('deepDiveStatus');
  const payload = deepDivePayload();
  if (!payload.router_ids_text.trim()) {
    alert('Paste or import at least one router ID/name first.');
    return;
  }
  if (!payload.modules.length) {
    alert('Select at least one investigation module.');
    return;
  }

  status.innerText = 'Building XLSX export...';
  const res = await fetch('/router-deep-dive/export.xlsx', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  });

  if (!res.ok) {
    status.innerText = 'Export failed.';
    alert(await res.text());
    return;
  }

  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `router_deep_dive_${payload.days}d.xlsx`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
  status.innerText = 'Export downloaded.';
}

async function loadGeneralNotes() {
  const res = await fetch('/notes/general');
  const data = await res.json();
  const box = document.getElementById('generalNotesList');
  const notes = data.notes || [];
  box.innerHTML = notes.length ? notes.slice(0, 5).map(n => `<div class="note-item"><b>${n.created_at_local || ''}</b><br>${n.note}</div>`).join('') : 'No general notes saved yet.';
}

async function addGeneralNote() {
  const t = document.getElementById('generalNote');
  const note = t.value.trim();
  if (!note) return;
  await fetch('/notes/general', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({note})
  });
  t.value = '';
  await loadGeneralNotes();
}

function activeProfileId() {{
  const params = new URLSearchParams(window.location.search);
  return params.get('profile_id') || localStorage.getItem('ncm_active_profile_id') || '1';
}}

function profileUrl(path) {{
  const sep = path.includes('?') ? '&' : '?';
  return path + sep + 'profile_id=' + encodeURIComponent(activeProfileId());
}}

function openRouterLogs(routerId) {
  routerLogsCurrentRouter = String(routerId || '');
  document.getElementById('routerLogsTitle').innerText = `Router Logs — ${routerLogsCurrentRouter}`;
  document.getElementById('routerLogsSubtitle').innerText = `Profile ID: ${activeProfileId()}`;
  document.getElementById('routerLogsStatus').innerText = '';
  document.getElementById('routerLogsContent').innerHTML = '<div class="small">Loading logs...</div>';
  document.getElementById('routerLogsModalBack').style.display = 'flex';
  loadRouterLogs();
}

function closeRouterLogs(event) {
  if (event && event.target && event.target.id !== 'routerLogsModalBack') return;
  const modal = document.getElementById('routerLogsModalBack');
  if (modal) modal.style.display = 'none';
}

async function loadRouterLogs() {
  if (!routerLogsCurrentRouter) return;

  const days = document.getElementById('routerLogsDays').value || '7';
  const pid = activeProfileId();
  const status = document.getElementById('routerLogsStatus');
  const box = document.getElementById('routerLogsContent');

  status.innerText = 'Loading...';

  try {
    const res = await fetch(`/router-logs/${encodeURIComponent(routerLogsCurrentRouter)}?days=${encodeURIComponent(days)}&profile_id=${encodeURIComponent(pid)}&limit=1000`, {cache:'no-store'});
    const data = await res.json();

    if (!res.ok) {
      status.innerText = 'Failed.';
      box.innerHTML = `<div class="review">Unable to load router logs.</div><pre class="small">${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
      return;
    }

    const logs = data.logs || [];
    status.innerText = `${logs.length} log rows loaded.`;

    document.getElementById('routerLogsSubtitle').innerText =
      `Router ${data.router_id} • Profile ID ${data.profile_id} • Last ${data.days} day(s) • Since ${data.since_utc}`;

    if (!logs.length) {
      status.innerText = '0 log rows loaded.';
      box.innerHTML = `
        <div class="note-item" style="border-color:#334155;">
          <b>0 logs recorded for this date window.</b><br>
          <span class="small">
            Router logs must be enabled at the NCM group level before NCM will collect and return router log data.
            If logs are expected here, confirm router logging is enabled for this router's group in NCM, then allow time for new logs to be collected.
          </span>
        </div>
      `;
      return;
    }

    box.innerHTML = `
      <table class="logs-table">
        <thead>
          <tr>
            <th>Reported Local</th>
            <th>Level</th>
            <th>Source</th>
            <th>Message</th>
            <th>Created Local</th>
            <th>Seq</th>
          </tr>
        </thead>
        <tbody>
          ${logs.map(log => {
            const level = String(log.level || '');
            const levelClass = 'level-' + level.replace(/[^A-Za-z]/g, '').toUpperCase();
            return `<tr>
              <td>${escapeHtml(log.reported_at_local || log.reported_at || '')}</td>
              <td class="${escapeHtml(levelClass)}">${escapeHtml(level || 'n/a')}</td>
              <td>${escapeHtml(log.source || '')}</td>
              <td class="logs-message">${escapeHtml(log.message || '')}</td>
              <td>${escapeHtml(log.created_at_local || log.created_at || '')}</td>
              <td>${escapeHtml(log.sequence ?? '')}</td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>
    `;
  } catch (e) {
    status.innerText = 'Failed.';
    box.innerHTML = `<div class="review">Unable to load router logs: ${escapeHtml(e.message || e)}</div>`;
  }
}

function exportRouterLogs() {
  if (!routerLogsCurrentRouter) return;
  const days = document.getElementById('routerLogsDays').value || '7';
  const pid = activeProfileId();
  window.location = `/router-logs/${encodeURIComponent(routerLogsCurrentRouter)}/export.xlsx?days=${encodeURIComponent(days)}&profile_id=${encodeURIComponent(pid)}`;
}

async function refresh() {
  const search = document.getElementById('search').value.trim();
  const urlProfileId = new URLSearchParams(window.location.search).get('profile_id');
  const activeProfileId = urlProfileId || '1';
  localStorage.setItem('ncm_active_profile_id', activeProfileId);
  const params = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize),
    tab: currentTab,
    counter_filter: counterFilter || '',
    search: search,
    profile_id: activeProfileId
  });
  const res = await fetch('/dashboard-data?' + params.toString());
  const data = await res.json();
  allRouters = data.routers || [];
  allPools = data.pools || [];

  // Defensive fallback: the main dashboard must always show monitoring pool tabs.
  // If /dashboard-data ever returns an empty/missing pools list, pull the lighter /pools endpoint.
  if (!allPools.length) {
    try {
      const poolRes = await fetch(`/pools?profile_id=${encodeURIComponent(activeProfileId())}`);      if (poolRes.ok) {
        const poolData = await poolRes.json();
        allPools = poolData.pools || [];
      }
    } catch (e) {
      console.warn('Unable to load monitoring pools', e);
    }
  }

  summaryCounts = data.summary || {};
  pagination = data.pagination || {page: 1, page_size: pageSize, total: 0, total_pages: 1};
  page = pagination.page || page;
  pageSize = pagination.page_size || pageSize;
  renderPoolTabs();
  renderPoolManager();
  render();
  renderPagination();
  loadGeneralNotes();
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}


function openRouterView(routerId, deepDive=false) {
  if (!routerId) return;
  const profileId =
    (typeof activeProfileId === 'function')
      ? activeProfileId()
      : (new URLSearchParams(window.location.search).get('profile_id') || '1');

  let url = `/router-view/${encodeURIComponent(routerId)}?profile_id=${encodeURIComponent(profileId)}`;
  if (typeof selectedPool !== 'undefined' && selectedPool) {
    url += `&pool=${encodeURIComponent(selectedPool)}`;
  }
  if (deepDive) url += '&deep_dive=1';
  window.location.href = url;
}

function renderPoolTabs() {
  const el = document.getElementById('poolTabs');
  if (!el) return;

  if (!allPools || !allPools.length) {
    el.innerHTML = '';
    return;
  }

  // Use data-tab instead of embedding the pool name inside JavaScript quotes.
  // This keeps pool names with spaces/special characters safe and preserves the golden dashboard behavior.
  el.innerHTML = allPools.map(p => {
    const name = String(p.name || '');
    const count = Number(p.router_count || 0);
    return `<button data-tab="${escapeHtml(name)}" onclick="setTab(this.dataset.tab, this)">${escapeHtml(name)} (${count})</button>`;
  }).join('');
}

function renderPoolManager() {
  const select = document.getElementById('poolSelect');
  const list = document.getElementById('poolList');
  if (!select || !list) return;

  const current = select.value;
  select.innerHTML = allPools.map(p => `<option value="${escapeHtml(p.name)}">${escapeHtml(p.name)} (${p.router_count || 0})</option>`).join('');
  if (current && allPools.some(p => p.name === current)) select.value = current;

  list.innerHTML = allPools.map(p => `
    <div class="note-item">
      <b>${escapeHtml(p.name)}</b> — ${p.router_count || 0} routers<br>
      ${escapeHtml(p.description || '')}
    </div>
  `).join('') || 'No pools found.';
}

async function createPool() {
  const name = document.getElementById('poolName').value.trim();
  const description = document.getElementById('poolDescription').value.trim();
  if (!name) return alert('Enter a pool name first.');
  const res = await fetch(profileUrl('/pools'), {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({name, description})
  });
  if (!res.ok) return alert(await res.text());
  document.getElementById('poolName').value = '';
  document.getElementById('poolDescription').value = '';
  await refresh();
}

async function renamePool() {
  const old_name = document.getElementById('poolSelect').value;
  const new_name = prompt('New pool name:', old_name);
  if (!new_name || !old_name || new_name === old_name) return;
  const description = prompt('Optional description. Leave blank to keep simple:', '') || '';
  const res = await fetch('/pools/rename', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({old_name, new_name, description})
  });
  if (!res.ok) return alert(await res.text());
  currentTab = new_name;
  await refresh();
}

async function deletePool(removeRouters) {
  const name = document.getElementById('poolSelect').value;
  if (!name) return;
  const msg = removeRouters
    ? `Delete pool "${name}" and remove its routers plus stored router history?`
    : `Delete pool "${name}" and move routers to Unassigned while keeping history?`;
  if (!confirm(msg)) return;
  const res = await fetch('/pools/delete', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({name, remove_routers: removeRouters})
  });
  if (!res.ok) return alert(await res.text());
  currentTab = 'Active Issues';
  await refresh();
}

async function addRoutersToPool() {
  const pool_name = document.getElementById('poolSelect').value || document.getElementById('poolName').value.trim();
  const router_ids_text = document.getElementById('poolRouterIds').value;
  if (!pool_name) return alert('Select or create a pool first.');
  if (!router_ids_text.trim()) return alert('Paste one or more router IDs first.');
  const res = await fetch('/pools/add-routers', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({pool_name, router_ids_text})
  });
  if (!res.ok) return alert(await res.text());
  document.getElementById('poolRouterIds').value = '';
  currentTab = pool_name;
  await refresh();
}

async function removeRouterFromPool(deleteHistory) {
  const router_id = document.getElementById('removeRouterId').value.trim();
  if (!router_id) return alert('Enter a router ID first.');
  const msg = deleteHistory
    ? `Remove router ${router_id} and delete all locally stored history?`
    : `Remove router ${router_id} from its pool and keep local history?`;
  if (!confirm(msg)) return;
  const res = await fetch('/pools/remove-router', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({router_id, delete_history: deleteHistory})
  });
  if (!res.ok) return alert(await res.text());
  document.getElementById('removeRouterId').value = '';
  await refresh();
}

function filteredRouters() {
  // Server-side pagination/filtering means the API already returned only
  // the routers for the current page and selected view.
  return allRouters;
}

function applyCounterFilter(filter) {
  counterFilter = filter;
  page = 1;
  refresh();
}

function renderSummary() {
  const total = summaryCounts.total ?? 0;
  const needsReview = summaryCounts.needs_review ?? 0;
  const manualReview = summaryCounts.manual_review ?? 0;
  const watch = summaryCounts.watch ?? 0;
  const active = summaryCounts.active ?? 0;
  const storeCycle = summaryCounts.store_power_cycle ?? 0;
  const connected = summaryCounts.connected ?? 0;

  document.getElementById('summary').innerHTML = `
    <div class="stat" onclick="counterFilter=null;page=1;refresh()"><div class="num">${total}</div><div class="label">Routers in View</div></div>
    <div class="stat" onclick="applyCounterFilter('needs_review')"><div class="num review">${needsReview}</div><div class="label">Needs Review</div></div>
    <div class="stat" onclick="applyCounterFilter('manual_review')"><div class="num review">${manualReview}</div><div class="label">Marked for Review</div></div>
    <div class="stat" onclick="applyCounterFilter('watch')"><div class="num watch">${watch}</div><div class="label">Watch</div></div>
    <div class="stat" onclick="applyCounterFilter('active')"><div class="num">${active}</div><div class="label">Active Issues</div></div>
    <div class="stat" onclick="applyCounterFilter('connected')"><div class="num ok">${connected}</div><div class="label">With Connected WAN</div></div>
  `;
}

function render() {
  const routers = filteredRouters();
  renderSummary();

  const content = document.getElementById('content');
  content.innerHTML = '';

  if (routers.length === 0) {
    content.innerHTML = '<div class="card"><h2>No routers match this view.</h2><p class="small">Try another group, counter, or search term.</p></div>';
    return;
  }

  routers.forEach(r => {
    const needsReview = hasOpenIssue(r, 'needs_review');
    const manualReview = hasManualReview(r);
    const watch = hasOpenIssue(r, 'watch');
    const storeCycle = hasStorePowerCycleIndicator(r);
    const status = needsReview ? 'Needs Review' : manualReview ? 'Marked for Review' : watch ? 'Watch' : 'Healthy';
    const statusClass = needsReview ? 'review' : manualReview ? 'review' : watch ? 'watch' : storeCycle ? 'store' : 'ok';
    const avg = r.avg_signal_30d || {};

    const sims = (r.sims || []).map(s => {
      const isConnected = s.connection_state === 'connected';
      const cls = isConnected ? 'ok' : 'small';
      const uptimeText = isConnected ? ` / uptime ${formatUptime(s.uptime)}` : '';
      return `<div class="pill ${cls}">${s.sim_label}: ${s.carrier || 'Unknown'} / ${s.connection_state || 'unknown'}${uptimeText}</div>`;
    }).join('');

    const issues = (r.issues || []).map(i => {
      let summary = i.summary || '';
      summary = summary.replace(/Examples:.*?(?=(\\s\\|\\s|$))/g, '').replace(/\\s\\|\\s$/g, '').trim();
      return `<div class="small">${i.severity.replaceAll('_',' ')}: ${escapeHtml(summary)}</div>`;
    }).join('');

    const loc = r.latitude && r.longitude
      ? `<div class="small">Location method: ${r.method || 'available'}</div>`
      : `<div class="small">Location method: not available</div>`;

    const sig = `
      <div class="small">
        30d Avg: 
        RSRP <span class="${signalClass('rsrp', avg.avg_rsrp)}">${avg.avg_rsrp ?? 'n/a'}</span> |
        RSRQ <span class="${signalClass('rsrq', avg.avg_rsrq)}">${avg.avg_rsrq ?? 'n/a'}</span> |
        SINR <span class="${signalClass('sinr', avg.avg_sinr)}">${avg.avg_sinr ?? 'n/a'}</span>
      </div>
    `;

    content.innerHTML += `
      <div class="card" onclick="openRouterView('${escapeHtml(r.router_id)}')">
        ${r.platform_image_url ? `<img class="device-thumb" src="${r.platform_image_url}" alt="${r.platform_label || 'Router'} platform">` : ''}
        <div class="card-body-pad">
        <div class="bucket">${r.bucket}</div>
        <div class="router">Router ${r.router_id}</div>
        <div class="card-actions" style="margin:8px 0 10px 0;">
          <button class="action" onclick="event.stopPropagation(); openRouterView('${escapeHtml(r.router_id)}')">Open</button>
          <button class="action" onclick="event.stopPropagation(); openRouterLogs('${escapeHtml(r.router_id)}')">Router Logs</button>
        </div>
        <div class="pill ${statusClass}">${status}</div>
        <div>${sims || '<span class="small">No SIM data stored yet</span>'}</div>
        ${sig}
        ${issues || '<div class="small">No open operational issues.</div>'}
        <p class="small">Last alert: ${r.last_alert || 'No alerts stored yet'}</p>
        <p class="small">Last alert local: ${r.last_alert_local || 'n/a'}</p>
        ${loc}
        </div>
      </div>
    `;
  });
}

function goToPage(newPage) {
  const totalPages = pagination.total_pages || 1;
  page = Math.max(1, Math.min(Number(newPage || 1), totalPages));
  refresh();
}

function changePageSize(value) {
  pageSize = Number(value || 20);
  page = 1;
  refresh();
}

function renderPagination() {
  const el = document.getElementById('paginationControls');
  if (!el) return;
  const total = pagination.total || 0;
  const totalPages = pagination.total_pages || 1;
  const current = pagination.page || 1;
  const start = total === 0 ? 0 : ((current - 1) * pageSize) + 1;
  const end = Math.min(current * pageSize, total);

  el.innerHTML = `
    <button class="action" ${current <= 1 ? 'disabled' : ''} onclick="goToPage(${current - 1})">Previous</button>
    <span>Showing ${start}-${end} of ${total} • Page ${current} of ${totalPages}</span>
    <button class="action" ${current >= totalPages ? 'disabled' : ''} onclick="goToPage(${current + 1})">Next</button>
    <span>Per page</span>
    <select onchange="changePageSize(this.value)">
      <option value="20" ${pageSize === 20 ? 'selected' : ''}>20</option>
      <option value="50" ${pageSize === 50 ? 'selected' : ''}>50</option>
      <option value="100" ${pageSize === 100 ? 'selected' : ''}>100</option>
    </select>
  `;
}

refresh();
setInterval(refresh, 30000);
</script>





<script src="/api/odometer.js"></script>
<script src="/api/profile-header.js"></script>
</body>
</html>
    """


@app.get("/pool-admin", response_class=HTMLResponse)
async def pool_admin():
    return """
<!DOCTYPE html>
<html>
<head>
  <title>Pool Administration</title>
  <style>
    body { font-family: Arial, sans-serif; background: #0f172a; color: #e5e7eb; padding: 28px; }
    a { color:#38bdf8; text-decoration:none; }
    .hero {
      background: radial-gradient(circle at top left, #1d4ed8 0, #0f172a 42%, #020617 100%);
      border:1px solid #334155; border-radius:22px; padding:24px; margin-bottom:18px;
      box-shadow:0 24px 45px rgba(0,0,0,.28);
    }
    h1 { margin:0; font-size:32px; letter-spacing:-.03em; }
    .sub, .small { color:#94a3b8; font-size:13px; }
    .layout { display:grid; grid-template-columns: 360px 1fr; gap:18px; align-items:start; }
    .card { background:#111827; border:1px solid #1f2937; border-radius:18px; padding:18px; box-shadow:0 20px 35px rgba(0,0,0,.20); }
    .pool-card { cursor:pointer; margin-bottom:10px; }
    .pool-card:hover, .pool-card.active { border-color:#38bdf8; }
    input, textarea, select {
      width:100%; box-sizing:border-box; background:#020617; color:#e5e7eb; border:1px solid #334155;
      border-radius:12px; padding:10px; margin:8px 0;
    }
    textarea { min-height:120px; resize:vertical; }
    button {
      background:#1e293b; color:#e5e7eb; border:1px solid #334155; border-radius:999px;
      padding:9px 13px; cursor:pointer; margin:4px 4px 4px 0;
      transition: transform .08s ease, opacity .18s ease, background .18s ease, border-color .18s ease, box-shadow .18s ease;
    }
    button:active {
      transform: translateY(1px) scale(.98);
    }
    button:disabled {
      opacity:.72;
      cursor:wait;
    }
    button.primary { background:#2563eb; border-color:#60a5fa; }
    button.primary.saving {
      background:#1d4ed8;
      border-color:#93c5fd;
      box-shadow:0 0 0 3px rgba(147,197,253,.14);
    }
    button.primary.saved {
      background:#166534;
      border-color:#22c55e;
      box-shadow:0 0 0 3px rgba(34,197,94,.14);
    }
    button.primary.failed {
      background:#7f1d1d;
      border-color:#fb7185;
      box-shadow:0 0 0 3px rgba(251,113,133,.14);
    }
    button.danger { border-color:#fb7185; color:#fecdd3; }
    .router-row { display:flex; justify-content:space-between; gap:12px; border-top:1px solid #1f2937; padding:10px 0; }
    .pill { display:inline-block; padding:4px 9px; border-radius:999px; background:#1e293b; margin:2px; font-size:13px; }
    .toolbar { margin:14px 0; }
    @media (max-width: 900px) { .layout { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
<div id="activeProfileBranding" style="margin:18px 18px 10px 18px;background:linear-gradient(135deg,#102042,#0b1220);border:1px solid #263449;border-radius:20px;padding:18px 20px;display:flex;align-items:center;gap:16px;box-shadow:0 18px 40px rgba(0,0,0,.28);">
  <div id="activeProfileLogoBox" style="width:76px;height:76px;border-radius:18px;background:#020617;border:1px solid #334155;display:flex;align-items:center;justify-content:center;overflow:hidden;font-size:32px;font-weight:900;color:#60a5fa;flex:0 0 auto;">?</div>
  <div>
    <div id="activeProfileName" style="font-size:28px;font-weight:900;line-height:1.1;">Dashboard</div>
    <div id="activeProfileCompany" style="font-size:14px;color:#93c5fd;margin-top:4px;"></div>
    <div id="activeProfilePurpose" style="font-size:13px;color:#cbd5e1;margin-top:6px;"></div>
  </div>
</div>

<a id="dashboardSwitcher" href="/launcher" style="position:fixed;top:18px;left:22px;z-index:999998;background:linear-gradient(135deg,#2563eb,#1d4ed8);color:white;text-decoration:none;border-radius:14px;padding:10px 14px;font-weight:800;font-size:13px;box-shadow:0 14px 30px rgba(0,0,0,.30);border:1px solid rgba(255,255,255,.16);">Switch Dashboard</a>

<div id="apiOdometer" aria-label="NCM API odometer" style="position:fixed;top:18px;right:22px;z-index:999999;width:230px;background:linear-gradient(135deg,rgba(15,23,42,.98),rgba(30,64,105,.98));color:#f8fafc;border:1px solid rgba(255,255,255,.18);border-radius:18px;padding:13px 15px;box-shadow:0 18px 42px rgba(0,0,0,.35);text-align:right;font-family:inherit;">
  <div style="font-size:11px;font-weight:800;letter-spacing:.07em;text-transform:uppercase;opacity:.82;">NCM API Odometer</div>
  <div id="odoMonth" style="margin-top:3px;font-size:30px;line-height:1;font-weight:900;">0</div>
  <div style="margin-top:3px;font-size:11px;opacity:.72;">This Month</div>
  <div style="margin-top:8px;padding-top:8px;border-top:1px solid rgba(255,255,255,.15);font-size:11px;opacity:.85;">Today: <span id="odoToday">0</span> · Lifetime: <span id="odoLifetime">0</span></div>
</div>







  <div class="hero">
    <a id="poolBackToDashboard" href="/ui">← Back to dashboard</a>
    <h1>Pool Administration</h1>
    <div class="sub">Create, rename, delete, import, and maintain monitoring groups. Router history is retained unless you explicitly delete it.</div>
  </div>

  <div class="layout">
    <div class="card">
      <h2>Monitoring Groups</h2>
      <div id="poolCards"></div>
      <hr style="border-color:#1f2937">
      <h3>Create / Update Group</h3>
      <input id="poolName" placeholder="Pool name">
      <input id="poolDescription" placeholder="Description">
      <button class="primary" onclick="createPool()">Create / Update</button>
    </div>

    <div class="card">
      <h2 id="selectedTitle">Select a group</h2>
      <div id="selectedMeta" class="small"></div>

      <div class="toolbar">
        <button onclick="renamePool()">Rename Group</button>
        <button class="danger" onclick="deletePool(false)">Delete Group, Keep Routers</button>
        <button class="danger" onclick="deletePool(true)">Delete Group + Router History</button>
      </div>

      <div id="poolModuleDefaults"></div>

      <h3>Import / Add Routers</h3>
      <textarea id="poolRouterIds" placeholder="Paste router IDs here — one per line, comma-separated, or copied from Excel."></textarea>
      <button id="addRoutersBtn" class="primary" onclick="addRoutersToPool()">Add Routers to Selected Group</button>

      <h3>Routers in Group</h3>
      <input id="routerSearch" placeholder="Search router ID" oninput="renderSelectedPool()">
      <div id="routerList" class="small"></div>
    </div>
  </div>

<script>
let allRouters = [];
let allPools = [];
let selectedPool = null;

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}

function activeProfileId() {{
  const params = new URLSearchParams(window.location.search);
  return params.get('profile_id') || localStorage.getItem('ncm_active_profile_id') || '1';
}}

function profileUrl(path) {{
  const sep = path.includes('?') ? '&' : '?';
  return path + sep + 'profile_id=' + encodeURIComponent(activeProfileId());
}}

function openRouterView(routerId) {{
  if (!routerId) return;
  window.location.href = '/router-view/' + encodeURIComponent(routerId) + '?profile_id=' + encodeURIComponent(activeProfileId());
}}

async function loadData() {
  const back = document.getElementById('poolBackToDashboard');
  if (back) back.href = '/ui?profile_id=' + encodeURIComponent(activeProfileId());

  const res = await fetch('/pool-admin-data?profile_id=' + encodeURIComponent(activeProfileId()));
  const data = await res.json();
  allRouters = data.routers || [];
  allPools = data.pools || [];
  if (!selectedPool && allPools.length) selectedPool = allPools[0].name;
  renderPools();
  renderSelectedPool();
}

function renderPools() {
  const box = document.getElementById('poolCards');
  box.innerHTML = allPools.map(p => `
    <div class="card pool-card ${p.name === selectedPool ? 'active' : ''}" onclick="selectedPool='${escapeHtml(p.name)}';renderPools();renderSelectedPool();">
      <b>${escapeHtml(p.name)}</b><br>
      <span class="pill">${p.router_count || 0} routers</span><br>
      <span class="small">${escapeHtml(p.description || '')}</span>
    </div>
  `).join('') || '<div class="small">No monitoring groups found.</div>';
}

function poolModuleHelpText(name) {
  const help = {
    metadata: 'Collects basic router profile details such as model, name, product, and general inventory metadata.',
    signal_health: 'Collects RSRP, RSRQ, SINR, dBm, and cell identity over time for signal trend graphs.',
    router_state: 'Collects online/offline state samples used to understand availability and state churn.',
    alerts: 'Pulls configured NCM alerts. Alert rules must first be configured in NCM and may take time to populate.',
    router_stream_usage: 'Collects NCM cloud traffic from router stream usage samples, used for management-traffic investigation.',
    sim_usage: 'Collects carrier/SIM usage by modem or SIM interface for data-usage graphs and reports.',
    location: 'Collects latest router location, GPS, or serving-cell location data when available.',
    router_logs: 'Collects router log entries when router logging is enabled at the NCM group level.'
  };
  return help[name] || 'Controls whether this data set is collected and how often it is refreshed.';
}

function poolModuleIntervalOptions(current) {
  const values = ['', 5, 15, 30, 60, 240, 720, 1440];
  return values.map(v => {
    const label = v === '' ? 'No interval' : String(v) + ' min';
    const selected = String(current ?? '') === String(v) ? 'selected' : '';
    return '<option value="' + v + '" ' + selected + '>' + label + '</option>';
  }).join('');
}

function poolModuleModeOptions(current) {
  const modes = [
    ['disabled', 'Disabled — do not collect this data'],
    ['passive', 'Passive — collect automatically in the background'],
    ['on_demand', 'On demand — collect only when manually requested'],
    ['cached', 'Cached — use data captured during normal refresh/discovery'],
    ['discovery', 'Discovery — collect inventory or identity details only']
  ];

  return modes.map(([value, label]) => {
    const selected = String(current || '') === value ? 'selected' : '';
    return '<option value="' + value + '" ' + selected + '>' + label + '</option>';
  }).join('');
}


function togglePoolPollingAttributes() {
  const panel = document.getElementById('poolPollingAttributesPanel');
  const btn = document.getElementById('poolPollingAttributesToggle');
  if (!panel) return;

  const isOpen = panel.style.display !== 'none';
  panel.style.display = isOpen ? 'none' : 'block';

  if (btn) {
    btn.textContent = isOpen ? '↻ Modify polling attributes' : '↻ Hide polling attributes';
  }
}

async function loadPoolModuleDefaults() {
  const box = document.getElementById('poolModuleDefaults');
  if (!box || !selectedPool) return;

  box.innerHTML = '<div class="small">Loading monitoring defaults...</div>';

  const res = await fetch('/pools/modules?profile_id=' + encodeURIComponent(activeProfileId()) + '&pool_name=' + encodeURIComponent(selectedPool));
  if (!res.ok) {
    box.innerHTML = '<div class="small">Failed to load pool monitoring defaults.</div>';
    return;
  }

  const data = await res.json();
  const modules = data.modules || {};
  const entries = Object.entries(modules);

  box.innerHTML = `
    <hr style="border-color:#1f2937">
    <h3>Pool Monitoring Defaults</h3>
    <p class="small">Optional polling defaults for routers in this group. New routers added to this group inherit these settings; saving also applies them to current routers in the group.</p>

    <button
      id="poolPollingAttributesToggle"
      onclick="togglePoolPollingAttributes()"
      style="background:rgba(15,23,42,.72);border:1px solid rgba(56,189,248,.35);color:#bae6fd;border-radius:999px;padding:8px 12px;font-size:13px;font-weight:800;"
    >↻ Modify polling attributes</button>

    <span id="poolModuleStatus" class="small" style="margin-left:8px;"></span>

    <div id="poolPollingAttributesPanel" style="display:none;margin-top:12px;">
      ${entries.map(([name, m]) => `
        <div style="border-top:1px solid #1f2937;padding:12px 0;">
          <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between;">
            <div>
              <b>${escapeHtml(m.label || name)}</b>
              <div class="small">Default: ${escapeHtml(m.default_mode || 'disabled')}${m.default_interval_minutes ? ' · ' + m.default_interval_minutes + ' min' : ''}</div>
              <div class="small" style="margin-top:4px;color:rgba(203,213,225,.88);">${escapeHtml(poolModuleHelpText(name))}</div>
            </div>
            <label class="small" style="display:inline-flex;align-items:center;gap:8px;cursor:pointer;">
              <input id="poolModEnabled-${escapeHtml(name)}" type="checkbox" ${m.enabled ? 'checked' : ''} style="width:auto;margin:0;">
              Enabled
            </label>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px;">
            <div>
              <label class="small">Mode</label>
              <select id="poolModMode-${escapeHtml(name)}">${poolModuleModeOptions(m.mode)}</select>
            </div>
            <div>
              <label class="small">Interval</label>
              <select id="poolModInterval-${escapeHtml(name)}">${poolModuleIntervalOptions(m.interval_minutes)}</select>
            </div>
          </div>
        </div>
      `).join('')}

      <button id="savePoolDefaultsBtn" class="primary" onclick="savePoolModuleDefaults(this)">Save Pool Defaults</button>
    </div>
  `;
}

async function savePoolModuleDefaults(btn) {
  if (!selectedPool) return alert('Select a group first.');

  const status = document.getElementById('poolModuleStatus');
  const button = btn || document.getElementById('savePoolDefaultsBtn');

  function setButtonState(state, text) {
    if (!button) return;
    button.classList.remove('saving', 'saved', 'failed');
    if (state) button.classList.add(state);
    button.textContent = text;
  }

  if (button) button.disabled = true;
  setButtonState('saving', 'Saving...');
  if (status) {
    status.style.color = '#93c5fd';
    status.textContent = 'Saving pool defaults...';
  }

  try {
    const resGet = await fetch('/pools/modules?profile_id=' + encodeURIComponent(activeProfileId()) + '&pool_name=' + encodeURIComponent(selectedPool));

    if (!resGet.ok) {
      throw new Error('Failed to load module list before save.');
    }

    const current = await resGet.json();
    const modules = current.modules || {};
    const payloadModules = {};

    Object.keys(modules).forEach(name => {
      const enabledEl = document.getElementById('poolModEnabled-' + name);
      const modeEl = document.getElementById('poolModMode-' + name);
      const intervalEl = document.getElementById('poolModInterval-' + name);

      payloadModules[name] = {
        enabled: enabledEl ? enabledEl.checked : false,
        mode: modeEl ? modeEl.value : 'disabled',
        interval_minutes: intervalEl && intervalEl.value ? Number(intervalEl.value) : null
      };
    });

    const res = await fetch('/pools/modules', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        profile_id: activeProfileId(),
        pool_name: selectedPool,
        modules: payloadModules
      })
    });

    if (!res.ok) {
      let msg = 'Save failed.';
      try {
        const errText = await res.text();
        if (errText) msg = errText;
      } catch (e) {}
      throw new Error(msg);
    }

    const result = await res.json();

    setButtonState('saved', 'Saved ✓');
    if (status) {
      status.style.color = '#86efac';
      status.textContent = 'Saved. Applied to ' + (result.applied_router_count || 0) + ' routers.';
    }

    setTimeout(() => {
      if (button) {
        button.disabled = false;
        setButtonState('', 'Save Pool Defaults');
      }
    }, 1400);

  } catch (err) {
    setButtonState('failed', 'Save failed');
    if (status) {
      status.style.color = '#fecdd3';
      status.textContent = err && err.message ? err.message : 'Save failed.';
    }

    setTimeout(() => {
      if (button) {
        button.disabled = false;
        setButtonState('', 'Save Pool Defaults');
      }
    }, 2200);
  }
}


function renderSelectedPool() {
  const pool = allPools.find(p => p.name === selectedPool);
  const title = document.getElementById('selectedTitle');
  const meta = document.getElementById('selectedMeta');
  const list = document.getElementById('routerList');
  if (!pool) {
    title.innerText = 'Select a group';
    meta.innerText = '';
    list.innerHTML = '';
    const defaultsBox = document.getElementById('poolModuleDefaults');
    if (defaultsBox) defaultsBox.innerHTML = '';
    return;
  }
  title.innerText = pool.name;
  meta.innerText = `${pool.router_count || 0} routers • ${pool.description || 'No description'}`;
  loadPoolModuleDefaults();

  const q = document.getElementById('routerSearch').value.trim().toLowerCase();
  const routers = allRouters.filter(r => r.bucket === pool.name && (!q || String(r.router_id).toLowerCase().includes(q)));
  list.innerHTML = routers.map(r => `
    <div class="router-row">
      <div>
        <b>${escapeHtml(r.router_id)}</b><br>
        <span class="small">${escapeHtml(r.last_alert || 'No recent alert')}</span>
      </div>
      <div>
        <button onclick="event.stopPropagation(); openRouterView('${escapeHtml(r.router_id)}')">Open</button>
        <button class="danger" onclick="event.stopPropagation(); removeRouter('${escapeHtml(r.router_id)}', false)">Remove</button>
      </div>
    </div>
  `).join('') || '<div class="small">No routers in this group.</div>';
}

async function createPool() {
  const name = document.getElementById('poolName').value.trim();
  const description = document.getElementById('poolDescription').value.trim();
  if (!name) return alert('Enter a pool name first.');
  const res = await fetch(profileUrl('/pools'), {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name, description, profile_id: activeProfileId()})});
  if (!res.ok) return alert(await res.text());
  selectedPool = name;
  document.getElementById('poolName').value = '';
  document.getElementById('poolDescription').value = '';
  await loadData();
}

async function renamePool() {
  if (!selectedPool) return alert('Select a group first.');
  const new_name = prompt('New group name:', selectedPool);
  if (!new_name || new_name === selectedPool) return;
  const description = prompt('Optional description:', '') || '';
  const res = await fetch('/pools/rename', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({old_name:selectedPool, new_name, description, profile_id: activeProfileId()})});
  if (!res.ok) return alert(await res.text());
  selectedPool = new_name;
  await loadData();
}

async function deletePool(removeRouters) {
  if (!selectedPool) return alert('Select a group first.');
  const msg = removeRouters
    ? `Delete "${selectedPool}" and delete all local router history for routers in this group?`
    : `Delete "${selectedPool}" and move routers to Unassigned while keeping history?`;
  if (!confirm(msg)) return;
  const res = await fetch('/pools/delete', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name:selectedPool, remove_routers:removeRouters, profile_id: activeProfileId()})});
  if (!res.ok) return alert(await res.text());
  selectedPool = null;
  await loadData();
}

async function addRoutersToPool() {
  if (!selectedPool) return alert('Select a group first.');

  const router_ids_text = document.getElementById('poolRouterIds').value;
  if (!router_ids_text.trim()) return alert('Paste router IDs first.');

  const btn = document.getElementById('addRoutersBtn');
  const originalText = btn ? btn.innerHTML : 'Add Routers to Selected Group';

  if (btn) {
    btn.disabled = true;
    btn.classList.remove('success', 'danger');
    btn.style.opacity = '0.75';
    btn.style.transform = 'translateY(1px)';
    btn.style.cursor = 'wait';
    btn.innerHTML = 'Adding...';
  }

  try {
    const res = await fetch('/pools/add-routers', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({pool_name:selectedPool, router_ids_text, profile_id: activeProfileId()})
    });

    if (!res.ok) {
      throw new Error(await res.text());
    }

    document.getElementById('poolRouterIds').value = '';

    if (btn) {
      btn.style.opacity = '1';
      btn.style.transform = 'translateY(0)';
      btn.style.cursor = 'default';
      btn.style.background = '#188038';
      btn.style.color = '#fff';
      btn.innerHTML = '✓ Added';
    }

    await loadData();

    if (btn) {
      setTimeout(() => {
        btn.disabled = false;
        btn.style.background = '';
        btn.style.color = '';
        btn.innerHTML = originalText;
      }, 1100);
    }
  } catch (err) {
    if (btn) {
      btn.style.opacity = '1';
      btn.style.transform = 'translateY(0)';
      btn.style.cursor = 'default';
      btn.style.background = '#b42318';
      btn.style.color = '#fff';
      btn.innerHTML = 'Add failed';
    }

    alert('Failed to add router(s): ' + (err && err.message ? err.message : err));

    if (btn) {
      setTimeout(() => {
        btn.disabled = false;
        btn.style.background = '';
        btn.style.color = '';
        btn.innerHTML = originalText;
      }, 1500);
    }
  }
}

async function removeRouter(router_id, deleteHistory=false) {
  if (!confirm(`Remove router ${router_id} from ${selectedPool}? History will be kept.`)) return;
  const res = await fetch('/pools/remove-router', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({router_id, delete_history:deleteHistory, profile_id: activeProfileId()})});
  if (!res.ok) return alert(await res.text());
  await loadData();
}

loadData();
</script>


<script src="/api/odometer.js"></script>
<script src="/api/profile-header.js"></script>
</body>
</html>
    """



@app.get("/router/{router_id}/usage-report")
async def router_usage_report(router_id: str, days: int = Query(30), profile_id=None):
    since, until, clamped = clamp_usage_window(days)

    # Keep single-router Usage Investigation responsive.
    # 250 rows/page * 12 pages = up to 3,000 samples per source for 7-day reports.
    try:
        usage_days_int = int(days or 7)
    except Exception:
        usage_days_int = 7

    if usage_days_int <= 7:
        usage_max_pages = 12
    elif usage_days_int <= 30:
        usage_max_pages = 25
    else:
        usage_max_pages = 40

    # Make sure we have current SIM/net_device IDs stored locally.
    with db() as conn:
        conn.row_factory = sqlite3.Row
        sims = conn.execute("""
            SELECT id, sim_label, carrier, connection_state
            FROM net_devices
            WHERE router_id = ?
            ORDER BY sim_label
        """, (router_id,)).fetchall()

    if not sims:
        await poll_router(router_id, include_signal=False, profile_id=profile_id)
        with db() as conn:
            conn.row_factory = sqlite3.Row
            sims = conn.execute("""
                SELECT id, sim_label, carrier, connection_state
                FROM net_devices
                WHERE router_id = ?
                ORDER BY sim_label
            """, (router_id,)).fetchall()

    router_stream_rows = await ncm_get_all(
        "/api/v2/router_stream_usage_samples/",
        {"router": router_id, "created_at__gt": since, "limit": 250},
        max_pages=usage_max_pages,
        profile_id=profile_id,
    )

    print(f"[usage-report] router={router_id} profile={profile_id} router_stream_rows_filtered={len(router_stream_rows)} since={since}", flush=True)

    # Some NCM router_stream_usage_samples queries return data with ?router=<id>
    # but return no rows when created_at__gt is included. If the filtered query
    # comes back empty, retry unfiltered and apply the time window locally.
    if not router_stream_rows:
        unfiltered_router_stream_rows = await ncm_get_all(
            "/api/v2/router_stream_usage_samples/",
            {"router": router_id, "limit": 250},
            max_pages=usage_max_pages,
            profile_id=profile_id,
        )
        router_stream_rows = [
            row for row in unfiltered_router_stream_rows
            if str(row.get("created_at") or "") >= str(since)
        ]
        print(
            f"[usage-report] router={router_id} profile={profile_id} "
            f"router_stream_rows_unfiltered={len(unfiltered_router_stream_rows)} "
            f"router_stream_rows_after_local_filter={len(router_stream_rows)}",
            flush=True,
        )

    if router_stream_rows:
        print(f"[usage-report] router={router_id} first_router_stream_row={router_stream_rows[0]}", flush=True)

    state_rows = await ncm_get_all(
        "/api/v2/router_state_samples/",
        {"router": router_id, "created_at__gt": since, "limit": 250},
        max_pages=usage_max_pages,
        profile_id=profile_id,
    )

    sim_reports = []
    wan_totals = {"bytes_in": 0.0, "bytes_out": 0.0, "total_bytes": 0.0}

    with db() as conn:
        conn.row_factory = sqlite3.Row
        for sim in sims:
            net_device_id = str(sim["id"])
            rows = []
            used_cached_usage = False
            live_usage_error = ""

            try:
                rows = await ncm_get_all(
                    "/api/v2/net_device_usage_samples/",
                    {"net_device": net_device_id, "created_at__gt": since, "limit": 250},
                    max_pages=usage_max_pages,
                    profile_id=profile_id,
                )
                totals = sum_bytes(rows)

                # Cache samples locally too, so the existing usage chart continues to improve.
                for u in rows:
                    created_at = u.get("created_at")
                    sample_id = str(u.get("created_at_timeuuid") or u.get("id") or f"{net_device_id}:{created_at}")
                    sample_bytes_in = float(u.get("bytes_in") or u.get("rx_bytes") or u.get("in_bytes") or u.get("rx") or 0)
                    sample_bytes_out = float(u.get("bytes_out") or u.get("tx_bytes") or u.get("out_bytes") or u.get("tx") or 0)
                    sample_total = sample_bytes_in + sample_bytes_out
                    conn.execute("""
                        INSERT OR IGNORE INTO usage_samples(
                            id, router_id, net_device_id, sim_label, created_at, bytes_in, bytes_out, total_bytes
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (sample_id, router_id, net_device_id, sim["sim_label"], created_at, sample_bytes_in, sample_bytes_out, sample_total))

            except Exception as exc:
                used_cached_usage = True
                live_usage_error = str(exc)
                print(
                    f"[usage-report] router={router_id} profile={profile_id} "
                    f"net_device={net_device_id} sim={sim['sim_label']} live_usage_failed={live_usage_error}",
                    flush=True,
                )

                cached = conn.execute("""
                    SELECT
                        COUNT(*) AS sample_count,
                        SUM(bytes_in) AS bytes_in,
                        SUM(bytes_out) AS bytes_out,
                        SUM(total_bytes) AS total_bytes
                    FROM usage_samples
                    WHERE router_id = ?
                      AND net_device_id = ?
                      AND created_at >= ?
                """, (router_id, net_device_id, since)).fetchone()

                if not cached or int(cached["sample_count"] or 0) == 0:
                    cached = conn.execute("""
                        SELECT
                            COUNT(*) AS sample_count,
                            SUM(bytes_in) AS bytes_in,
                            SUM(bytes_out) AS bytes_out,
                            SUM(total_bytes) AS total_bytes
                        FROM usage_samples
                        WHERE router_id = ?
                          AND sim_label = ?
                          AND created_at >= ?
                    """, (router_id, sim["sim_label"], since)).fetchone()

                rows = []
                totals = {
                    "bytes_in": float(cached["bytes_in"] or 0) if cached else 0.0,
                    "bytes_out": float(cached["bytes_out"] or 0) if cached else 0.0,
                    "total_bytes": float(cached["total_bytes"] or 0) if cached else 0.0,
                }

            wan_totals["bytes_in"] += totals["bytes_in"]
            wan_totals["bytes_out"] += totals["bytes_out"]
            wan_totals["total_bytes"] += totals["total_bytes"]

            sample_count = len(rows)
            if used_cached_usage:
                try:
                    sample_count = int((cached or {}).get("sample_count") or 0)
                except Exception:
                    sample_count = 0

            sim_reports.append({
                "sim_label": sim["sim_label"],
                "carrier": sim["carrier"],
                "connection_state": sim["connection_state"],
                "net_device_id": net_device_id,
                "sample_count": sample_count,
                "bytes_in": totals["bytes_in"],
                "bytes_out": totals["bytes_out"],
                "total_bytes": totals["total_bytes"],
                "in_mb": bytes_to_mb(totals["bytes_in"]),
                "out_mb": bytes_to_mb(totals["bytes_out"]),
                "total_mb": bytes_to_mb(totals["total_bytes"]),
                "in_gb": bytes_to_gb(totals["bytes_in"]),
                "out_gb": bytes_to_gb(totals["bytes_out"]),
                "total_gb": bytes_to_gb(totals["total_bytes"]),
                "in_human": human_bytes(totals["bytes_in"]),
                "out_human": human_bytes(totals["bytes_out"]),
                "total_human": human_bytes(totals["total_bytes"]),
                "direction": ("Cached fallback" if used_cached_usage and (totals["total_bytes"] > 0) else traffic_direction(totals["bytes_in"], totals["bytes_out"])),
                "source": "cached" if used_cached_usage else "live",
                "live_usage_error": live_usage_error,
            })

        ncm_totals = sum_bytes(router_stream_rows)
        for r in router_stream_rows:
            bytes_in = float(r.get("bytes_in") or 0)
            bytes_out = float(r.get("bytes_out") or 0)
            conn.execute("""
                INSERT OR IGNORE INTO router_stream_usage_samples(
                    created_at_timeuuid, router_id, created_at, bytes_in, bytes_out, total_bytes, period, uptime
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r.get("created_at_timeuuid"), router_id, r.get("created_at"),
                bytes_in, bytes_out, bytes_in + bytes_out,
                r.get("period"), r.get("uptime"),
            ))

        for r in state_rows:
            conn.execute("""
                INSERT OR IGNORE INTO router_state_samples(
                    created_at_timeuuid, router_id, created_at, state, period
                ) VALUES (?, ?, ?, ?, ?)
            """, (r.get("created_at_timeuuid"), router_id, r.get("created_at"), r.get("state"), r.get("period")))

        avg_signal_row = conn.execute("""
            SELECT ROUND(AVG(rsrp), 1) AS avg_rsrp, ROUND(AVG(rsrq), 1) AS avg_rsrq,
                   ROUND(AVG(sinr), 1) AS avg_sinr, ROUND(AVG(dbm), 1) AS avg_dbm
            FROM signal_samples
            WHERE router_id = ? AND created_at >= ?
        """, (router_id, since)).fetchone()

        avg_signal = {
            "avg_rsrp": avg_signal_row[0],
            "avg_rsrq": avg_signal_row[1],
            "avg_sinr": avg_signal_row[2],
            "avg_dbm": avg_signal_row[3],
        } if avg_signal_row else {}
        state_summary = analyze_router_states(state_rows)

        # Bug 11 fallback: if live net_device lookups return no SIM reports,
        # use locally cached usage_samples so the report does not show false-zero usage.
        if not sim_reports and wan_totals["total_bytes"] <= 0:
            cached_usage_rows = conn.execute("""
                SELECT
                    sim_label,
                    COUNT(*) AS sample_count,
                    SUM(bytes_in) AS bytes_in,
                    SUM(bytes_out) AS bytes_out,
                    SUM(total_bytes) AS total_bytes
                FROM usage_samples
                WHERE router_id = ? AND created_at >= ?
                GROUP BY sim_label
                ORDER BY sim_label
            """, (router_id, since)).fetchall()

            for cu in cached_usage_rows:
                cu_bytes_in = float(cu["bytes_in"] or 0)
                cu_bytes_out = float(cu["bytes_out"] or 0)
                cu_total = float(cu["total_bytes"] or (cu_bytes_in + cu_bytes_out) or 0)

                wan_totals["bytes_in"] += cu_bytes_in
                wan_totals["bytes_out"] += cu_bytes_out
                wan_totals["total_bytes"] += cu_total

                sim_reports.append({
                    "sim_label": cu["sim_label"] or "Cached",
                    "carrier": "Cached",
                    "connection_state": "Cached",
                    "net_device_id": "",
                    "sample_count": int(cu["sample_count"] or 0),
                    "bytes_in": cu_bytes_in,
                    "bytes_out": cu_bytes_out,
                    "total_bytes": cu_total,
                    "in_mb": bytes_to_mb(cu_bytes_in),
                    "out_mb": bytes_to_mb(cu_bytes_out),
                    "total_mb": bytes_to_mb(cu_total),
                    "in_gb": bytes_to_gb(cu_bytes_in),
                    "out_gb": bytes_to_gb(cu_bytes_out),
                    "total_gb": bytes_to_gb(cu_total),
                    "in_human": human_bytes(cu_bytes_in),
                    "out_human": human_bytes(cu_bytes_out),
                    "total_human": human_bytes(cu_total),
                    "direction": traffic_direction(cu_bytes_in, cu_bytes_out),
                })

        # Same idea for cached router-stream/NCM usage.
        if ncm_totals["total_bytes"] <= 0:
            cached_stream = conn.execute("""
                SELECT
                    SUM(bytes_in) AS bytes_in,
                    SUM(bytes_out) AS bytes_out,
                    SUM(total_bytes) AS total_bytes
                FROM router_stream_usage_samples
                WHERE router_id = ? AND created_at >= ?
            """, (router_id, since)).fetchone()

            if cached_stream:
                ncm_totals = {
                    "bytes_in": float(cached_stream["bytes_in"] or 0),
                    "bytes_out": float(cached_stream["bytes_out"] or 0),
                    "total_bytes": float(cached_stream["total_bytes"] or 0),
                }

    uncat_totals = {
        "bytes_in": max(wan_totals["bytes_in"] - ncm_totals["bytes_in"], 0),
        "bytes_out": max(wan_totals["bytes_out"] - ncm_totals["bytes_out"], 0),
    }
    uncat_totals["total_bytes"] = uncat_totals["bytes_in"] + uncat_totals["bytes_out"]

    story = usage_story(wan_totals["total_bytes"], ncm_totals["total_bytes"], state_summary, avg_signal)

    return {
        "router_id": router_id,
        "requested_days": days,
        "since_utc": since,
        "until_utc": until,
        "clamped": clamped,
        "sample_counts": {
            "router_stream_usage": len(router_stream_rows),
            "router_state": len(state_rows),
            "net_device_usage_total": sum(s["sample_count"] for s in sim_reports),
        },
        "totals": {
            "wan_bytes_in": wan_totals["bytes_in"],
            "wan_bytes_out": wan_totals["bytes_out"],
            "wan_total_bytes": wan_totals["total_bytes"],
            "wan_in_human": human_bytes(wan_totals["bytes_in"]),
            "wan_out_human": human_bytes(wan_totals["bytes_out"]),
            "wan_total_human": human_bytes(wan_totals["total_bytes"]),
            "wan_total_mb": bytes_to_mb(wan_totals["total_bytes"]),
            "wan_total_gb": bytes_to_gb(wan_totals["total_bytes"]),

            "ncm_bytes_in": ncm_totals["bytes_in"],
            "ncm_bytes_out": ncm_totals["bytes_out"],
            "ncm_total_bytes": ncm_totals["total_bytes"],
            "ncm_in_human": human_bytes(ncm_totals["bytes_in"]),
            "ncm_out_human": human_bytes(ncm_totals["bytes_out"]),
            "ncm_total_human": human_bytes(ncm_totals["total_bytes"]),
            "ncm_total_mb": bytes_to_mb(ncm_totals["total_bytes"]),
            "ncm_total_gb": bytes_to_gb(ncm_totals["total_bytes"]),

            "uncategorized_bytes_in": uncat_totals["bytes_in"],
            "uncategorized_bytes_out": uncat_totals["bytes_out"],
            "uncategorized_bytes": uncat_totals["total_bytes"],
            "uncategorized_in_human": human_bytes(uncat_totals["bytes_in"]),
            "uncategorized_out_human": human_bytes(uncat_totals["bytes_out"]),
            "uncategorized_total_human": human_bytes(uncat_totals["total_bytes"]),
            "uncategorized_mb": bytes_to_mb(uncat_totals["total_bytes"]),
            "uncategorized_gb": bytes_to_gb(uncat_totals["total_bytes"]),
        },
        "percentages": {
            "ncm_percent_of_wan": story["ncm_percent_of_wan"],
            "uncategorized_percent_of_wan": story["uncategorized_percent_of_wan"],
            "ncm_in_percent_of_wan_in": percent(ncm_totals["bytes_in"], wan_totals["bytes_in"]),
            "ncm_out_percent_of_wan_out": percent(ncm_totals["bytes_out"], wan_totals["bytes_out"]),
            "uncategorized_in_percent_of_wan_in": percent(uncat_totals["bytes_in"], wan_totals["bytes_in"]),
            "uncategorized_out_percent_of_wan_out": percent(uncat_totals["bytes_out"], wan_totals["bytes_out"]),
        },
        "directions": {
            "wan": traffic_direction(wan_totals["bytes_in"], wan_totals["bytes_out"]),
            "ncm": traffic_direction(ncm_totals["bytes_in"], ncm_totals["bytes_out"]),
            "uncategorized": traffic_direction(uncat_totals["bytes_in"], uncat_totals["bytes_out"]),
        },
        "state_summary": state_summary,
        "avg_signal": avg_signal,
        "sim_reports": sim_reports,
        "story": story,
    }



async def build_batch_usage_reports(router_ids, days):
    results = []
    success_count = 0
    error_count = 0

    for router_id in router_ids:
        try:
            report = await router_usage_report(router_id, days, profile_id=profile_id)
            results.append({"router_id": router_id, "report": report})
            success_count += 1
        except Exception as exc:
            results.append({"router_id": router_id, "error": str(exc)})
            error_count += 1

    return {
        "requested_days": days,
        "router_count": len(router_ids),
        "success_count": success_count,
        "error_count": error_count,
        "results": results,
    }


@app.post("/usage-report/batch")
async def usage_report_batch(payload: dict = Body(default={})):
    days = int(payload.get("days") or 30)
    router_ids = parse_router_ids(payload.get("router_ids", payload.get("router_ids_text", "")))
    if not router_ids:
        raise HTTPException(status_code=400, detail="No router IDs were provided.")
    if len(router_ids) > 10000:
        raise HTTPException(status_code=400, detail="Please limit data usage analysis reports to 10,000 routers or fewer.")
    return await build_batch_usage_reports(router_ids, days)


@app.post("/usage-report/batch/export.xlsx")
async def usage_report_batch_export_xlsx(payload: dict = Body(default={})):
    days = int(payload.get("days") or 30)
    router_ids = parse_router_ids(payload.get("router_ids", payload.get("router_ids_text", "")))
    if not router_ids:
        raise HTTPException(status_code=400, detail="No router IDs were provided.")
    if len(router_ids) > 10000:
        raise HTTPException(status_code=400, detail="Please limit data usage analysis exports to 10,000 routers or fewer.")

    batch = await build_batch_usage_reports(router_ids, days)

    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Border, Side, Alignment
        from openpyxl.utils import get_column_letter
        from openpyxl.chart import BarChart, Reference
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"openpyxl is required for XLSX export: {exc}")

    wb = Workbook()
    ws = wb.active
    ws.title = "Data Usage Summary"

    dark_fill = PatternFill("solid", fgColor="0F172A")
    blue_fill = PatternFill("solid", fgColor="1D4ED8")
    light_green_fill = PatternFill("solid", fgColor="DCFCE7")
    light_orange_fill = PatternFill("solid", fgColor="FFEDD5")
    light_red_fill = PatternFill("solid", fgColor="FEE2E2")
    header_font = Font(color="FFFFFF", bold=True)
    title_font = Font(color="FFFFFF", bold=True, size=16)
    sub_font = Font(color="E5E7EB", italic=True)
    bold_font = Font(bold=True)
    thin_side = Side(style="thin", color="CBD5E1")
    table_border = Border(left=thin_side, right=thin_side, top=thin_side, bottom=thin_side)

    ws.merge_cells("A1:N1")
    ws["A1"] = "Data Usage Analysis Report"
    ws["A1"].fill = dark_fill
    ws["A1"].font = title_font
    ws["A1"].alignment = Alignment(horizontal="center")

    ws.merge_cells("A2:N2")
    ws["A2"] = "WAN/SIM usage vs. NCM router-stream usage across one or more routers"
    ws["A2"].fill = dark_fill
    ws["A2"].font = sub_font
    ws["A2"].alignment = Alignment(horizontal="center")

    info = [("Requested Days", batch["requested_days"]), ("Routers Requested", batch["router_count"]), ("Succeeded", batch["success_count"]), ("Failed", batch["error_count"])]
    row = 4
    for label, value in info:
        ws.cell(row=row, column=1, value=label).font = bold_font
        ws.cell(row=row, column=2, value=value)
        row += 1

    row = 9
    headers = ["Router ID", "Status", "Clamped", "WAN In", "WAN Out", "WAN Total", "NCM In", "NCM Out", "NCM Total", "NCM % WAN", "Uncat In", "Uncat Out", "Uncat Total", "Narrative"]
    for col, header in enumerate(headers, 1):
        c = ws.cell(row=row, column=col, value=header)
        c.fill = blue_fill
        c.font = header_font
        c.border = table_border
        c.alignment = Alignment(horizontal="center", wrap_text=True)

    for item in batch["results"]:
        row += 1
        if item.get("error"):
            values = [item["router_id"], "Error", "", "", "", "", "", "", "", "", "", "", "", item["error"]]
            fill = light_red_fill
        else:
            r = item["report"]
            t = r["totals"]
            p = r["percentages"]
            values = [
                r["router_id"], "OK", "Yes" if r.get("clamped") else "No",
                t["wan_in_human"], t["wan_out_human"], t["wan_total_human"],
                t["ncm_in_human"], t["ncm_out_human"], t["ncm_total_human"], p["ncm_percent_of_wan"],
                t["uncategorized_in_human"], t["uncategorized_out_human"], t["uncategorized_total_human"],
                r["story"]["narrative"],
            ]
            fill = light_green_fill if not r.get("clamped") else light_orange_fill
        for col, value in enumerate(values, 1):
            c = ws.cell(row=row, column=col, value=value)
            c.border = table_border
            c.alignment = Alignment(wrap_text=True, vertical="top")
        ws.cell(row=row, column=1).fill = fill
        ws.cell(row=row, column=1).font = bold_font

    raw = wb.create_sheet("Raw Overview")
    raw.append(["Router ID", "WAN Bytes In", "WAN Bytes Out", "WAN Total Bytes", "NCM Bytes In", "NCM Bytes Out", "NCM Total Bytes", "Uncat Bytes In", "Uncat Bytes Out", "Uncat Total Bytes", "NCM Percent WAN", "Offline Events", "Offline Hours", "Availability Percent"])
    for item in batch["results"]:
        if item.get("error"):
            raw.append([item["router_id"], "ERROR", item["error"]])
            continue
        r = item["report"]
        t = r["totals"]
        p = r["percentages"]
        st = r["state_summary"]
        raw.append([r["router_id"], t["wan_bytes_in"], t["wan_bytes_out"], t["wan_total_bytes"], t["ncm_bytes_in"], t["ncm_bytes_out"], t["ncm_total_bytes"], t["uncategorized_bytes_in"], t["uncategorized_bytes_out"], t["uncategorized_bytes"], p["ncm_percent_of_wan"], st.get("offline_events"), st.get("offline_hours"), st.get("availability_pct")])

    for item in batch["results"]:
        if item.get("error"):
            continue
        r = item["report"]
        sheet_name = f"R{str(r['router_id'])[-20:]}"[:31]
        detail = wb.create_sheet(sheet_name)
        detail.append(["Router Usage Investigation Report"])
        detail.append(["Router ID", r["router_id"]])
        detail.append(["Requested Days", r["requested_days"]])
        detail.append(["Since UTC", r["since_utc"]])
        detail.append(["Until UTC", r["until_utc"]])
        detail.append(["Clamped", "Yes" if r.get("clamped") else "No"])
        detail.append([])
        detail.append(["Metric", "Inbound", "Outbound", "Total", "Interpretation"])
        detail.append(["WAN Total", r["totals"]["wan_in_human"], r["totals"]["wan_out_human"], r["totals"]["wan_total_human"], r["directions"]["wan"]])
        detail.append(["NCM Router Stream", r["totals"]["ncm_in_human"], r["totals"]["ncm_out_human"], r["totals"]["ncm_total_human"], f'{r["percentages"]["ncm_percent_of_wan"]}% of WAN total'])
        detail.append(["Uncategorized", r["totals"]["uncategorized_in_human"], r["totals"]["uncategorized_out_human"], r["totals"]["uncategorized_total_human"], f'{r["percentages"]["uncategorized_percent_of_wan"]}% of WAN total'])
        detail.append([])
        detail.append(["NCM State Churn"])
        detail.append(["Availability", f'{r["state_summary"].get("availability_pct", "n/a")}%'])
        detail.append(["Offline Events", r["state_summary"].get("offline_events")])
        detail.append(["Offline Hours", r["state_summary"].get("offline_hours")])
        detail.append(["Longest Offline", f'{r["state_summary"].get("longest_offline_minutes")} minutes'])
        detail.append([])
        detail.append(["SIM", "Carrier", "Connection State", "Net Device ID", "Samples", "Inbound", "Outbound", "Total", "Direction"])
        for sim in r["sim_reports"]:
            detail.append([sim["sim_label"], sim["carrier"], sim["connection_state"], sim["net_device_id"], sim["sample_count"], sim["in_human"], sim["out_human"], sim["total_human"], sim["direction"]])
        detail.append([])
        detail.append(["Narrative", r["story"]["narrative"]])

        for cell in detail[1]:
            cell.fill = dark_fill
            cell.font = title_font
        for row_cells in detail.iter_rows():
            for cell in row_cells:
                cell.alignment = Alignment(wrap_text=True, vertical="top")
                if cell.row in (8, 19):
                    cell.fill = blue_fill
                    cell.font = header_font
                    cell.border = table_border
        detail.freeze_panes = "A8"

    for sheet in wb.worksheets:
        for col_idx in range(1, sheet.max_column + 1):
            letter = get_column_letter(col_idx)
            max_len = 0
            for cell in sheet[letter]:
                max_len = max(max_len, len(str(cell.value or "")))
            sheet.column_dimensions[letter].width = min(max(max_len + 2, 12), 46)
        for row_cells in sheet.iter_rows():
            for cell in row_cells:
                cell.alignment = Alignment(wrap_text=True, vertical="top")

    if batch["success_count"] > 0:
        chart = BarChart()
        chart.title = "WAN Total Bytes by Router"
        chart.y_axis.title = "Bytes"
        chart.x_axis.title = "Router"
        max_row = raw.max_row
        data = Reference(raw, min_col=4, min_row=1, max_row=max_row)
        cats = Reference(raw, min_col=1, min_row=2, max_row=max_row)
        chart.add_data(data, titles_from_data=True)
        chart.set_categories(cats)
        ws.add_chart(chart, "P4")

    stream = io.BytesIO()
    wb.save(stream)
    stream.seek(0)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"one_shot_usage_{days}d_{timestamp}.xlsx"
    return StreamingResponse(
        stream,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )




async def resolve_router_identifier(identifier: str, profile_id=None):
    """Resolve a router ID/name into a router ID. Numeric identifiers are treated as router IDs."""
    ident = (identifier or "").strip()
    if not ident:
        raise HTTPException(status_code=400, detail="Blank router identifier")

    if ident.isdigit():
        try:
            payload = await ncm_get(f"/api/v2/routers/{ident}/", profile_id=profile_id)
            data = payload.get("data") if isinstance(payload, dict) else None
            return {
                "requested_identifier": ident,
                "router_id": str((data or {}).get("id") or ident),
                "router_name": (data or {}).get("name") or (data or {}).get("description") or "",
                "router": data or {},
            }
        except Exception:
            return {"requested_identifier": ident, "router_id": ident, "router_name": "", "router": {}}

    attempts = [
        {"name": ident, "limit": 5},
        {"name__icontains": ident, "limit": 5},
        {"q": ident, "limit": 5},
    ]
    last_error = None
    for params in attempts:
        try:
            payload = await ncm_get("/api/v2/routers/", params, profile_id=profile_id)
            rows = payload.get("data", []) if isinstance(payload, dict) else []
            exact = [r for r in rows if str(r.get("name") or "").lower() == ident.lower()]
            chosen = exact[0] if exact else (rows[0] if len(rows) == 1 else None)
            if chosen:
                return {
                    "requested_identifier": ident,
                    "router_id": str(chosen.get("id")),
                    "router_name": chosen.get("name") or "",
                    "router": chosen,
                }
            if rows:
                matches = ", ".join([f"{r.get('name') or 'unnamed'} ({r.get('id')})" for r in rows[:5]])
                raise HTTPException(status_code=400, detail=f"Router name '{ident}' matched multiple routers or was ambiguous: {matches}")
        except HTTPException as exc:
            last_error = exc
            continue
        except Exception as exc:
            last_error = exc
            continue

    detail = getattr(last_error, "detail", None) or str(last_error or "No matching router was found")
    raise HTTPException(status_code=404, detail=f"Could not resolve router '{ident}'. {detail}")


def grade_signal(avg_rsrp, avg_sinr):
    try:
        rsrp = float(avg_rsrp) if avg_rsrp is not None else None
    except Exception:
        rsrp = None
    try:
        sinr = float(avg_sinr) if avg_sinr is not None else None
    except Exception:
        sinr = None

    if rsrp is None and sinr is None:
        return "No signal samples"
    if (rsrp is not None and rsrp <= -111) or (sinr is not None and sinr < 7):
        return "Poor"
    if (rsrp is not None and rsrp <= -102) or (sinr is not None and sinr < 10):
        return "Fair"
    if (rsrp is not None and rsrp <= -84) or (sinr is not None and sinr < 12.5):
        return "Good"
    return "Excellent"


async def build_signal_health_report(router_id: str, days: int, profile_id=None):
    since, until, clamped = clamp_usage_window(days)
    await poll_router(router_id, include_signal=True, profile_id=profile_id)

    with db() as conn:
        conn.row_factory = sqlite3.Row
        sims = conn.execute("""
            SELECT nd.id, nd.sim_label, nd.carrier, nd.connection_state,
                   ROUND(AVG(ss.rsrp), 1) AS avg_rsrp,
                   ROUND(AVG(ss.rsrq), 1) AS avg_rsrq,
                   ROUND(AVG(ss.sinr), 1) AS avg_sinr,
                   ROUND(AVG(ss.dbm), 1) AS avg_dbm,
                   COUNT(ss.created_at_timeuuid) AS sample_count
            FROM net_devices nd
            LEFT JOIN signal_samples ss ON ss.net_device_id = nd.id AND ss.created_at >= ?
            WHERE nd.router_id = ?
            GROUP BY nd.id, nd.sim_label, nd.carrier, nd.connection_state
            ORDER BY nd.sim_label
        """, (since, router_id)).fetchall()

    sim_reports = []
    vals_rsrp = []
    vals_sinr = []
    for s in sims:
        row = dict(s)
        row["grade"] = grade_signal(row.get("avg_rsrp"), row.get("avg_sinr"))
        if row.get("avg_rsrp") is not None:
            vals_rsrp.append(float(row["avg_rsrp"]))
        if row.get("avg_sinr") is not None:
            vals_sinr.append(float(row["avg_sinr"]))
        sim_reports.append(row)

    # If historical signal samples are unavailable, fall back to latest net_device_metrics.
    if not vals_rsrp and not vals_sinr:
        metric_reports = []
        vals_rsrp = []
        vals_sinr = []

        with db() as conn:
            conn.row_factory = sqlite3.Row
            nds = conn.execute("""
                SELECT id, sim_label, carrier, connection_state
                FROM net_devices
                WHERE router_id = ?
                ORDER BY sim_label
            """, (router_id,)).fetchall()

        for nd in nds:
            try:
                metrics = await ncm_get(
                    "/api/v2/net_device_metrics/",
                    {"id": str(nd["id"]), "limit": 1},
                    profile_id=profile_id
                )
                rows = metrics.get("data", []) if isinstance(metrics, dict) else []
                m = rows[0] if rows else {}

                rsrp = m.get("rsrp")
                rsrq = m.get("rsrq")
                sinr = m.get("sinr") if m.get("sinr") is not None else m.get("rssnr")
                dbm = m.get("dbm")
                signal_percent = m.get("signal_strength") or m.get("signal_percent")

                if rsrp is not None:
                    vals_rsrp.append(float(rsrp))
                if sinr is not None:
                    vals_sinr.append(float(sinr))

                metric_reports.append({
                    "id": nd["id"],
                    "sim_label": nd["sim_label"],
                    "carrier": nd["carrier"],
                    "connection_state": nd["connection_state"],
                    "avg_rsrp": rsrp,
                    "avg_rsrq": rsrq,
                    "avg_sinr": sinr,
                    "avg_dbm": dbm,
                    "signal_percent": signal_percent,
                    "sample_count": 1 if m else 0,
                    "source": "latest net_device_metrics",
                    "grade": grade_signal(rsrp, sinr),
                })
            except Exception:
                metric_reports.append({
                    "id": nd["id"],
                    "sim_label": nd["sim_label"],
                    "carrier": nd["carrier"],
                    "connection_state": nd["connection_state"],
                    "sample_count": 0,
                    "source": "net_device_metrics unavailable",
                    "grade": "No signal samples",
                })

        if metric_reports:
            sim_reports = metric_reports

    avg_rsrp = round(sum(vals_rsrp) / len(vals_rsrp), 1) if vals_rsrp else None
    avg_sinr = round(sum(vals_sinr) / len(vals_sinr), 1) if vals_sinr else None
    return {
        "since_utc": since,
        "until_utc": until,
        "clamped": clamped,
        "avg_rsrp": avg_rsrp,
        "avg_sinr": avg_sinr,
        "overall": grade_signal(avg_rsrp, avg_sinr),
        "sims": sim_reports,
    }


async def build_geo_location_report(router_id: str, profile_id=None):
    locations = await ncm_get("/api/v2/locations/", {"router": router_id, "limit": 1}, profile_id=profile_id)
    loc_rows = locations.get("data", []) if isinstance(locations, dict) else []
    if not loc_rows:
        return {"found": False, "label": "No location returned"}
    loc = loc_rows[0]
    lat = loc.get("latitude")
    lon = loc.get("longitude")
    try:
        await reverse_geocode_location(router_id, lat, lon)
    except Exception:
        pass
    label = ""
    with db() as conn:
        row = conn.execute("SELECT label FROM location_labels WHERE router_id = ?", (router_id,)).fetchone()
        label = row[0] if row else ""
    return {
        "found": True,
        "latitude": lat,
        "longitude": lon,
        "accuracy": loc.get("accuracy"),
        "method": loc.get("method"),
        "updated_at": loc.get("updated_at"),
        "updated_at_local": to_local_string(loc.get("updated_at")),
        "label": label,
    }


async def build_alerts_report(router_id: str, days: int, profile_id=None):
    since, until, clamped = clamp_usage_window(days)
    rows = await ncm_get_all("/api/v2/alerts/", {"router": router_id, "created_at__gt": since, "limit": 250}, max_pages=12, profile_id=profile_id)
    counts = {}
    for row in rows:
        t = row.get("type") or "unknown"
        counts[t] = counts.get(t, 0) + 1
    latest = rows[0] if rows else {}

    failover_interface_map = {}
    try:
        nds = await ncm_get_all("/api/v2/net_devices/", {"router": router_id}, profile_id=profile_id)
        for nd in nds:
            name = nd.get("name")
            model = (nd.get("model") or "").upper()
            sim = None
            if "SIM1" in model:
                sim = "SIM1"
            elif "SIM2" in model:
                sim = "SIM2"
            if name and sim:
                failover_interface_map[name] = {
                    "sim": sim,
                    "carrier": nd.get("modem_fw"),
                    "net_device_id": nd.get("id"),
                }
    except Exception:
        failover_interface_map = {}

    failover_summary = summarize_failover_alerts(rows, failover_interface_map)

    return {
        "since_utc": since,
        "until_utc": until,
        "clamped": clamped,
        "total_alerts": len(rows),
        "counts_by_type": counts,
        "latest_type": latest.get("type"),
        "latest_info": latest.get("friendly_info"),
        "latest_created_at": latest.get("created_at"),
        "latest_created_at_local": to_local_string(latest.get("created_at")),
        "latest_alerts": rows[:15],
        "failover_summary": failover_summary,
    }



def summarize_failover_alerts(rows, interface_map=None):
    interface_map = interface_map or {}

    def parse_failover_ts(value):
        if not value:
            return None
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except Exception:
            return None

    failovers = [
        r for r in rows
        if r.get("type") == "failover_event"
        or (r.get("info") or {}).get("event_type") == "failover"
    ]

    daily = {}
    sim1_to_sim2 = 0
    sim2_to_sim1 = 0
    first_seen = None
    last_seen = None

    for r in failovers:
        info = r.get("info") or {}
        ts = info.get("started_at") or r.get("created_at")
        dt = parse_failover_ts(ts)

        if dt:
            day = dt.date().isoformat()
            daily[day] = daily.get(day, 0) + 1

            if first_seen is None or dt < first_seen:
                first_seen = dt
            if last_seen is None or dt > last_seen:
                last_seen = dt

        prev_if = info.get("previous_wan_interface")
        curr_if = info.get("current_wan_interface")

        prev_sim = interface_map.get(prev_if, {}).get("sim")
        curr_sim = interface_map.get(curr_if, {}).get("sim")

        if prev_sim == "SIM1" and curr_sim == "SIM2":
            sim1_to_sim2 += 1
        elif prev_sim == "SIM2" and curr_sim == "SIM1":
            sim2_to_sim1 += 1

    records = len(failovers)
    days = len(daily)
    peak = max(daily.values()) if daily else 0
    avg = round(records / days, 2) if days else 0

    if records:
        summary = f"{records} failover alert records across {days} day(s). Peak day: {peak}. SIM1→SIM2: {sim1_to_sim2}; SIM2→SIM1: {sim2_to_sim1}."
    else:
        summary = "No failover_event alerts found."

    return {
        "alert_records": records,
        "distinct_failover_days": days,
        "confirmed_transitions": records,
        "sim1_to_sim2": sim1_to_sim2,
        "sim2_to_sim1": sim2_to_sim1,
        "most_failovers_one_day": peak,
        "average_per_active_day": avg,
        "first_seen": first_seen.isoformat() if first_seen else None,
        "last_seen": last_seen.isoformat() if last_seen else None,
        "summary": summary,
        "daily": daily,
    }


def summarize_deep_dive(report):
    parts = []
    sig = report.get("signal_health")
    if sig:
        parts.append(f"Signal: {sig.get('overall')}" )
    geo = report.get("geo_location")
    if geo:
        parts.append(f"Location: {geo.get('label') or geo.get('method') or ('found' if geo.get('found') else 'not found')}")
    usage = report.get("data_usage")
    if usage:
        totals = usage.get("totals", {})
        pct = usage.get("percentages", {}).get("ncm_percent_of_wan")
        parts.append(f"WAN: {totals.get('wan_total_human')} / NCM: {totals.get('ncm_total_human')} ({pct}% of WAN)")
    alerts = report.get("alerts")
    if alerts:
        fo = alerts.get("failover_summary") or {}
        if fo.get("alert_records"):
            parts.append(f"Failovers: {fo.get('alert_records')} records / {fo.get('distinct_failover_days')} day(s), peak {fo.get('most_failovers_one_day')}/day")
        else:
            parts.append(f"Alerts: {alerts.get('total_alerts', 0)}")
    return " | ".join([p for p in parts if p]) or "Deep dive completed."


async def build_router_deep_dive_reports(identifiers, days, modules, profile_id=None):
    valid_modules = {"signal_health", "geo_location", "data_usage", "alerts", "failover"}
    selected = [m for m in modules if m in valid_modules]
    if not selected:
        selected = ["signal_health", "geo_location", "data_usage", "alerts"]

    results = []
    success_count = 0
    error_count = 0
    for ident in identifiers:
        try:
            resolved = await resolve_router_identifier(ident, profile_id=profile_id)
            router_id = resolved["router_id"]
            report = {
                "requested_identifier": ident,
                "router_id": router_id,
                "router_name": resolved.get("router_name", ""),
                "modules": selected,
                "profile_id": profile_id or get_default_profile_id(),
            }
            if "signal_health" in selected:
                report["signal_health"] = await build_signal_health_report(router_id, days, profile_id=profile_id)
            if "geo_location" in selected:
                report["geo_location"] = await build_geo_location_report(router_id, profile_id=profile_id)
            if "data_usage" in selected:
                report["data_usage"] = await router_usage_report(router_id, days, profile_id=profile_id)
            if "alerts" in selected or "failover" in selected:
                report["alerts"] = await build_alerts_report(router_id, days, profile_id=profile_id)
            report["summary"] = summarize_deep_dive(report)
            results.append({"requested_identifier": ident, "router_id": router_id, "report": report})
            success_count += 1
        except Exception as exc:
            detail = getattr(exc, "detail", None) or str(exc)
            results.append({"requested_identifier": ident, "error": detail})
            error_count += 1

    return {
        "requested_days": days,
        "router_count": len(identifiers),
        "success_count": success_count,
        "error_count": error_count,
        "modules": selected,
        "results": results,
    }


@app.post("/router-deep-dive")
async def router_deep_dive(payload: dict = Body(default={})):
    days = int(payload.get("days") or 30)
    identifiers = parse_router_ids(payload.get("router_ids", payload.get("router_ids_text", "")))
    modules = payload.get("modules") or []
    if not identifiers:
        raise HTTPException(status_code=400, detail="No router IDs or names were provided.")
    if len(identifiers) > 10000:
        raise HTTPException(status_code=400, detail="Please limit Router Deep Dive runs to 10,000 routers or fewer.")
    return await build_router_deep_dive_reports(identifiers, days, modules)


@app.post("/router-deep-dive/export.xlsx")
async def router_deep_dive_export_xlsx(payload: dict = Body(default={})):
    days = int(payload.get("days") or 30)
    identifiers = parse_router_ids(payload.get("router_ids", payload.get("router_ids_text", "")))
    modules = payload.get("modules") or []
    if not identifiers:
        raise HTTPException(status_code=400, detail="No router IDs or names were provided.")
    # Export is intentionally capped to avoid long-running synchronous API calls and giant workbooks.
    # If more scale is needed later, the next step should be a background job + saved report artifact.
    if len(identifiers) > 100:
        raise HTTPException(status_code=400, detail="Please limit Router Deep Dive exports to 100 routers or fewer.")

    batch = await build_router_deep_dive_reports(identifiers, days, modules)

    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Border, Side, Alignment
        from openpyxl.utils import get_column_letter
        from openpyxl.worksheet.table import Table, TableStyleInfo
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"openpyxl is required for XLSX export: {exc}")

    wb = Workbook()
    wb.remove(wb.active)

    dark_fill = PatternFill("solid", fgColor="0F172A")
    blue_fill = PatternFill("solid", fgColor="1D4ED8")
    light_blue_fill = PatternFill("solid", fgColor="DBEAFE")
    red_fill = PatternFill("solid", fgColor="FEE2E2")
    green_fill = PatternFill("solid", fgColor="DCFCE7")
    amber_fill = PatternFill("solid", fgColor="FEF3C7")
    gray_fill = PatternFill("solid", fgColor="F1F5F9")
    header_font = Font(color="FFFFFF", bold=True)
    title_font = Font(color="FFFFFF", bold=True, size=16)
    section_font = Font(bold=True, size=13)
    bold_font = Font(bold=True)
    small_font = Font(size=9, color="64748B")
    thin_side = Side(style="thin", color="CBD5E1")
    border = Border(left=thin_side, right=thin_side, top=thin_side, bottom=thin_side)

    def safe_num(value, default=0.0):
        try:
            return float(value or 0)
        except Exception:
            return default

    def pct(value):
        if value is None or value == "":
            return ""
        try:
            return float(value) / 100
        except Exception:
            return ""

    def set_title(ws, title, subtitle=""):
        ws.merge_cells("A1:J1")
        ws["A1"] = title
        ws["A1"].fill = dark_fill
        ws["A1"].font = title_font
        ws["A1"].alignment = Alignment(horizontal="center")
        if subtitle:
            ws.merge_cells("A2:J2")
            ws["A2"] = subtitle
            ws["A2"].font = small_font
            ws["A2"].alignment = Alignment(horizontal="center")

    def style_sheet(ws, freeze="A5"):
        for row in ws.iter_rows():
            for cell in row:
                cell.alignment = Alignment(wrap_text=True, vertical="top")
        for col_idx in range(1, ws.max_column + 1):
            letter = get_column_letter(col_idx)
            max_len = 0
            for cell in ws[letter]:
                max_len = max(max_len, len(str(cell.value or "")))
            ws.column_dimensions[letter].width = min(max(max_len + 2, 12), 55)
        ws.freeze_panes = freeze

    def style_header_row(ws, row_num):
        for cell in ws[row_num]:
            cell.fill = blue_fill
            cell.font = header_font
            cell.border = border
            cell.alignment = Alignment(horizontal="center", wrap_text=True, vertical="center")

    def add_table(ws, name, start_row, end_row, end_col):
        if end_row <= start_row:
            return
        ref = f"A{start_row}:{get_column_letter(end_col)}{end_row}"
        # Excel table names cannot contain spaces/symbols and must be unique.
        table_name = ''.join(ch for ch in name if ch.isalnum())[:240]
        tab = Table(displayName=table_name, ref=ref)
        tab.tableStyleInfo = TableStyleInfo(name="TableStyleMedium2", showFirstColumn=False, showLastColumn=False, showRowStripes=True, showColumnStripes=False)
        try:
            ws.add_table(tab)
        except Exception:
            pass

    successes = [x for x in batch.get("results", []) if not x.get("error")]
    errors = [x for x in batch.get("results", []) if x.get("error")]

    # Aggregate totals for executive summary.
    agg = {
        "wan_in": 0.0, "wan_out": 0.0, "wan_total": 0.0,
        "ncm_in": 0.0, "ncm_out": 0.0, "ncm_total": 0.0,
        "uncat_in": 0.0, "uncat_out": 0.0, "uncat_total": 0.0,
        "offline_events": 0, "offline_hours": 0.0, "alert_count": 0,
    }
    for item in successes:
        r = item.get("report", {})
        du = r.get("data_usage") or {}
        t = du.get("totals", {})
        agg["wan_in"] += safe_num(t.get("wan_in_bytes"))
        agg["wan_out"] += safe_num(t.get("wan_out_bytes"))
        agg["wan_total"] += safe_num(t.get("wan_total_bytes"))
        agg["ncm_in"] += safe_num(t.get("ncm_in_bytes"))
        agg["ncm_out"] += safe_num(t.get("ncm_out_bytes"))
        agg["ncm_total"] += safe_num(t.get("ncm_total_bytes"))
        agg["uncat_in"] += safe_num(t.get("uncategorized_in_bytes"))
        agg["uncat_out"] += safe_num(t.get("uncategorized_out_bytes"))
        agg["uncat_total"] += safe_num(t.get("uncategorized_total_bytes"))
        states = du.get("state_summary", {}) or {}
        agg["offline_events"] += int(states.get("offline_events") or 0)
        agg["offline_hours"] += safe_num(states.get("offline_hours"))
        alerts = r.get("alerts") or {}
        agg["alert_count"] += int(alerts.get("total_alerts") or 0)

    # Executive Summary sheet: readable with a few routers or a lot of routers.
    ws = wb.create_sheet("Executive Summary")
    set_title(ws, "Router Deep Dive Report", f"Window: last {batch.get('requested_days')} days | Modules: {', '.join(batch.get('modules', []))}")
    ws.append([])
    ws.append(["Report Scope", "Value", "Notes"])
    style_header_row(ws, 4)
    scope_rows = [
        ["Routers Requested", batch.get("router_count", 0), "Total identifiers submitted."],
        ["Routers Succeeded", batch.get("success_count", 0), "Resolved and processed successfully."],
        ["Routers Failed", batch.get("error_count", 0), "See Errors sheet if non-zero."],
        ["Requested Days", batch.get("requested_days", days), "NCM sample retention is clamped near 90 days."],
    ]
    for row in scope_rows:
        ws.append(row)
    for row in range(5, ws.max_row + 1):
        ws.cell(row=row, column=1).font = bold_font
        ws.cell(row=row, column=1).fill = gray_fill

    # Recompute usage aggregate from the same per-router totals used by Data Usage Detail.
    # This prevents the Usage Rollup from showing 0 when detail rows have valid inbound/outbound values.
    agg["wan_in"] = 0.0
    agg["wan_out"] = 0.0
    agg["wan_total"] = 0.0
    agg["ncm_in"] = 0.0
    agg["ncm_out"] = 0.0
    agg["ncm_total"] = 0.0
    agg["uncat_in"] = 0.0
    agg["uncat_out"] = 0.0
    agg["uncat_total"] = 0.0

    for item in batch.get("results", []):
        if item.get("error"):
            continue
        r = item.get("report", {}) or {}
        du = r.get("data_usage") or {}
        totals = du.get("totals") or {}

        agg["wan_in"] += float(totals.get("wan_bytes_in") or 0)
        agg["wan_out"] += float(totals.get("wan_bytes_out") or 0)
        agg["wan_total"] += float(totals.get("wan_total_bytes") or 0)

        agg["ncm_in"] += float(totals.get("ncm_bytes_in") or 0)
        agg["ncm_out"] += float(totals.get("ncm_bytes_out") or 0)
        agg["ncm_total"] += float(totals.get("ncm_total_bytes") or 0)

        agg["uncat_in"] += float(totals.get("uncategorized_bytes_in") or 0)
        agg["uncat_out"] += float(totals.get("uncategorized_bytes_out") or 0)
        agg["uncat_total"] += float(totals.get("uncategorized_bytes") or totals.get("uncategorized_total_bytes") or 0)

    ws.append([])
    ws.append(["Usage Rollup", "Inbound", "Outbound", "Combined", "What this means"])
    usage_header = ws.max_row
    style_header_row(ws, usage_header)
    rollup_rows = [
        ["WAN Total", human_bytes(agg["wan_in"]), human_bytes(agg["wan_out"]), human_bytes(agg["wan_total"]), "Total SIM/WAN usage across analyzed routers."],
        ["NCM Router Stream", human_bytes(agg["ncm_in"]), human_bytes(agg["ncm_out"]), human_bytes(agg["ncm_total"]), "Traffic attributable to router-stream/NCM management telemetry."],
        ["Uncategorized", human_bytes(agg["uncat_in"]), human_bytes(agg["uncat_out"]), human_bytes(agg["uncat_total"]), "Likely customer/application, encapsulated, or otherwise non-NCM traffic."],
    ]
    for row in rollup_rows:
        ws.append(row)
    ws.append([])
    ws.append(["Operational Rollup", "Value", "Notes"])
    op_header = ws.max_row
    style_header_row(ws, op_header)
    ncm_pct = (agg["ncm_total"] / agg["wan_total"] * 100) if agg["wan_total"] else 0
    op_rows = [
        ["NCM % of WAN", f"{ncm_pct:.2f}%", "Higher percentages may be normal for low-use sites or unstable connectivity."],
        ["Offline Events", agg["offline_events"], "Total offline state samples across routers."],
        ["Offline Hours", round(agg["offline_hours"], 2), "Cumulative offline period from router state samples."],
        ["Alerts", agg["alert_count"], "Total alerts returned for selected window."],
    ]
    for row in op_rows:
        ws.append(row)
    style_sheet(ws, "A5")

    # Scalable summary table: one row per router, not one worksheet per router.
    ws = wb.create_sheet("Router Summary")
    set_title(ws, "Router Summary", "One row per router. Use filters to quickly find high usage, high NCM %, poor signal, or alert-heavy routers.")
    ws.append([])
    headers = [
        "Requested", "Router ID", "Router Name", "Status", "Signal Grade", "Location", "WAN Total", "NCM Total", "NCM % WAN",
        "Uncategorized", "Offline Events", "Offline Hours", "Alerts", "Failover Records", "Failover Days", "Peak Failover Day", "SIM1→SIM2", "SIM2→SIM1", "Summary"
    ]
    ws.append(headers)
    style_header_row(ws, 4)
    start_row = 4
    for item in batch.get("results", []):
        if item.get("error"):
            ws.append([item.get("requested_identifier"), "", "", "Error", "", "", "", "", "", "", "", "", "", item.get("error")])
            ws.cell(row=ws.max_row, column=4).fill = red_fill
            continue
        r = item.get("report", {})
        du = r.get("data_usage") or {}
        totals = du.get("totals", {})
        pct_map = du.get("percentages", {}) or {}
        states = du.get("state_summary", {}) or {}
        sig = r.get("signal_health") or {}
        geo = r.get("geo_location") or {}
        alerts = r.get("alerts") or {}
        ws.append([
            r.get("requested_identifier"), r.get("router_id"), r.get("router_name"), "OK",
            sig.get("overall", "Not run"), geo.get("label") or geo.get("method") or ("Not run" if not geo else "No location"),
            totals.get("wan_total_human", "Not run"), totals.get("ncm_total_human", "Not run"), pct(pct_map.get("ncm_percent_of_wan")),
            totals.get("uncategorized_total_human", "Not run"), states.get("offline_events", "Not run"), states.get("offline_hours", "Not run"),
            alerts.get("total_alerts", "Not run"),
            (alerts.get("failover_summary") or {}).get("alert_records", ""),
            (alerts.get("failover_summary") or {}).get("distinct_failover_days", ""),
            (alerts.get("failover_summary") or {}).get("most_failovers_one_day", ""),
            (alerts.get("failover_summary") or {}).get("sim1_to_sim2", ""),
            (alerts.get("failover_summary") or {}).get("sim2_to_sim1", ""),
            r.get("summary"),
        ])
        ws.cell(row=ws.max_row, column=4).fill = green_fill
        if ws.cell(row=ws.max_row, column=9).value != "":
            ws.cell(row=ws.max_row, column=9).number_format = "0.00%"
    add_table(ws, "RouterSummary", start_row, ws.max_row, len(headers))
    style_sheet(ws, "A5")

    # Data Usage Detail: long-form and scalable for many routers.
    if "data_usage" in batch.get("modules", []):
        ws = wb.create_sheet("Data Usage Detail")
        set_title(ws, "Data Usage Detail", "WAN, NCM, and uncategorized usage broken out by inbound/outbound direction.")
        ws.append([])
        headers = [
            "Router ID", "Router Name", "Metric", "Inbound", "Outbound", "Total", "Direction", "NCM % WAN", "Offline Events", "Offline Hours", "Narrative"
        ]
        ws.append(headers)
        style_header_row(ws, 4)
        start_row = 4
        for item in successes:
            r = item.get("report", {})
            du = r.get("data_usage") or {}
            if not du:
                continue
            t = du.get("totals", {})
            directions = du.get("directions", {}) or {}
            percentages = du.get("percentages", {}) or {}
            states = du.get("state_summary", {}) or {}
            story = du.get("story", {}) or {}
            for metric, in_key, out_key, total_key, direction_key in [
                ("WAN Total", "wan_in_human", "wan_out_human", "wan_total_human", "wan"),
                ("NCM Router Stream", "ncm_in_human", "ncm_out_human", "ncm_total_human", "ncm"),
                ("Uncategorized", "uncategorized_in_human", "uncategorized_out_human", "uncategorized_total_human", "uncategorized"),
            ]:
                ws.append([
                    r.get("router_id"), r.get("router_name"), metric,
                    t.get(in_key), t.get(out_key), t.get(total_key), directions.get(direction_key),
                    pct(percentages.get("ncm_percent_of_wan")) if metric == "NCM Router Stream" else "",
                    states.get("offline_events"), states.get("offline_hours"), story.get("narrative") if metric == "WAN Total" else "",
                ])
                if ws.cell(row=ws.max_row, column=8).value != "":
                    ws.cell(row=ws.max_row, column=8).number_format = "0.00%"
        add_table(ws, "DataUsageDetail", start_row, ws.max_row, len(headers))
        style_sheet(ws, "A5")

        ws = wb.create_sheet("SIM Usage Detail")
        set_title(ws, "SIM Usage Detail", "Per-SIM usage with inbound/outbound direction. This is the best sheet for SIM1/SIM2 comparison.")
        ws.append([])
        headers = ["Router ID", "Router Name", "SIM", "Carrier", "State", "Net Device ID", "Samples", "Inbound", "Outbound", "Total", "Direction"]
        ws.append(headers)
        style_header_row(ws, 4)
        start_row = 4
        for item in successes:
            r = item.get("report", {})
            du = r.get("data_usage") or {}
            for sim in du.get("sim_reports", []) if du else []:
                ws.append([
                    r.get("router_id"), r.get("router_name"), sim.get("sim_label"), sim.get("carrier"), sim.get("connection_state"),
                    sim.get("net_device_id"), sim.get("sample_count"), sim.get("in_human"), sim.get("out_human"), sim.get("total_human"), sim.get("direction"),
                ])
        add_table(ws, "SIMUsageDetail", start_row, ws.max_row, len(headers))
        style_sheet(ws, "A5")

    if "signal_health" in batch.get("modules", []):
        ws = wb.create_sheet("Signal Health")
        set_title(ws, "Signal Health", "Per-SIM signal health across selected routers.")
        ws.append([])
        headers = ["Router ID", "Router Name", "Overall Grade", "SIM", "Carrier", "State", "Samples", "Avg RSRP", "Avg RSRQ", "Avg SINR", "Avg dBm", "SIM Grade"]
        ws.append(headers)
        style_header_row(ws, 4)
        start_row = 4
        for item in successes:
            r = item.get("report", {})
            sig = r.get("signal_health") or {}
            if not sig:
                continue
            for sim in sig.get("sims", []) or [{}]:
                ws.append([
                    r.get("router_id"), r.get("router_name"), sig.get("overall"), sim.get("sim_label"), sim.get("carrier"), sim.get("connection_state"),
                    sim.get("sample_count"), sim.get("avg_rsrp"), sim.get("avg_rsrq"), sim.get("avg_sinr"), sim.get("avg_dbm"), sim.get("grade"),
                ])
        add_table(ws, "SignalHealth", start_row, ws.max_row, len(headers))
        style_sheet(ws, "A5")

    if "geo_location" in batch.get("modules", []):
        ws = wb.create_sheet("Geo Location")
        set_title(ws, "Geo Location", "Latest location data returned by NCM.")
        ws.append([])
        headers = ["Router ID", "Router Name", "Found", "Label", "Latitude", "Longitude", "Accuracy", "Method", "Updated Local"]
        ws.append(headers)
        style_header_row(ws, 4)
        start_row = 4
        for item in successes:
            r = item.get("report", {})
            geo = r.get("geo_location") or {}
            if not geo:
                continue
            ws.append([r.get("router_id"), r.get("router_name"), geo.get("found"), geo.get("label"), geo.get("latitude"), geo.get("longitude"), geo.get("accuracy"), geo.get("method"), geo.get("updated_at_local")])
        add_table(ws, "GeoLocation", start_row, ws.max_row, len(headers))
        style_sheet(ws, "A5")

    if "alerts" in batch.get("modules", []):
        ws = wb.create_sheet("Alert Summary")
        set_title(ws, "Alert Summary", "Alert totals by router and latest alert context.")
        ws.append([])
        headers = ["Router ID", "Router Name", "Total Alerts", "Latest Type", "Latest Created Local", "Latest Info"]
        ws.append(headers)
        style_header_row(ws, 4)
        start_row = 4
        for item in successes:
            r = item.get("report", {})
            al = r.get("alerts") or {}
            if not al:
                continue
            ws.append([r.get("router_id"), r.get("router_name"), al.get("total_alerts"), al.get("latest_type"), al.get("latest_created_at_local"), al.get("latest_info")])
        add_table(ws, "AlertSummary", start_row, ws.max_row, len(headers))
        style_sheet(ws, "A5")

        ws = wb.create_sheet("Alert Type Counts")
        set_title(ws, "Alert Type Counts", "Long-form alert counts by type for pivoting/filtering.")
        ws.append([])
        headers = ["Router ID", "Router Name", "Alert Type", "Count"]
        ws.append(headers)
        style_header_row(ws, 4)
        start_row = 4
        for item in successes:
            r = item.get("report", {})
            al = r.get("alerts") or {}
            for alert_type, count in (al.get("counts_by_type") or {}).items():
                ws.append([r.get("router_id"), r.get("router_name"), alert_type, count])
        add_table(ws, "AlertTypeCounts", start_row, ws.max_row, len(headers))
        style_sheet(ws, "A5")

    if errors:
        ws = wb.create_sheet("Errors")
        set_title(ws, "Errors", "Routers that could not be resolved or processed.")
        ws.append([])
        headers = ["Requested Identifier", "Error"]
        ws.append(headers)
        style_header_row(ws, 4)
        start_row = 4
        for item in errors:
            ws.append([item.get("requested_identifier"), item.get("error")])
        add_table(ws, "Errors", start_row, ws.max_row, len(headers))
        style_sheet(ws, "A5")

    # Friendly per-router sheets are useful for small batches, but they do not scale well to large exports.
    # For larger exports, the filtered summary/detail sheets above are easier and faster to use.
    if len(successes) <= 25:
        for item in successes:
            r = item.get("report", {})
            sheet_name = f"R{str(r.get('router_id', 'unknown'))[-20:]}"[:31]
            sheet = wb.create_sheet(sheet_name)
            set_title(sheet, "Router Deep Dive Detail", f"Router ID: {r.get('router_id')} | Name: {r.get('router_name') or 'n/a'}")
            sheet.append([])
            sheet.append(["Field", "Value"])
            style_header_row(sheet, 4)
            for k, v in [
                ("Router ID", r.get("router_id")),
                ("Router Name", r.get("router_name")),
                ("Requested Identifier", r.get("requested_identifier")),
                ("Summary", r.get("summary")),
            ]:
                sheet.append([k, v])
            sheet.append([])

            if r.get("data_usage"):
                du = r["data_usage"]
                t = du.get("totals", {})
                sheet.append(["Data Usage Analysis"])
                sheet.cell(row=sheet.max_row, column=1).font = section_font
                sheet.append(["Metric", "Inbound", "Outbound", "Total", "Direction"])
                style_header_row(sheet, sheet.max_row)
                sheet.append(["WAN Total", t.get("wan_in_human"), t.get("wan_out_human"), t.get("wan_total_human"), du.get("directions", {}).get("wan")])
                sheet.append(["NCM Router Stream", t.get("ncm_in_human"), t.get("ncm_out_human"), t.get("ncm_total_human"), du.get("directions", {}).get("ncm")])
                sheet.append(["Uncategorized", t.get("uncategorized_in_human"), t.get("uncategorized_out_human"), t.get("uncategorized_total_human"), du.get("directions", {}).get("uncategorized")])
                sheet.append(["Narrative", du.get("story", {}).get("narrative")])
                sheet.append([])

            if r.get("signal_health"):
                sig = r["signal_health"]
                sheet.append(["Signal Health"])
                sheet.cell(row=sheet.max_row, column=1).font = section_font
                sheet.append(["Overall", sig.get("overall"), "Avg RSRP", sig.get("avg_rsrp"), "Avg SINR", sig.get("avg_sinr")])
                sheet.append([])

            if r.get("geo_location"):
                geo = r["geo_location"]
                sheet.append(["Geo Location"])
                sheet.cell(row=sheet.max_row, column=1).font = section_font
                for k in ["found", "label", "latitude", "longitude", "accuracy", "method", "updated_at_local"]:
                    sheet.append([k, geo.get(k)])
                sheet.append([])

            if r.get("alerts"):
                al = r["alerts"]
                sheet.append(["Alerts"])
                sheet.cell(row=sheet.max_row, column=1).font = section_font
                sheet.append(["Total Alerts", al.get("total_alerts")])
                fo = al.get("failover_summary") or {}
                if fo.get("alert_records"):
                    sheet.append(["Failover Alert Records", fo.get("alert_records")])
                    sheet.append(["Distinct Failover Days", fo.get("distinct_failover_days")])
                    sheet.append(["SIM1→SIM2", fo.get("sim1_to_sim2")])
                    sheet.append(["SIM2→SIM1", fo.get("sim2_to_sim1")])
                    sheet.append(["Most Failovers In One Day", fo.get("most_failovers_one_day")])
                    sheet.append(["Average Per Active Day", fo.get("average_per_active_day")])
                    sheet.append(["First Failover Seen", fo.get("first_seen")])
                    sheet.append(["Last Failover Seen", fo.get("last_seen")])
                    sheet.append(["Failover Summary", fo.get("summary")])
                sheet.append(["Latest Type", al.get("latest_type")])
                sheet.append(["Latest Info", al.get("latest_info")])
                sheet.append([])
            style_sheet(sheet, "A5")

    # Put summary sheets first and make the workbook pleasant to open.
    for ws in wb.worksheets:
        for row in ws.iter_rows():
            for cell in row:
                cell.border = border
        ws.sheet_view.showGridLines = False

    stream = io.BytesIO()
    wb.save(stream)
    stream.seek(0)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"router_deep_dive_{days}d_{timestamp}.xlsx"
    return StreamingResponse(
        stream,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )

@app.get("/router/{router_id}/usage-report/export.csv")
async def router_usage_report_export_csv(router_id: str, days: int = Query(30)):
    report = await router_usage_report(router_id, days, profile_id=profile_id)
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Router Usage Investigation Report"])
    writer.writerow(["Router ID", report["router_id"]])
    writer.writerow(["Requested Days", report["requested_days"]])
    writer.writerow(["Since UTC", report["since_utc"]])
    writer.writerow(["Until UTC", report["until_utc"]])
    writer.writerow(["Clamped", report["clamped"]])
    writer.writerow([])
    writer.writerow(["Metric", "Inbound", "Outbound", "Total", "Notes"])
    writer.writerow(["WAN Total", report["totals"]["wan_in_human"], report["totals"]["wan_out_human"], report["totals"]["wan_total_human"], report["directions"]["wan"]])
    writer.writerow(["NCM Router Stream", report["totals"]["ncm_in_human"], report["totals"]["ncm_out_human"], report["totals"]["ncm_total_human"], f'{report["percentages"]["ncm_percent_of_wan"]}% of WAN total'])
    writer.writerow(["Uncategorized", report["totals"]["uncategorized_in_human"], report["totals"]["uncategorized_out_human"], report["totals"]["uncategorized_total_human"], f'{report["percentages"]["uncategorized_percent_of_wan"]}% of WAN total'])
    writer.writerow([])
    writer.writerow(["Availability %", report["state_summary"].get("availability_pct")])
    writer.writerow(["Offline Events", report["state_summary"].get("offline_events")])
    writer.writerow(["Offline Hours", report["state_summary"].get("offline_hours")])
    writer.writerow(["Longest Offline Minutes", report["state_summary"].get("longest_offline_minutes")])
    writer.writerow(["Narrative", report["story"]["narrative"]])
    writer.writerow([])
    writer.writerow(["SIM", "Carrier", "Connection State", "Net Device ID", "Samples", "Inbound", "Outbound", "Total", "Direction"])
    for sim in report["sim_reports"]:
        writer.writerow([sim["sim_label"], sim["carrier"], sim["connection_state"], sim["net_device_id"], sim["sample_count"], sim["in_human"], sim["out_human"], sim["total_human"], sim["direction"]])

    filename = f"router_{router_id}_usage_{report['requested_days']}d.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/router/{router_id}/usage-report/export.xlsx")
async def router_usage_report_export_xlsx(router_id: str, days: int = Query(30), profile_id=None):
    report = await router_usage_report(router_id, days, profile_id=profile_id)

    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Border, Side, Alignment
        from openpyxl.utils import get_column_letter
        from openpyxl.chart import BarChart, Reference
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"openpyxl is required for XLSX export: {exc}")

    wb = Workbook()
    ws = wb.active
    ws.title = "Usage Summary"

    def export_mb(value):
        try:
            return round(float(value or 0) / (1024 * 1024), 2)
        except Exception:
            return 0.0

    def export_gb(value):
        try:
            return round(float(value or 0) / (1024 * 1024 * 1024), 4)
        except Exception:
            return 0.0

    def pct_value(value):
        try:
            return round(float(value or 0), 2)
        except Exception:
            return 0.0

    dark_fill = PatternFill("solid", fgColor="0F172A")
    blue_fill = PatternFill("solid", fgColor="1D4ED8")
    light_blue_fill = PatternFill("solid", fgColor="DBEAFE")
    light_green_fill = PatternFill("solid", fgColor="DCFCE7")
    light_orange_fill = PatternFill("solid", fgColor="FFEDD5")
    header_font = Font(color="FFFFFF", bold=True)
    title_font = Font(color="FFFFFF", bold=True, size=16)
    sub_font = Font(color="E5E7EB", italic=True)
    bold_font = Font(bold=True)
    thin_side = Side(style="thin", color="CBD5E1")
    table_border = Border(left=thin_side, right=thin_side, top=thin_side, bottom=thin_side)

    ws.merge_cells("A1:E1")
    ws["A1"] = "Router Usage Investigation Report"
    ws["A1"].fill = dark_fill
    ws["A1"].font = title_font
    ws["A1"].alignment = Alignment(horizontal="center")

    ws.merge_cells("A2:E2")
    ws["A2"] = "WAN/SIM usage vs. NCM router-stream usage, with inbound/outbound directionality"
    ws["A2"].fill = dark_fill
    ws["A2"].font = sub_font
    ws["A2"].alignment = Alignment(horizontal="center")

    info_rows = [
        ("Router ID", report["router_id"]),
        ("Requested Days", report["requested_days"]),
        ("Since UTC", report["since_utc"]),
        ("Until UTC", report["until_utc"]),
        ("Clamped", "Yes" if report["clamped"] else "No"),
    ]
    row = 4
    for label, value in info_rows:
        ws.cell(row=row, column=1, value=label).font = bold_font
        ws.cell(row=row, column=2, value=value)
        row += 1

    row += 1
    ws.cell(row=row, column=1, value="Executive Narrative").font = bold_font
    ws.cell(row=row, column=2, value=report["story"]["narrative"])
    ws.merge_cells(start_row=row, start_column=2, end_row=row, end_column=5)
    ws.cell(row=row, column=2).alignment = Alignment(wrap_text=True, vertical="top")

    row += 2
    table_start = row
    headers = ["Metric", "Inbound", "Outbound", "Total", "Interpretation"]
    for col, header in enumerate(headers, 1):
        c = ws.cell(row=row, column=col, value=header)
        c.fill = blue_fill
        c.font = header_font
        c.border = table_border
        c.alignment = Alignment(horizontal="center")

    summary_rows = [
        ["WAN Total", report["totals"]["wan_in_human"], report["totals"]["wan_out_human"], report["totals"]["wan_total_human"], report["directions"]["wan"]],
        ["NCM Router Stream", report["totals"]["ncm_in_human"], report["totals"]["ncm_out_human"], report["totals"]["ncm_total_human"], f'{report["percentages"]["ncm_percent_of_wan"]}% of WAN total'],
        ["Uncategorized", report["totals"]["uncategorized_in_human"], report["totals"]["uncategorized_out_human"], report["totals"]["uncategorized_total_human"], f'{report["percentages"]["uncategorized_percent_of_wan"]}% of WAN total'],
    ]
    for values in summary_rows:
        row += 1
        for col, value in enumerate(values, 1):
            c = ws.cell(row=row, column=col, value=value)
            c.border = table_border
            c.alignment = Alignment(wrap_text=True)
        if values[0] == "WAN Total":
            ws.cell(row=row, column=1).fill = light_blue_fill
        elif values[0] == "NCM Router Stream":
            ws.cell(row=row, column=1).fill = light_green_fill
        else:
            ws.cell(row=row, column=1).fill = light_orange_fill
        ws.cell(row=row, column=1).font = bold_font

    row += 2
    ws.cell(row=row, column=1, value="NCM State Churn").font = bold_font
    state_rows = [
        ["Availability", f'{report["state_summary"].get("availability_pct", "n/a")}%'],
        ["Offline Events", report["state_summary"].get("offline_events")],
        ["Offline Hours", report["state_summary"].get("offline_hours")],
        ["Longest Offline", f'{report["state_summary"].get("longest_offline_minutes")} minutes'],
    ]
    for label, value in state_rows:
        row += 1
        ws.cell(row=row, column=1, value=label).font = bold_font
        ws.cell(row=row, column=2, value=value)

    row += 2
    sim_table_start = row
    sim_headers = ["SIM", "Carrier", "Connection State", "Net Device ID", "Samples", "Inbound", "Outbound", "Total", "Direction"]
    for col, header in enumerate(sim_headers, 1):
        c = ws.cell(row=row, column=col, value=header)
        c.fill = blue_fill
        c.font = header_font
        c.border = table_border
        c.alignment = Alignment(horizontal="center")

    for sim in report["sim_reports"]:
        row += 1
        values = [sim["sim_label"], sim["carrier"], sim["connection_state"], sim["net_device_id"], sim["sample_count"], sim["in_human"], sim["out_human"], sim["total_human"], sim["direction"]]
        for col, value in enumerate(values, 1):
            c = ws.cell(row=row, column=col, value=value)
            c.border = table_border
            c.alignment = Alignment(wrap_text=True)

    raw = wb.create_sheet("Raw Metrics")
    raw.append(["Metric", "In MB", "Out MB", "Total MB", "Percent In", "Percent Out", "Percent Total"])
    raw.append([
        "WAN Total",
        export_mb(report["totals"]["wan_bytes_in"]),
        export_mb(report["totals"]["wan_bytes_out"]),
        export_mb(report["totals"]["wan_total_bytes"]),
        100,
        100,
        100,
    ])
    raw.append([
        "NCM Router Stream",
        export_mb(report["totals"]["ncm_bytes_in"]),
        export_mb(report["totals"]["ncm_bytes_out"]),
        export_mb(report["totals"]["ncm_total_bytes"]),
        pct_value(report["percentages"]["ncm_in_percent_of_wan_in"]),
        pct_value(report["percentages"]["ncm_out_percent_of_wan_out"]),
        pct_value(report["percentages"]["ncm_percent_of_wan"]),
    ])
    raw.append([
        "Uncategorized",
        export_mb(report["totals"]["uncategorized_bytes_in"]),
        export_mb(report["totals"]["uncategorized_bytes_out"]),
        export_mb(report["totals"]["uncategorized_bytes"]),
        pct_value(report["percentages"]["uncategorized_in_percent_of_wan_in"]),
        pct_value(report["percentages"]["uncategorized_out_percent_of_wan_out"]),
        pct_value(report["percentages"]["uncategorized_percent_of_wan"]),
    ])
    raw.append([])
    raw.append(["SIM", "Carrier", "Connection State", "Net Device ID", "Samples", "In MB", "Out MB", "Total MB"])
    for sim in report["sim_reports"]:
        raw.append([
            sim["sim_label"],
            sim["carrier"],
            sim["connection_state"],
            sim["net_device_id"],
            sim["sample_count"],
            export_mb(sim["bytes_in"]),
            export_mb(sim["bytes_out"]),
            export_mb(sim["total_bytes"]),
        ])

    for sheet in [ws, raw]:
        sheet.freeze_panes = "A4" if sheet == ws else "A2"
        for col_idx in range(1, sheet.max_column + 1):
            letter = get_column_letter(col_idx)
            max_len = 0
            for cell in sheet[letter]:
                max_len = max(max_len, len(str(cell.value or "")))
            sheet.column_dimensions[letter].width = min(max(max_len + 2, 12), 42)
        for row_cells in sheet.iter_rows():
            for cell in row_cells:
                cell.alignment = Alignment(wrap_text=True, vertical="top")

    # Chart based on Total MB for readability.
    chart = BarChart()
    chart.title = "WAN vs NCM vs Uncategorized Usage (MB)"
    chart.y_axis.title = "MB"
    chart.x_axis.title = ""
    data = Reference(raw, min_col=4, min_row=1, max_row=4)
    cats = Reference(raw, min_col=1, min_row=2, max_row=4)
    chart.add_data(data, titles_from_data=True)
    chart.set_categories(cats)
    chart.height = 9
    chart.width = 18
    ws.add_chart(chart, "G4")

    stream = io.BytesIO()
    wb.save(stream)
    stream.seek(0)

    filename = f"router_{router_id}_usage_{report['requested_days']}d.xlsx"
    return StreamingResponse(
        stream,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/router-view/{router_id}", response_class=HTMLResponse)
async def router_view(
    router_id: str,
    profile_id: int = Query(default=1),
    pool: str = Query(default=None),
):
    safe_pool = html.escape(pool) if pool else ""
    back_to_pool_html = (
        f'<button onclick="window.location.href=\'/monitoring-targets-ui?profile_id={profile_id}\'">← Router Overview</button>'
    )
    return f"""
<!DOCTYPE html>
<html>
<head>
  <title>Router {router_id}</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body {{ font-family: Arial, sans-serif; background: #0f172a; color: #e5e7eb; padding: 30px; }}
    a {{ color: #38bdf8; text-decoration: none; }}
    button {{
      background: #1e293b; color: #e5e7eb; border: 1px solid #334155;
      border-radius: 999px; padding: 9px 13px; cursor: pointer; margin: 4px;
    }}
    button.primary {{ background: #2563eb; border-color: #60a5fa; }}
    .router-nav {{
      display:flex;
      gap:8px;
      flex-wrap:wrap;
      align-items:center;
      margin-bottom:14px;
    }}
    .router-nav button {{
      margin:0;
    }}
    textarea, input, select {{
      width: 100%; background: #020617; color: #e5e7eb; border: 1px solid #334155;
      border-radius: 12px; padding: 10px; box-sizing: border-box;
    }}
    .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 18px; padding: 20px; margin-bottom: 18px; box-shadow: 0 20px 35px rgba(0,0,0,.25); }}
    .small {{ color: #94a3b8; font-size: 14px; }}
    .pill {{ display: inline-block; padding: 5px 10px; border-radius: 999px; background: #1e293b; margin: 4px; }}
    .ok {{ color: #22c55e; }} .watch {{ color: #facc15; }} .review {{ color: #fb7185; }} .store {{ color: #38bdf8; }}
    .sig-excellent {{ color:#22c55e; font-weight:700; }}
    .sig-good {{ color:#eab308; font-weight:700; }}
    .sig-fair {{ color:#fb923c; font-weight:700; }}
    .sig-poor {{ color:#fb7185; font-weight:700; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 16px; }}
    .device-hero {{
      display: flex; align-items: center; justify-content: center;
      min-height: 210px; background: radial-gradient(circle at center, rgba(56,189,248,.14), rgba(2,6,23,.35));
    }}
    .device-hero img {{
      max-width: min(460px, 90%); max-height: 240px; width: auto; height: auto;
      object-fit: contain; filter: drop-shadow(0 24px 36px rgba(0,0,0,.45));
    }}
    #map {{ height: 420px; border-radius: 18px; overflow: hidden; }}
    .chart-box {{
      background:#020617;
      border-radius:12px;
      padding:14px;
      height:280px;
      box-sizing:border-box;
      position:relative;
      overflow:hidden;
    }}
    .logs-modal-back {{
      display:none; position:fixed; inset:0; background:rgba(0,0,0,.72);
      z-index:1000000; align-items:center; justify-content:center; padding:24px;
    }}
    .logs-modal {{
      width:min(1180px,96vw); max-height:88vh; overflow:hidden;
      background:#111827; border:1px solid #334155; border-radius:22px;
      box-shadow:0 28px 90px rgba(0,0,0,.65); display:flex; flex-direction:column;
    }}
    .logs-modal-top {{
      display:flex; justify-content:space-between; align-items:flex-start; gap:14px;
      padding:18px 20px; border-bottom:1px solid #1f2937;
      background:linear-gradient(135deg,#172554,#0f172a);
    }}
    .logs-modal-top h2 {{ margin:0; font-size:22px; }}
    .logs-toolbar {{
      display:flex; gap:10px; flex-wrap:wrap; align-items:center;
      padding:14px 20px; border-bottom:1px solid #1f2937;
    }}
    .logs-toolbar select {{
      width:auto; background:#020617; color:#e5e7eb; border:1px solid #334155;
      border-radius:999px; padding:9px 12px;
    }}
    .logs-body {{ overflow:auto; padding:0 20px 20px; }}
    .logs-table {{ width:100%; border-collapse:collapse; margin-top:14px; font-size:13px; }}
    .logs-table th {{
      position:sticky; top:0; background:#1e293b; color:#e5e7eb;
      text-align:left; padding:10px; border-bottom:1px solid #334155; z-index:1;
    }}
    .logs-table td {{ vertical-align:top; padding:9px 10px; border-bottom:1px solid #1f2937; }}
    .logs-message {{ max-width:700px; white-space:pre-wrap; word-break:break-word; }}
    .level-ERR, .level-ERROR, .level-CRIT, .level-CRITICAL {{ color:#fecdd3; font-weight:800; }}
    .level-WARN, .level-WARNING {{ color:#fde68a; font-weight:800; }}
    .level-NOTICE {{ color:#bfdbfe; font-weight:800; }}
    .level-INFO {{ color:#bbf7d0; font-weight:800; }}
    .level-DEBUG {{ color:#cbd5e1; font-weight:800; }}
    .chart-box {{
      position:relative;
    }}
    .chart-box canvas {{
      display:block;
      box-sizing:border-box;
      cursor: crosshair !important;
    }}

    .chart-box:hover {{
      cursor: crosshair;
    }}
    .no-data-overlay {{
      position:absolute;
      inset:0;
      display:none;
      align-items:center;
      justify-content:center;
      background:rgba(15,23,42,.42);
      color:rgba(255,255,255,.72);
      font-size:14px;
      font-weight:700;
      letter-spacing:.02em;
      border-radius:12px;
      pointer-events:none;
      backdrop-filter:blur(1px);
    }}
    .no-data-overlay.visible {{
      display:flex;
    }}
    .cellular-bars {{
      display:flex;
      align-items:flex-end;
      gap:6px;
      height:120px;
      padding:12px;
      background:#020617;
      border:1px solid #1e293b;
      border-radius:14px;
      overflow:hidden;
    }}
    .cellular-bar-wrap {{
      flex:1;
      min-width:8px;
      display:flex;
      flex-direction:column;
      align-items:center;
      justify-content:flex-end;
      height:100%;
      gap:6px;
    }}
    .cellular-bar {{
      width:100%;
      min-height:3px;
      border-radius:8px 8px 2px 2px;
      background:linear-gradient(180deg,#38bdf8,#2563eb);
      box-shadow:0 0 18px rgba(56,189,248,.25);
    }}
    .cellular-bar.empty {{
      background:#1e293b;
      box-shadow:none;
      opacity:.55;
    }}
    .cellular-bar-label {{
      font-size:10px;
      color:#94a3b8;
      writing-mode:vertical-rl;
      transform:rotate(180deg);
      max-height:42px;
      overflow:hidden;
    }}
    .cellular-event-table {{
      width:100%;
      border-collapse:collapse;
      margin-top:12px;
      font-size:12px;
    }}
    .cellular-event-table th {{
      text-align:left;
      color:#cbd5e1;
      padding:8px;
      border-bottom:1px solid #334155;
      background:#0f172a;
    }}
    .cellular-event-table td {{
      padding:8px;
      border-bottom:1px solid #1e293b;
      vertical-align:top;
    }}
    .cellular-kpi-row {{
      display:grid;
      grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
      gap:10px;
      margin:10px 0 12px;
    }}
    .cellular-kpi {{
      background:#020617;
      border:1px solid #1e293b;
      border-radius:14px;
      padding:12px;
    }}
    .cellular-kpi .big {{
      font-size:28px;
      font-weight:900;
      line-height:1;
    }}
    .cellular-kpi .label {{
      font-size:11px;
      color:#94a3b8;
      margin-top:5px;
      text-transform:uppercase;
      letter-spacing:.05em;
    }}
    .radio-context-pop {{
      position:relative;
      display:inline-block;
    }}
    .radio-context-btn {{
      position:relative;
      overflow:hidden;
      background:linear-gradient(135deg,rgba(37,99,235,.92),rgba(14,165,233,.62));
      border:1px solid rgba(125,211,252,.72);
      color:#e0f2fe;
      font-size:12px;
      font-weight:900;
      padding:7px 11px;
      border-radius:999px;
      box-shadow:0 0 0 1px rgba(56,189,248,.12), 0 8px 20px rgba(14,165,233,.12);
      cursor:help;
      white-space:nowrap;
    }}
    .radio-context-btn::after {{
      content:"";
      position:absolute;
      top:-45%;
      left:-80%;
      width:55%;
      height:190%;
      background:linear-gradient(90deg,transparent,rgba(255,255,255,.35),transparent);
      transform:rotate(25deg);
      animation:radioShine 3.8s infinite;
    }}
    @keyframes radioShine {{
      0% {{ left:-80%; }}
      38% {{ left:135%; }}
      100% {{ left:135%; }}
    }}
    .radio-context-tip {{
      display:none;
      position:absolute;
      left:0;
      top:calc(100% + 8px);
      z-index:9999;
      min-width:330px;
      max-width:430px;
      background:#020617;
      color:#e5e7eb;
      border:1px solid rgba(125,211,252,.45);
      border-radius:14px;
      padding:12px;
      box-shadow:0 22px 45px rgba(0,0,0,.55);
      font-size:12px;
      line-height:1.45;
    }}
    .radio-context-pop:hover .radio-context-tip,
    .radio-context-pop:focus-within .radio-context-tip {{
      display:block;
    }}
    .radio-context-tip b {{
      color:#bae6fd;
    }}
    .radio-context-tip .muted {{
      color:#94a3b8;
      margin-top:2px;
      word-break:break-word;
    }}
    canvas {{ background:#020617; border-radius:12px; }}
  </style>
</head>
<body>
  <div style="margin-bottom: 14px;">
    <div class="router-nav">
      {back_to_pool_html}
      <button onclick="window.location.href='/ui?profile_id={profile_id}'">← Dashboard</button>
      <button onclick="window.location.href='/pool-admin?profile_id={profile_id}'">Pool Administration</button>
    </div>
  </div>
<div id="activeProfileBranding" style="margin:18px 18px 10px 18px;background:linear-gradient(135deg,#102042,#0b1220);border:1px solid #263449;border-radius:20px;padding:18px 20px;display:flex;align-items:center;gap:16px;box-shadow:0 18px 40px rgba(0,0,0,.28);">
  <div id="activeProfileLogoBox" style="width:76px;height:76px;border-radius:18px;background:#020617;border:1px solid #334155;display:flex;align-items:center;justify-content:center;overflow:hidden;font-size:32px;font-weight:900;color:#60a5fa;flex:0 0 auto;">?</div>
  <div>
    <div id="activeProfileName" style="font-size:28px;font-weight:900;line-height:1.1;">Dashboard</div>
    <div id="activeProfileCompany" style="font-size:14px;color:#93c5fd;margin-top:4px;"></div>
    <div id="activeProfilePurpose" style="font-size:13px;color:#cbd5e1;margin-top:6px;"></div>
  </div>
</div>



<div id="apiOdometer" aria-label="NCM API odometer" style="position:fixed;top:18px;right:22px;z-index:999999;width:230px;background:linear-gradient(135deg,rgba(15,23,42,.98),rgba(30,64,105,.98));color:#f8fafc;border:1px solid rgba(255,255,255,.18);border-radius:18px;padding:13px 15px;box-shadow:0 18px 42px rgba(0,0,0,.35);text-align:right;font-family:inherit;">
  <div style="font-size:11px;font-weight:800;letter-spacing:.07em;text-transform:uppercase;opacity:.82;">NCM API Odometer</div>
  <div id="odoMonth" style="margin-top:3px;font-size:30px;line-height:1;font-weight:900;">0</div>
  <div style="margin-top:3px;font-size:11px;opacity:.72;">This Month</div>
  <div style="margin-top:8px;padding-top:8px;border-top:1px solid rgba(255,255,255,.15);font-size:11px;opacity:.85;">Today: <span id="odoToday">0</span> · Lifetime: <span id="odoLifetime">0</span></div>
</div>







  
  <h1>Router {router_id}</h1>

  <div>
    <button class="primary" onclick="refreshRouter(false)">Refresh This Router</button>
    <button onclick="refreshRouter(true)">Refresh This Router + Signal</button>
    <button onclick="openRouterLogs()">Router Logs</button>
    <span class="small" id="refreshStatus"></span>
  </div>

  <div id="routerLogsModalBack" class="logs-modal-back" onclick="closeRouterLogs(event)">
    <div class="logs-modal" onclick="event.stopPropagation()">
      <div class="logs-modal-top">
        <div>
          <h2 id="routerLogsTitle">Router Logs — Router {router_id}</h2>
          <div id="routerLogsSubtitle" class="small">Select a date range and refresh logs.</div>
        </div>
        <button onclick="closeRouterLogs()">Close</button>
      </div>

      <div class="logs-toolbar">
        <label class="small">Date window</label>
        <select id="routerLogsDays" onchange="loadRouterLogs()">
          <option value="1">Last 24 Hours</option>
          <option value="7" selected>Last 7 Days</option>
          <option value="14">Last 14 Days</option>
          <option value="30">Last 30 Days</option>
          <option value="90">Last 90 Days</option>
        </select>
        <button onclick="loadRouterLogs()">Refresh Logs</button>
        <button onclick="exportRouterLogs()">Export XLSX</button>
        <span id="routerLogsStatus" class="small"></span>
      </div>

      <div class="logs-body">
        <div id="routerLogsContent" class="small">No logs loaded yet.</div>
      </div>
    </div>
  </div>

  <div id="content">Loading router details...</div>

<script>
let routerData = null;

function activeProfileId() {{
  const params = new URLSearchParams(window.location.search);
  const pid = params.get('profile_id') || localStorage.getItem('ncm_active_profile_id') || '1';
  localStorage.setItem('ncm_active_profile_id', pid);
  return pid;
}}

function openRouterLogs() {{
  document.getElementById('routerLogsTitle').innerText = 'Router Logs — Router {router_id}';
  document.getElementById('routerLogsSubtitle').innerText = `Profile ID: ${{activeProfileId()}}`;
  document.getElementById('routerLogsStatus').innerText = '';
  document.getElementById('routerLogsContent').innerHTML = '<div class="small">Loading logs...</div>';
  document.getElementById('routerLogsModalBack').style.display = 'flex';
  loadRouterLogs();
}}

function closeRouterLogs(event) {{
  if (event && event.target && event.target.id !== 'routerLogsModalBack') return;
  const modal = document.getElementById('routerLogsModalBack');
  if (modal) modal.style.display = 'none';
}}

async function loadRouterLogs() {{
  const days = document.getElementById('routerLogsDays').value || '7';
  const pid = activeProfileId();
  const status = document.getElementById('routerLogsStatus');
  const box = document.getElementById('routerLogsContent');

  status.innerText = 'Loading...';

  try {{
    const res = await fetch(`/router-logs/{router_id}?days=${{encodeURIComponent(days)}}&profile_id=${{encodeURIComponent(pid)}}&limit=1000`, {{cache:'no-store'}});
    const data = await res.json();

    if (!res.ok) {{
      status.innerText = 'Failed.';
      box.innerHTML = `<div class="review">Unable to load router logs.</div><pre class="small">${{escapeHtml(JSON.stringify(data, null, 2))}}</pre>`;
      return;
    }}

    const logs = data.logs || [];
    status.innerText = `${{logs.length}} log rows loaded.`;
    document.getElementById('routerLogsSubtitle').innerText =
      `Router ${{data.router_id}} • Profile ID ${{data.profile_id}} • Last ${{data.days}} day(s) • Since ${{data.since_utc}}`;

    if (!logs.length) {{
      status.innerText = '0 log rows loaded.';
      box.innerHTML = `
        <div class="card" style="border-color:#334155;">
          <b>0 logs recorded for this date window.</b><br>
          <span class="small">
            Router logs must be enabled at the NCM group level before NCM will collect and return router log data.
            If logs are expected here, confirm router logging is enabled for this router's group in NCM, then allow time for new logs to be collected.
          </span>
        </div>
      `;
      return;
    }}

    box.innerHTML = `
      <table class="logs-table">
        <thead>
          <tr>
            <th>Reported Local</th>
            <th>Level</th>
            <th>Source</th>
            <th>Message</th>
            <th>Created Local</th>
            <th>Seq</th>
          </tr>
        </thead>
        <tbody>
          ${{logs.map(log => {{
            const level = String(log.level || '');
            const levelClass = 'level-' + level.replace(/[^A-Za-z]/g, '').toUpperCase();
            return `<tr>
              <td>${{escapeHtml(log.reported_at_local || log.reported_at || '')}}</td>
              <td class="${{escapeHtml(levelClass)}}">${{escapeHtml(level || 'n/a')}}</td>
              <td>${{escapeHtml(log.source || '')}}</td>
              <td class="logs-message">${{escapeHtml(log.message || '')}}</td>
              <td>${{escapeHtml(log.created_at_local || log.created_at || '')}}</td>
              <td>${{escapeHtml(log.sequence ?? '')}}</td>
            </tr>`;
          }}).join('')}}
        </tbody>
      </table>
    `;
  }} catch (e) {{
    status.innerText = 'Failed.';
    box.innerHTML = `<div class="review">Unable to load router logs: ${{escapeHtml(e.message || e)}}</div>`;
  }}
}}

function exportRouterLogs() {{
  const days = document.getElementById('routerLogsDays').value || '7';
  const pid = activeProfileId();
  window.location = `/router-logs/{router_id}/export.xlsx?days=${{encodeURIComponent(days)}}&profile_id=${{encodeURIComponent(pid)}}`;
}}

function escapeHtml(value) {{
  return String(value ?? '').replace(/[&<>"']/g, ch => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[ch]));
}}

function formatBytes(bytes) {{
  const b = Number(bytes || 0);
  if (b >= 1024 ** 3) return `${{(b / (1024 ** 3)).toFixed(2)}} GB`;
  return `${{(b / (1024 ** 2)).toFixed(1)}} MB`;
}}

function signalClass(metric, value) {{
  if (value === null || value === undefined || value === 'n/a') return '';
  const v = Number(value);
  if (Number.isNaN(v)) return '';
  if (metric === 'rsrp') {{ if (v > -84) return 'sig-excellent'; if (v >= -102) return 'sig-good'; if (v >= -111) return 'sig-fair'; return 'sig-poor'; }}
  if (metric === 'rsrq') {{ if (v > -5) return 'sig-excellent'; if (v >= -9) return 'sig-good'; if (v >= -12) return 'sig-fair'; return 'sig-poor'; }}
  if (metric === 'sinr') {{ if (v > 12.5) return 'sig-excellent'; if (v >= 10) return 'sig-good'; if (v >= 7) return 'sig-fair'; return 'sig-poor'; }}
  if (metric === 'dbm') {{ if (v > -65) return 'sig-excellent'; if (v >= -75) return 'sig-good'; if (v >= -85) return 'sig-fair'; return 'sig-poor'; }}
  return '';
}}

function formatUptime(seconds) {{
  if (seconds === null || seconds === undefined || Number.isNaN(Number(seconds))) return 'n/a';
  const total = Math.floor(Number(seconds));
  if (total > 0 && total < 60) return '<1m';
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const mins = Math.floor((total % 3600) / 60);
  if (days > 0) return `${{days}}d ${{hours}}h`;
  if (hours > 0) return `${{hours}}h ${{mins}}m`;
  return `${{mins}}m`;
}}

function ensureMiniSpinnerStyle() {{
    if (document.getElementById('miniSpinnerStyle')) return;

    const style = document.createElement('style');
    style.id = 'miniSpinnerStyle';
    style.textContent = `
      @keyframes miniSpin {{ to {{ transform: rotate(360deg); }} }}
      .mini-spinner {{
        display:inline-block;
        width:14px;
        height:14px;
        border:2px solid rgba(148,163,184,.45);
        border-top-color:#38bdf8;
        border-radius:50%;
        animation:miniSpin .8s linear infinite;
        vertical-align:-2px;
        margin-right:8px;
      }}
    `;
    document.head.appendChild(style);
  }}

  function setRefreshStatusLoading(text) {{
    ensureMiniSpinnerStyle();
    const s = document.getElementById('refreshStatus');
    if (s) s.innerHTML = `<span class="mini-spinner"></span>${{escapeHtml(text)}}`;
  }}

  function setRefreshStatusText(text) {{
    const s = document.getElementById('refreshStatus');
    if (s) s.textContent = text;
  }}

  let refreshSpinnerTimer = null;

  function startRefreshSpinner(text) {{
    const s = document.getElementById('refreshStatus');
    if (!s) return;

    const frames = ['◐', '◓', '◑', '◒'];
    let i = 0;

    if (refreshSpinnerTimer) clearInterval(refreshSpinnerTimer);

    s.textContent = frames[i] + ' ' + text;
    refreshSpinnerTimer = setInterval(() => {{
      i = (i + 1) % frames.length;
      s.textContent = frames[i] + ' ' + text;
    }}, 140);
  }}

  function stopRefreshSpinner(text) {{
    const s = document.getElementById('refreshStatus');
    if (refreshSpinnerTimer) {{
      clearInterval(refreshSpinnerTimer);
      refreshSpinnerTimer = null;
    }}
    if (s) s.textContent = text;
  }}

  async function refreshRouter(includeSignal) {{
    startRefreshSpinner(includeSignal ? 'Refreshing + signal...' : 'Refreshing...');

    try {{
      const res = await fetch('/refresh-router/{router_id}', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{include_signal: includeSignal, profile_id: activeProfileId()}})
      }});

      stopRefreshSpinner(res.ok ? 'Refresh complete.' : 'Refresh failed.');
      await loadRouter();
      return res.ok;
    }} catch (e) {{
      stopRefreshSpinner('Refresh failed: ' + String(e.message || e));
      return false;
    }}
  }}

  async function addRouterComment() {{
  const comment = document.getElementById('routerComment').value.trim();
  if (!comment) return;

  await fetch('/router/{router_id}/comment', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{comment}})
  }});

  document.getElementById('routerComment').value = '';
  await loadRouter();
}}

async function resolveIssue(issueId, nonIncident) {{
  const note = prompt(nonIncident ? 'Resolution note for non-incident:' : 'Resolution note:') || '';
  await fetch(`/issue/${{issueId}}/resolve`, {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{note, non_incident: nonIncident}})
  }});
  await loadRouter();
}}

async function markForReview() {{
  const note = prompt('Why are we marking this router for further review?', 'Manually marked for further review.');
  if (note === null) return;
  const res = await fetch('/router/{router_id}/mark-review', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{note: note || 'Manually marked for further review.'}})
  }});
  document.getElementById('refreshStatus').innerText = res.ok ? 'Marked for further review.' : 'Failed to mark for review.';
  await loadRouter();
}}

async function markStoreCycle() {{
  const note = prompt('Note for expected operational event:', 'Marked as expected operational behavior.') || 'Marked as expected operational behavior.';
  await fetch('/router/{router_id}/mark-expected-store-cycle', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{note}})
  }});
  await loadRouter();
}}


function formatCellularTime(value) {{
  if (!value) return 'n/a';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}}

function shortCell(value) {{
  const s = String(value || 'n/a');
  return s.length > 24 ? s.slice(0, 24) + '…' : s;
}}

function radioContextText(prefix, e) {{
  const parts = [];
  const rfband = e[prefix + '_rfband'];
  const rfband5g = e[prefix + '_rfband5g'];
  const rfchannel = e[prefix + '_rfchannel'];
  const ltebw = e[prefix + '_ltebandwidth'];
  const mtu = e[prefix + '_mtu'];

  if (rfband) parts.push('LTE B' + rfband);
  if (rfband5g) parts.push('5G ' + rfband5g);
  if (rfchannel) parts.push('CH ' + rfchannel);
  if (ltebw) parts.push('BW ' + ltebw);
  if (mtu) parts.push('MTU ' + mtu);

  return parts.length ? parts.join(' / ') : 'n/a';
}}

function isFirstRadioContextCapture(e) {{
  const oldText = radioContextText('old', e);
  const newText = radioContextText('new', e);
  return String(e.event_type || '') === 'radio_context_change'
    && oldText === 'n/a'
    && newText !== 'n/a';
}}

function friendlyCellularEventType(e) {{
  if (isFirstRadioContextCapture(e)) return 'Radio context captured';

  const labels = {{
    cell_id_change: 'Cell identity changed',
    tac_change: 'Tracking area changed',
    tac_and_cell_change: 'Cell/tac changed',
    carrier_change: 'Carrier changed',
    service_type_change: 'Service type changed',
    '5g_service_mode_change': '5G service mode changed',
    radio_context_change: 'Radio context changed',
    first_seen: 'First seen'
  }};

  return labels[e.event_type] || e.event_type || '';
}}

function cellularEventDeltaText(e) {{
  const eventType = String(e.event_type || '');

  if (eventType === 'service_type_change' || eventType === '5g_service_mode_change') {{
    const oldVal = e.old_service_type || 'n/a';
    const newVal = e.new_service_type || 'n/a';
    return oldVal + ' → ' + newVal;
  }}

  if (eventType === 'cell_id_change') {{
    return shortCell(e.old_cell_id) + ' → ' + shortCell(e.new_cell_id);
  }}

  if (eventType === 'tac_change') {{
    return 'TAC ' + (e.old_tac || 'n/a') + ' → ' + (e.new_tac || 'n/a');
  }}

  if (eventType === 'tac_and_cell_change') {{
    return 'TAC ' + (e.old_tac || 'n/a') + ' / ' + shortCell(e.old_cell_id)
      + ' → TAC ' + (e.new_tac || 'n/a') + ' / ' + shortCell(e.new_cell_id);
  }}

  if (eventType === 'radio_context_change' && !isFirstRadioContextCapture(e)) {{
    return radioContextText('old', e) + ' → ' + radioContextText('new', e);
  }}

  return '';
}}

function cellularEventCell(e) {{
  const delta = cellularEventDeltaText(e);
  return `
    <span class="pill">${{escapeHtml(friendlyCellularEventType(e))}}</span>
    ${{delta ? `<div class="small" style="margin-top:5px;color:#bfdbfe;">${{escapeHtml(delta)}}</div>` : ''}}
  `;
}}

function radioContextButton(e) {{
  const oldTextRaw = radioContextText('old', e);
  const newText = radioContextText('new', e);

  const oldText = oldTextRaw === 'n/a'
    ? 'Not previously captured'
    : oldTextRaw;

  const btnLabel = isFirstRadioContextCapture(e)
    ? 'Radio context'
    : 'Radio context';

  return `
    <div class="radio-context-pop">
      <button class="radio-context-btn" type="button" title="Hover for radio context">${{escapeHtml(btnLabel)}}</button>
      <div class="radio-context-tip">
        <div><b>Previous context</b></div>
        <div class="muted">${{escapeHtml(oldText)}}</div>
        <div style="height:8px"></div>
        <div><b>Current context</b></div>
        <div class="muted">${{escapeHtml(newText)}}</div>
      </div>
    </div>
  `;
}}

function renderCellularMobilityCard(cellular) {{
  if (!cellular) {{
    return `
      <div class="card">
        <h2>Cellular Mobility</h2>
        <p class="small">No cellular mobility data loaded.</p>
      </div>
    `;
  }}

  const current = cellular.current || [];
  const currentText = current.length
    ? current.map(c => `
        <div class="pill">
          ${{escapeHtml(c.service_type || 'Service n/a')}} ·
          MCC ${{escapeHtml(c.mcc || 'n/a')}} /
          MNC ${{escapeHtml(c.mnc || 'n/a')}} /
          TAC ${{escapeHtml(c.tac || 'n/a')}} /
          Cell ${{escapeHtml(shortCell(c.cell_id))}}
        </div>
      `).join('')
    : '<span class="small">No current cellular identity baseline stored yet.</span>';

  const timeline = cellular.timeline || [];
  const maxCount = Math.max(1, ...timeline.map(x => Number(x.count || 0)));

  const bars = timeline.length ? timeline.map(x => {{
    const count = Number(x.count || 0);
    const height = Math.max(4, Math.round((count / maxCount) * 100));
    const date = new Date(x.bucket_utc);
    const label = Number.isNaN(date.getTime())
      ? String(x.bucket_utc || '')
      : date.toLocaleString([], {{month:'short', day:'numeric', hour:'numeric'}});
    return `
      <div class="cellular-bar-wrap" title="${{escapeHtml(label)}} — ${{count}} change event(s)">
        <div class="cellular-bar ${{count ? '' : 'empty'}}" style="height:${{height}}%"></div>
        <div class="cellular-bar-label">${{escapeHtml(label)}}</div>
      </div>
    `;
  }}).join('') : `
    <div class="small" style="padding:18px;color:#94a3b8;">
      No tower/cell change events in this window.
    </div>
  `;

  const allChangeEvents = (cellular.recent_events || [])
    .filter(e => e.event_type && e.event_type !== 'first_seen');

  const changeEvents = allChangeEvents.slice(0, 10);

  function cellularEventAgeHours(e) {{
    const ts = new Date(e.detected_at || '');
    if (Number.isNaN(ts.getTime())) return null;
    return (Date.now() - ts.getTime()) / 3600000;
  }}

  function isTowerMobilityEvent(e) {{
    return ['cell_id_change', 'tac_change', 'tac_and_cell_change', 'carrier_change'].includes(String(e.event_type || ''));
  }}

  function isRadioBandEvent(e) {{
    return String(e.event_type || '') === 'radio_context_change'
      || String(e.event_type || '') === 'service_type_change'
      || String(e.event_type || '') === '5g_service_mode_change';
  }}

  function summarizeCellularEvents(hours) {{
    const scoped = allChangeEvents.filter(e => {{
      const age = cellularEventAgeHours(e);
      return age !== null && age >= 0 && age <= hours;
    }});

    return {{
      total: scoped.length,
      tower: scoped.filter(isTowerMobilityEvent).length,
      radio: scoped.filter(isRadioBandEvent).length
    }};
  }}

  function cellularSummaryCard(label, summary) {{
    return `
      <div class="cellular-kpi">
        <div class="big">${{Number(summary.total || 0)}}</div>
        <div class="label">${{escapeHtml(label)}}</div>
        <div class="small" style="margin-top:6px;color:#94a3b8;">
          ${{Number(summary.tower || 0)}} tower/cell · ${{Number(summary.radio || 0)}} radio/band
        </div>
      </div>
    `;
  }}

  const summary1h = summarizeCellularEvents(1);
  const summary24h = summarizeCellularEvents(24);
  const summary7d = {{
    total: Number(cellular.changes_7d || 0),
    tower: allChangeEvents.filter(e => {{
      const age = cellularEventAgeHours(e);
      return age !== null && age >= 0 && age <= 168 && isTowerMobilityEvent(e);
    }}).length,
    radio: allChangeEvents.filter(e => {{
      const age = cellularEventAgeHours(e);
      return age !== null && age >= 0 && age <= 168 && isRadioBandEvent(e);
    }}).length
  }};

  const eventRows = changeEvents.length ? changeEvents.map(e => `
    <tr>
      <td>${{escapeHtml(formatCellularTime(e.detected_at))}}</td>
      <td>${{cellularEventCell(e)}}</td>
      <td>
        <div class="small">TAC ${{escapeHtml(e.old_tac || 'n/a')}}</div>
        <div>${{escapeHtml(shortCell(e.old_cell_id))}}</div>
      </td>
      <td>
        <div class="small">TAC ${{escapeHtml(e.new_tac || 'n/a')}}</div>
        <div>${{escapeHtml(shortCell(e.new_cell_id))}}</div>
      </td>
      <td>${{radioContextButton(e)}}</td>
      <td>
        <div class="small">RSRP ${{escapeHtml(e.rsrp ?? 'n/a')}}</div>
        <div class="small">RSRQ ${{escapeHtml(e.rsrq ?? 'n/a')}}</div>
        <div class="small">SINR ${{escapeHtml(e.sinr ?? 'n/a')}}</div>
      </td>
    </tr>
  `).join('') : `
    <tr>
      <td colspan="6" class="small">No cell/tower or radio-context changes recorded yet. Baseline monitoring is active.</td>
    </tr>
  `;

  const eventDetailsLabel = changeEvents.length
    ? `Show latest ${{changeEvents.length}} event detail${{changeEvents.length === 1 ? '' : 's'}}`
    : 'Show event details';


  return `
    <div class="card">
      <h2>Cellular Mobility</h2>
      <p class="small">
        Tracks changes in cellular identity for this router using MCC, MNC, TAC, Cell ID, service type, and radio context when available.
      </p>

      <div class="cellular-kpi-row">
        <div class="cellular-kpi">
          <div class="big">${{Number(cellular.changes_24h || 0)}}</div>
          <div class="label">Changes last 24h</div>
        </div>
        <div class="cellular-kpi">
          <div class="big">${{Number(cellular.changes_7d || 0)}}</div>
          <div class="label">Changes last 7d</div>
        </div>
        <div class="cellular-kpi">
          <div class="big">${{current.length}}</div>
          <div class="label">Tracked modem(s)</div>
        </div>
      </div>

      <h3>Current serving cell</h3>
      <div>${{currentText}}</div>

      <h3 style="margin-top:16px;">Recent cell/tower changes</h3>
      <p class="small">
        Summary view keeps noisy mobility bursts from taking over the page. Expand details when you need the raw event list.
      </p>

      <div class="cellular-kpi-row">
        ${{cellularSummaryCard('Last 1 hour', summary1h)}}
        ${{cellularSummaryCard('Last 24 hours', summary24h)}}
        ${{cellularSummaryCard('Last 7 days', summary7d)}}
      </div>

      <details style="margin-top:12px;">
        <summary style="cursor:pointer;color:#bfdbfe;font-weight:700;">
          ${{escapeHtml(eventDetailsLabel)}}
        </summary>
        <p class="small" style="margin-top:8px;">
          Showing the latest ${{changeEvents.length}} non-baseline event${{changeEvents.length === 1 ? '' : 's'}}. 5G service mode transitions may also be plotted on the signal health chart below.
        </p>
        <table class="cellular-event-table">
          <thead>
            <tr>
              <th>Detected</th>
              <th>Event</th>
              <th>Previous serving cell</th>
              <th>New serving cell</th>
              <th>Radio context</th>
              <th>Signal</th>
            </tr>
          </thead>
          <tbody>${{eventRows}}</tbody>
        </table>
      </details>
    </div>
  `;
}}


function graphRangeParams() {{
  const params = new URLSearchParams();
  const mode = window.graphRangeMode || '30';

  if (mode === 'custom') {{
    if (window.graphStartDate) params.set('start_date', window.graphStartDate);
    if (window.graphEndDate) params.set('end_date', window.graphEndDate);
  }} else {{
    params.set('days', mode);
  }}

  return params;
}}

function applyGraphRange() {{
  const select = document.getElementById('graphRangeSelect');
  const status = document.getElementById('graphRangeStatus');
  const mode = select ? select.value : '30';

  if (mode === 'custom') {{
    const startEl = document.getElementById('graphStartDate');
    const endEl = document.getElementById('graphEndDate');
    const start = startEl ? startEl.value : '';
    const end = endEl ? endEl.value : '';

    if (!start || !end) {{
      if (status) status.textContent = 'Choose a start and end date.';
      return;
    }}

    const startDate = new Date(start + 'T00:00:00Z');
    const endDate = new Date(end + 'T00:00:00Z');
    const diffDays = Math.floor((endDate - startDate) / 86400000) + 1;

    if (Number.isNaN(diffDays) || diffDays < 1) {{
      if (status) status.textContent = 'End date must be on or after start date.';
      return;
    }}

    if (diffDays > 90) {{
      if (status) status.textContent = 'Custom range cannot exceed 90 days.';
      return;
    }}

    window.graphRangeMode = 'custom';
    window.graphStartDate = start;
    window.graphEndDate = end;
  }} else {{
    window.graphRangeMode = mode;
    window.graphStartDate = null;
    window.graphEndDate = null;
  }}

  if (status) status.textContent = '';
  loadRouter();
}}

function updateGraphRangeControls() {{
  const select = document.getElementById('graphRangeSelect');
  const customWrap = document.getElementById('graphCustomRangeInputs');
  const startEl = document.getElementById('graphStartDate');
  const endEl = document.getElementById('graphEndDate');

  if (!select) return;

  const mode = window.graphRangeMode || '30';
  select.value = mode;

  if (customWrap) {{
    customWrap.style.display = mode === 'custom' ? 'inline-flex' : 'none';
  }}

  if (startEl && window.graphStartDate) startEl.value = window.graphStartDate;
  if (endEl && window.graphEndDate) endEl.value = window.graphEndDate;

  if (!select.dataset.bound) {{
    select.dataset.bound = '1';
    select.addEventListener('change', () => {{
      if (customWrap) customWrap.style.display = select.value === 'custom' ? 'inline-flex' : 'none';
    }});
  }}
}}

function graphRangeLabel(data) {{
  if (data && data.range_mode === 'custom') {{
    return 'Custom Range';
  }}
  const days = data && data.selected_days ? Number(data.selected_days) : Number(window.graphRangeMode || 30);
  return days + '-Day';
}}

function defaultChartRanges() {{
  return {{
    signal: {{ mode: '30', startDate: null, endDate: null }},
    usage: {{ mode: '30', startDate: null, endDate: null }},
    alert: {{ mode: '30', startDate: null, endDate: null }}
  }};
}}

function ensureChartRanges() {{
  window.chartRanges = window.chartRanges || defaultChartRanges();
  ['signal', 'usage', 'alert'].forEach(kind => {{
    window.chartRanges[kind] = window.chartRanges[kind] || {{ mode: '30', startDate: null, endDate: null }};
  }});
}}

function chartRangeParams(kind) {{
  ensureChartRanges();
  const state = window.chartRanges[kind] || {{ mode: '30' }};
  const params = new URLSearchParams();

  if (state.mode === 'custom') {{
    if (state.startDate) params.set('start_date', state.startDate);
    if (state.endDate) params.set('end_date', state.endDate);
  }} else {{
    params.set('days', state.mode || '30');
  }}

  return params;
}}

function selectedDaysFromChartState(kind, data) {{
  ensureChartRanges();
  if (data && data.selected_days) return Number(data.selected_days);

  const state = window.chartRanges[kind] || {{ mode: '30' }};
  if (state.mode !== 'custom') return Number(state.mode || 30);

  if (state.startDate && state.endDate) {{
    const start = new Date(state.startDate + 'T00:00:00Z');
    const end = new Date(state.endDate + 'T00:00:00Z');
    const diffDays = Math.floor((end - start) / 86400000) + 1;
    if (!Number.isNaN(diffDays) && diffDays > 0 && diffDays <= 90) return diffDays;
  }}

  return 30;
}}

function chartRangeLabel(kind, data) {{
  ensureChartRanges();
  const state = window.chartRanges[kind] || {{ mode: '30' }};

  if (state.mode === 'custom' || (data && data.range_mode === 'custom')) {{
    return 'Custom Range';
  }}

  const days = data && data.selected_days ? Number(data.selected_days) : Number(state.mode || 30);
  return days + '-Day';
}}

function updateSingleChartRangeControls(kind) {{
  ensureChartRanges();

  const state = window.chartRanges[kind] || {{ mode: '30', startDate: null, endDate: null }};
  const select = document.getElementById(kind + 'RangeSelect');
  const customWrap = document.getElementById(kind + 'CustomRangeInputs');
  const startEl = document.getElementById(kind + 'StartDate');
  const endEl = document.getElementById(kind + 'EndDate');

  if (!select) return;

  select.value = state.mode || '30';

  if (customWrap) {{
    customWrap.style.display = state.mode === 'custom' ? 'inline-flex' : 'none';
  }}

  if (startEl && state.startDate) startEl.value = state.startDate;
  if (endEl && state.endDate) endEl.value = state.endDate;

  if (!select.dataset.bound) {{
    select.dataset.bound = '1';
    select.addEventListener('change', () => {{
      if (customWrap) customWrap.style.display = select.value === 'custom' ? 'inline-flex' : 'none';
    }});
  }}

  updateChartZoomResetControl(kind);
}}

function updateAllChartRangeControls() {{
  updateSingleChartRangeControls('signal');
  updateSingleChartRangeControls('usage');
  updateSingleChartRangeControls('alert');
}}

async function fetchRouterDetailForChart(kind, options = {{}}) {{
  const pid = activeProfileId();
  const params = chartRangeParams(kind);
  params.set('profile_id', pid);

  if (options.cacheOnly) {{
    params.set('cache_only', '1');
  }}

  const res = await fetch('/router/{router_id}/detail?' + params.toString());
  if (!res.ok) {{
    throw new Error('Router detail failed: HTTP ' + res.status);
  }}
  return await res.json();
}}

async function fetchCellularEventsForChart(kind, selectedDays) {{
  try {{
    const pid = activeProfileId();
    const hours = Math.max(24, Math.min(2160, Number(selectedDays || 30) * 24));
    const cellRes = await fetch('/api/cellular/router/{router_id}/summary?profile_id=' + encodeURIComponent(pid) + '&hours=' + encodeURIComponent(hours), {{cache:'no-store'}});
    if (cellRes.ok) return await cellRes.json();
  }} catch (e) {{
    return null;
  }}
  return null;
}}

function applyRangeStateFromControls(kind) {{
  ensureChartRanges();

  const select = document.getElementById(kind + 'RangeSelect');
  const status = document.getElementById(kind + 'RangeStatus');
  const mode = select ? select.value : '30';

  if (mode === 'custom') {{
    const startEl = document.getElementById(kind + 'StartDate');
    const endEl = document.getElementById(kind + 'EndDate');
    const start = startEl ? startEl.value : '';
    const end = endEl ? endEl.value : '';

    if (!start || !end) {{
      if (status) status.textContent = 'Choose a start and end date.';
      return false;
    }}

    const startDate = new Date(start + 'T00:00:00Z');
    const endDate = new Date(end + 'T00:00:00Z');
    const diffDays = Math.floor((endDate - startDate) / 86400000) + 1;

    if (Number.isNaN(diffDays) || diffDays < 1) {{
      if (status) status.textContent = 'End date must be on or after start date.';
      return false;
    }}

    if (diffDays > 90) {{
      if (status) status.textContent = 'Custom range cannot exceed 90 days.';
      return false;
    }}

    window.chartRanges[kind] = {{ mode: 'custom', startDate: start, endDate: end }};
  }} else {{
    window.chartRanges[kind] = {{ mode, startDate: null, endDate: null }};
  }}

  if (status) status.textContent = '';
  return true;
}}


function chartRangeStateCopy(kind) {{
  ensureChartRanges();
  const state = window.chartRanges[kind] || {{ mode: '30', startDate: null, endDate: null }};
  return {{
    mode: state.mode || '30',
    startDate: state.startDate || null,
    endDate: state.endDate || null
  }};
}}

function setChartRangeControlsFromState(kind, state) {{
  const select = document.getElementById(kind + 'RangeSelect');
  const customWrap = document.getElementById(kind + 'CustomRangeInputs');
  const startEl = document.getElementById(kind + 'StartDate');
  const endEl = document.getElementById(kind + 'EndDate');

  if (select) select.value = state.mode || '30';

  if (customWrap) {{
    customWrap.style.display = state.mode === 'custom' ? 'inline-flex' : 'none';
  }}

  if (startEl) startEl.value = state.startDate || '';
  if (endEl) endEl.value = state.endDate || '';
}}

function updateChartZoomResetControl(kind) {{
  const btn = document.getElementById(kind + 'ResetZoomButton');
  if (!btn) return;

  window.chartZoomOriginals = window.chartZoomOriginals || {{}};
  btn.style.display = window.chartZoomOriginals[kind] ? 'inline-flex' : 'none';
}}

async function applyChartDragZoom(kind, startDate, endDate) {{
  ensureChartRanges();

  if (!startDate || !endDate) return;

  const start = String(startDate).slice(0, 10);
  const end = String(endDate).slice(0, 10);

  const startObj = new Date(start + 'T00:00:00Z');
  const endObj = new Date(end + 'T00:00:00Z');
  const diffDays = Math.floor((endObj - startObj) / 86400000) + 1;

  const status = document.getElementById(kind + 'RangeStatus');

  if (Number.isNaN(diffDays) || diffDays < 1) {{
    if (status) status.textContent = 'Drag zoom selection was not valid.';
    return;
  }}

  if (diffDays > 90) {{
    if (status) status.textContent = 'Drag zoom range cannot exceed 90 days.';
    return;
  }}

  window.chartZoomOriginals = window.chartZoomOriginals || {{}};

  if (!window.chartZoomOriginals[kind]) {{
    window.chartZoomOriginals[kind] = normalizeChartRangeState(
      chartRangeStateCopy(kind) || getSavedChartRangePreference(kind) || {{ mode: '30', startDate: null, endDate: null }}
    );
  }}

  window.chartRanges[kind] = {{
    mode: 'custom',
    startDate: start,
    endDate: end
  }};

  setChartRangeControlsFromState(kind, window.chartRanges[kind]);
  updateChartZoomResetControl(kind);

  if (status) status.textContent = 'Zooming to ' + start + ' to ' + end + '...';

  await applyChartRange(kind);

  if (status) status.textContent = 'Zoomed: ' + start + ' to ' + end;
}}


function chartRangeStorageKey() {{
  const profileId = typeof getRouterPageProfileId === 'function'
    ? getRouterPageProfileId()
    : (typeof activeProfileId === 'function' ? activeProfileId() : '1');

  return `ncm-monitor:router-chart-ranges:{router_id}:profile:${{profileId || '1'}}`;
}}

function getSavedChartRangePreference(kind) {{
  try {{
    const raw = localStorage.getItem(chartRangeStorageKey());
    const saved = raw ? JSON.parse(raw) : {{}};
    const state = saved && saved[kind] ? saved[kind] : null;

    if (state && state.mode) {{
      return {{
        mode: String(state.mode || '30'),
        startDate: state.startDate || null,
        endDate: state.endDate || null
      }};
    }}
  }} catch (e) {{
    console.warn('Unable to read saved chart range preference:', e);
  }}

  return null;
}}

function saveChartRangePreference(kind, state) {{
  try {{
    const key = chartRangeStorageKey();
    const raw = localStorage.getItem(key);
    const saved = raw ? JSON.parse(raw) : {{}};

    saved[kind] = {{
      mode: state.mode || '30',
      startDate: state.mode === 'custom' ? (state.startDate || null) : null,
      endDate: state.mode === 'custom' ? (state.endDate || null) : null
    }};

    localStorage.setItem(key, JSON.stringify(saved));
  }} catch (e) {{
    console.warn('Unable to save chart range preference:', e);
  }}
}}

function normalizeChartRangeState(state) {{
  if (!state || !state.mode) {{
    return {{ mode: '30', startDate: null, endDate: null }};
  }}

  const mode = String(state.mode || '30');

  if (mode === 'custom') {{
    if (state.startDate && state.endDate) {{
      return {{
        mode: 'custom',
        startDate: String(state.startDate).slice(0, 10),
        endDate: String(state.endDate).slice(0, 10)
      }};
    }}

    return {{ mode: '30', startDate: null, endDate: null }};
  }}

  return {{ mode, startDate: null, endDate: null }};
}}

function fallbackChartResetState(kind) {{
  return normalizeChartRangeState(
    getSavedChartRangePreference(kind) || {{ mode: '30', startDate: null, endDate: null }}
  );
}}

async function resetChartZoom(kind) {{
  ensureChartRanges();

  window.chartZoomOriginals = window.chartZoomOriginals || {{}};

  const btn = document.getElementById(kind + 'ResetZoomButton');
  const status = document.getElementById(kind + 'RangeStatus');

  const original = normalizeChartRangeState(
    window.chartZoomOriginals[kind] || fallbackChartResetState(kind)
  );

  window.chartRanges[kind] = original;
  setChartRangeControlsFromState(kind, original);

  if (btn) {{
    btn.disabled = true;
    btn.dataset.originalText = btn.dataset.originalText || btn.textContent || 'Reset zoom';
    btn.textContent = 'Resetting...';
  }}

  if (status) status.textContent = 'Resetting zoom...';

  try {{
    await applyChartRange(kind, {{ cacheOnly: true }});

    saveChartRangePreference(kind, original);
    delete window.chartZoomOriginals[kind];

    updateChartZoomResetControl(kind);

    if (btn) {{
      btn.disabled = false;
      btn.textContent = 'Reset ✓';
      window.setTimeout(() => {{
        btn.textContent = btn.dataset.originalText || 'Reset zoom';
      }}, 1200);
    }}

    if (status) {{
      status.textContent = original.mode === 'custom'
        ? 'Reset: ' + (original.startDate || '') + ' to ' + (original.endDate || '')
        : '';
    }}
  }} catch (e) {{
    console.error('Reset chart zoom failed:', e);

    if (btn) {{
      btn.disabled = false;
      btn.textContent = btn.dataset.originalText || 'Reset zoom';
    }}

    if (status) status.textContent = 'Reset zoom failed.';
  }}
}}

function chartDragZoomLabelIndex(chart, pixelX) {{
  const labels = chart?.data?.labels || [];
  const xScale = chart?.scales?.x;

  if (!labels.length || !xScale || typeof xScale.getValueForPixel !== 'function') return null;

  let raw = xScale.getValueForPixel(pixelX);
  let idx = null;

  if (typeof raw === 'number') {{
    idx = Math.round(raw);
  }} else if (raw !== null && raw !== undefined) {{
    idx = labels.indexOf(String(raw));
  }}

  if (idx === null || Number.isNaN(idx)) return null;
  return Math.max(0, Math.min(labels.length - 1, idx));
}}

const chartDragZoomPlugin = {{
  id: 'chartDragZoom',

  afterEvent(chart, args, pluginOptions) {{
    const opts = chart?.options?.plugins?.chartDragZoom || {{}};
    if (!opts.enabled || !opts.kind) return;

    const e = args.event;
    const area = chart.chartArea;
    if (!e || !area) return;

    const state = chart.$dragZoom || {{
      dragging: false,
      startX: null,
      currentX: null,
      suppressClick: false
    }};

    chart.$dragZoom = state;

    const insideX = e.x >= area.left && e.x <= area.right;
    const insideY = e.y >= area.top && e.y <= area.bottom;

    if (e.type === 'mousedown' && insideX && insideY) {{
      state.dragging = true;
      state.startX = e.x;
      state.currentX = e.x;
      state.suppressClick = false;
      args.changed = true;
      return;
    }}

    if (e.type === 'mousemove' && state.dragging) {{
      state.currentX = Math.max(area.left, Math.min(area.right, e.x));
      args.changed = true;
      return;
    }}

    if ((e.type === 'mouseup' || e.type === 'mouseout') && state.dragging) {{
      const startX = state.startX;
      const endX = Math.max(area.left, Math.min(area.right, state.currentX ?? e.x));
      const distance = Math.abs(endX - startX);

      state.dragging = false;
      state.currentX = null;

      if (distance < 10) {{
        args.changed = true;
        return;
      }}

      const leftX = Math.min(startX, endX);
      const rightX = Math.max(startX, endX);
      const startIdx = chartDragZoomLabelIndex(chart, leftX);
      const endIdx = chartDragZoomLabelIndex(chart, rightX);
      const labels = chart?.data?.labels || [];

      if (startIdx === null || endIdx === null || !labels[startIdx] || !labels[endIdx]) {{
        args.changed = true;
        return;
      }}

      const startDate = String(labels[Math.min(startIdx, endIdx)]).slice(0, 10);
      const endDate = String(labels[Math.max(startIdx, endIdx)]).slice(0, 10);

      if (!startDate || !endDate || startDate === endDate) {{
        const status = document.getElementById(opts.kind + 'RangeStatus');
        if (status) status.textContent = 'Drag across at least two date ticks to zoom.';
        args.changed = true;
        return;
      }}

      state.suppressClick = true;
      args.changed = true;

      window.setTimeout(() => {{
        applyChartDragZoom(opts.kind, startDate, endDate).catch(err => {{
          console.error('Chart drag zoom failed:', err);
          const status = document.getElementById(opts.kind + 'RangeStatus');
          if (status) status.textContent = 'Drag zoom failed.';
        }});
      }}, 0);

      return;
    }}
  }},

  afterDraw(chart, args, pluginOptions) {{
    const opts = chart?.options?.plugins?.chartDragZoom || {{}};
    if (!opts.enabled) return;

    const state = chart.$dragZoom;
    const area = chart.chartArea;

    if (!state || !state.dragging || state.startX === null || state.currentX === null || !area) return;

    const ctx = chart.ctx;
    const left = Math.max(area.left, Math.min(state.startX, state.currentX));
    const right = Math.min(area.right, Math.max(state.startX, state.currentX));

    ctx.save();
    ctx.fillStyle = 'rgba(56,189,248,0.18)';
    ctx.strokeStyle = 'rgba(125,211,252,0.85)';
    ctx.lineWidth = 1;
    ctx.fillRect(left, area.top, Math.max(1, right - left), area.bottom - area.top);
    ctx.strokeRect(left, area.top, Math.max(1, right - left), area.bottom - area.top);
    ctx.restore();
  }}
}};

if (window.Chart && !window.__chartDragZoomPluginRegistered) {{
  Chart.register(chartDragZoomPlugin);
  window.__chartDragZoomPluginRegistered = true;
}}


function applyButtonSetState(btn, state, text) {{
  if (!btn) return;

  if (!btn.dataset.originalText) {{
    btn.dataset.originalText = btn.textContent || 'Apply';
  }}

  btn.classList.remove('apply-loading', 'apply-success', 'apply-error');

  if (!document.getElementById('applyButtonStateStyles')) {{
    const style = document.createElement('style');
    style.id = 'applyButtonStateStyles';
    style.textContent = `
      @keyframes applyButtonPulse {{
        0% {{ box-shadow:0 0 0 0 rgba(56,189,248,.45); }}
        70% {{ box-shadow:0 0 0 8px rgba(56,189,248,0); }}
        100% {{ box-shadow:0 0 0 0 rgba(56,189,248,0); }}
      }}
      button.apply-loading {{
        cursor:wait !important;
        opacity:.95;
        background:linear-gradient(135deg,#0ea5e9,#2563eb) !important;
        color:white !important;
        border-color:rgba(125,211,252,.8) !important;
        animation:applyButtonPulse 1.1s infinite;
      }}
      button.apply-success {{
        background:linear-gradient(135deg,#16a34a,#22c55e) !important;
        color:white !important;
        border-color:rgba(134,239,172,.85) !important;
      }}
      button.apply-error {{
        background:linear-gradient(135deg,#dc2626,#ef4444) !important;
        color:white !important;
        border-color:rgba(252,165,165,.85) !important;
      }}
    `;
    document.head.appendChild(style);
  }}

  if (state === 'loading') {{
    btn.disabled = true;
    btn.textContent = text || 'Loading...';
    btn.classList.add('apply-loading');
    return;
  }}

  if (state === 'success') {{
    btn.disabled = false;
    btn.textContent = text || 'Loaded ✓';
    btn.classList.add('apply-success');
    window.setTimeout(() => {{
      btn.classList.remove('apply-success');
      btn.textContent = btn.dataset.originalText || 'Apply';
    }}, 1400);
    return;
  }}

  if (state === 'error') {{
    btn.disabled = false;
    btn.textContent = text || 'Failed';
    btn.classList.add('apply-error');
    window.setTimeout(() => {{
      btn.classList.remove('apply-error');
      btn.textContent = btn.dataset.originalText || 'Apply';
    }}, 2200);
    return;
  }}

  btn.disabled = false;
  btn.textContent = btn.dataset.originalText || 'Apply';
}}

async function applyChartRangeButton(kind, btn) {{
  applyButtonSetState(btn, 'loading', 'Loading...');

  try {{
    const select = document.getElementById(kind + 'RangeSelect');
    const startEl = document.getElementById(kind + 'StartDate');
    const endEl = document.getElementById(kind + 'EndDate');
    const mode = select ? String(select.value || '30') : '30';

    const profileId = typeof getRouterPageProfileId === 'function'
      ? getRouterPageProfileId()
      : '1';

    const storageKey = `ncm-monitor:router-chart-ranges:{router_id}:profile:${{profileId || '1'}}`;
    const existingRaw = localStorage.getItem(storageKey);
    const existing = existingRaw ? JSON.parse(existingRaw) : {{}};

    existing[kind] = {{
      mode,
      startDate: mode === 'custom' && startEl ? (startEl.value || null) : null,
      endDate: mode === 'custom' && endEl ? (endEl.value || null) : null
    }};

    localStorage.setItem(storageKey, JSON.stringify(existing));
    console.log('Saved chart range preference:', storageKey, existing);

    await applyChartRange(kind);

    const status = document.getElementById(kind + 'RangeStatus');
    const statusText = status ? String(status.textContent || '') : '';

    if (statusText && !statusText.includes('Loading range') && (
      statusText.includes('failed') ||
      statusText.includes('Failed') ||
      statusText.includes('HTTP') ||
      statusText.includes('Error') ||
      statusText.includes('Choose a start') ||
      statusText.includes('End date')
    )) {{
      applyButtonSetState(btn, 'error', 'Failed');
      return;
    }}

    applyButtonSetState(btn, 'success', 'Loaded ✓');
  }} catch (e) {{
    applyButtonSetState(btn, 'error', 'Failed');
    throw e;
  }}
}}

async function applyChartRange(kind, options = {{}}) {{
  if (!applyRangeStateFromControls(kind)) return;

  const status = document.getElementById(kind + 'RangeStatus');

  try {{
    const data = await fetchRouterDetailForChart(kind, options);
    const selectedDays = selectedDaysFromChartState(kind, data);
    const state = window.chartRanges[kind] || {{ mode: '30' }};
    const startDate = data.custom_start_date || state.startDate || null;
    const endDate = data.custom_end_date || state.endDate || null;
    const label = chartRangeLabel(kind, data);

    if (kind === 'signal') {{
      const cellular = await fetchCellularEventsForChart(kind, selectedDays);
      window.currentSignalRows = data.daily_signal || [];
      window.currentSignalEvents = cellular?.recent_events || [];
      window.currentSignalSelectedDays = selectedDays;
      window.currentSignalStartDate = startDate;
      window.currentSignalEndDate = endDate;

      const title = document.getElementById('signalChartTitle');
      if (title) title.textContent = label + ' Signal Health — SINR, RSRQ, and Cell Changes';

      renderSignalChart(window.currentSignalRows, window.currentSignalEvents, selectedDays, startDate, endDate);
    }}

    if (kind === 'usage') {{
      window.currentUsageRows = data.daily_usage || [];
      window.currentUsageNcmRows = data.daily_ncm_usage || [];
      window.currentUsageSelectedDays = selectedDays;
      window.currentUsageStartDate = startDate;
      window.currentUsageEndDate = endDate;

      const title = document.getElementById('usageChartTitle');
      if (title) title.textContent = label + ' Data Usage';

      renderUsageChart(
        window.currentUsageRows,
        window.currentUsageNcmRows,
        selectedDays,
        document.getElementById('showNcmTrafficToggle')?.checked,
        startDate,
        endDate
      );
    }}

    if (kind === 'alert') {{
      window.currentAlertRows = data.daily_alerts || [];
      window.currentAlertSelectedDays = selectedDays;
      window.currentAlertStartDate = startDate;
      window.currentAlertEndDate = endDate;

      const title = document.getElementById('alertChartTitle');
      if (title) title.textContent = label + ' Alert Timeline';

      renderAlertChart(window.currentAlertRows, selectedDays, startDate, endDate);
    }}

    updateSingleChartRangeControls(kind);

    if (status) {{
      status.textContent = data.range_mode === 'custom'
        ? ((data.custom_start_date || '') + ' to ' + (data.custom_end_date || ''))
        : '';
    }}
  }} catch (e) {{
    if (status) status.textContent = String(e.message || e);
  }}
}}


async function restoreSavedChartRangePreferences() {{
  try {{
    const profileId = typeof getRouterPageProfileId === 'function'
      ? getRouterPageProfileId()
      : '1';

    const storageKey = `ncm-monitor:router-chart-ranges:{router_id}:profile:${{profileId || '1'}}`;
    const raw = localStorage.getItem(storageKey);

    if (!raw) {{
      console.log('No saved chart range preference found:', storageKey);
      return;
    }}

    const saved = JSON.parse(raw);
    if (!saved || typeof saved !== 'object') return;

    console.log('Restoring saved chart range preference:', storageKey, saved);

    ensureChartRanges();

    for (const kind of ['signal', 'usage', 'alert']) {{
      const state = saved[kind];
      if (!state) continue;

      const mode = String(state.mode || '30');
      const startDate = state.startDate || null;
      const endDate = state.endDate || null;

      window.chartRanges[kind] = {{ mode, startDate, endDate }};

      const select = document.getElementById(kind + 'RangeSelect');
      const startEl = document.getElementById(kind + 'StartDate');
      const endEl = document.getElementById(kind + 'EndDate');

      if (select) select.value = mode;
      if (startEl && startDate) startEl.value = startDate;
      if (endEl && endDate) endEl.value = endDate;
    }}

    updateAllChartRangeControls();

    for (const kind of ['signal', 'usage', 'alert']) {{
      const state = window.chartRanges && window.chartRanges[kind];
      if (!state) continue;

      const isDefault = String(state.mode || '30') === '30' && !state.startDate && !state.endDate;
      if (isDefault) continue;

      console.log('Auto-applying saved chart range preference:', kind, state);

      const restoreBtn = document.getElementById(kind + 'ApplyButton');
      const restoreStatus = document.getElementById(kind + 'RangeStatus');
      const restoreLabel = state.mode === 'custom'
        ? 'custom range'
        : `${{state.mode || '30'}} days`;

      if (restoreBtn) {{
        applyButtonSetState(restoreBtn, 'loading', `Restoring ${{restoreLabel}}...`);
      }}

      if (restoreStatus) {{
        restoreStatus.textContent = `Restoring saved ${{restoreLabel}} view...`;
      }}

      await applyChartRange(kind, {{ cacheOnly: true }});

      if (restoreBtn) {{
        applyButtonSetState(restoreBtn, 'success', 'Restored ✓');
      }}

      if (restoreStatus) {{
        restoreStatus.textContent = '';
      }}
    }}
  }} catch (e) {{
    console.warn('Could not restore saved chart range preference:', e);
  }}
}}


function routerModuleIntervalOptions(current) {{
  const values = ['', 5, 15, 30, 60, 240, 720, 1440];
  return values.map(v => {{
    const label = v === '' ? 'No interval' : String(v) + ' min';
    const selected = String(current ?? '') === String(v) ? 'selected' : '';
    return '<option value="' + v + '" ' + selected + '>' + label + '</option>';
  }}).join('');
}}

function routerModuleModeOptions(current) {{
  const modes = ['disabled', 'cached', 'discovery', 'passive', 'on_demand'];
  return modes.map(m => {{
    const selected = String(current || '') === m ? 'selected' : '';
    return '<option value="' + m + '" ' + selected + '>' + m.replace('_', ' ') + '</option>';
  }}).join('');
}}

function renderRouterMonitoringSettings(modules) {{
  modules = modules || {{}};
  const entries = Object.entries(modules);

  if (!entries.length) {{
    return `
      <div class="card">
        <h2>Monitoring Settings</h2>
        <p class="small">No monitoring module settings are available for this router yet.</p>
      </div>
    `;
  }}

  return `
    <div class="card">
      <h2>Monitoring Settings</h2>
      <p class="small">Adjust this router's monitoring intervals and collection modes. These settings override any pool defaults that were applied when the router was added or when pool defaults were last saved.</p>
      <div id="routerMonitoringSettings">
        ${{entries.map(([name, m]) => `
          <div style="border-top:1px solid #1f2937;padding:12px 0;">
            <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between;">
              <div>
                <b>${{m.label || name}}</b>
                <div class="small">Default: ${{m.default_mode || 'disabled'}}${{m.default_interval_minutes ? ' · ' + m.default_interval_minutes + ' min' : ''}}</div>
              </div>
              <label class="small" style="display:inline-flex;align-items:center;gap:8px;cursor:pointer;">
                <input id="routerModEnabled-${{name}}" type="checkbox" ${{m.enabled ? 'checked' : ''}} style="width:auto;margin:0;">
                Enabled
              </label>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px;">
              <div>
                <label class="small">Mode</label>
                <select id="routerModMode-${{name}}">${{routerModuleModeOptions(m.mode)}}</select>
              </div>
              <div>
                <label class="small">Interval</label>
                <select id="routerModInterval-${{name}}">${{routerModuleIntervalOptions(m.interval_minutes)}}</select>
              </div>
            </div>
          </div>
        `).join('')}}
      </div>
      <button class="primary" onclick="saveRouterMonitoringSettings()">Save Router Monitoring Settings</button>
      <span id="routerMonitoringStatus" class="small"></span>
    </div>
  `;
}}

async function saveRouterMonitoringSettings() {{
  const modules = routerData?.monitoring_modules || {{}};
  const payloadModules = {{}};

  Object.keys(modules).forEach(name => {{
    const enabledEl = document.getElementById('routerModEnabled-' + name);
    const modeEl = document.getElementById('routerModMode-' + name);
    const intervalEl = document.getElementById('routerModInterval-' + name);

    payloadModules[name] = {{
      enabled: enabledEl ? enabledEl.checked : false,
      mode: modeEl ? modeEl.value : 'disabled',
      interval_minutes: intervalEl && intervalEl.value ? Number(intervalEl.value) : null
    }};
  }});

  const status = document.getElementById('routerMonitoringStatus');
  if (status) status.textContent = 'Saving...';

  const res = await fetch('/monitoring-targets/modules', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{
      profile_id: activeProfileId(),
      router_id: '{router_id}',
      modules: payloadModules
    }})
  }});

  if (!res.ok) {{
    if (status) status.textContent = await res.text();
    return;
  }}

  if (status) status.textContent = 'Saved.';
  await loadRouter();
}}

function monitoringModule(name) {{
  return (routerData && routerData.monitoring_modules && routerData.monitoring_modules[name])
    ? routerData.monitoring_modules[name]
    : null;
}}

function graphModuleIntervalOptions(current) {{
  const values = ['', 5, 15, 30, 60, 240, 720, 1440];
  return values.map(v => {{
    const label = v === '' ? 'No interval' : String(v) + ' min';
    const selected = String(current ?? '') === String(v) ? 'selected' : '';
    return '<option value="' + v + '" ' + selected + '>' + label + '</option>';
  }}).join('');
}}

function graphModuleModeOptions(current) {{
  const modes = [
    ['disabled', 'Disabled — do not collect this data'],
    ['passive', 'Passive — collect automatically in the background'],
    ['on_demand', 'On demand — collect only when manually requested'],
    ['cached', 'Cached — use data captured during normal refresh/discovery'],
    ['discovery', 'Discovery — collect inventory or identity details only']
  ];

  return modes.map(([value, label]) => {{
    const selected = String(current || '') === value ? 'selected' : '';
    return '<option value="' + value + '" ' + selected + '>' + label + '</option>';
  }}).join('');
}}


function toggleGraphPollingDetails(moduleName) {{
  const panel = document.getElementById('graphModPanel-' + moduleName);
  const btn = document.getElementById('graphModToggle-' + moduleName);
  if (!panel) return;

  const isOpen = panel.style.display !== 'none';
  panel.style.display = isOpen ? 'none' : 'block';

  if (btn) {{
    const label = btn.getAttribute('title') || '↻ Modify polling details';
    btn.textContent = isOpen ? label : label.replace('Modify', 'Hide');
  }}
}}

function renderGraphModuleControl(moduleName, title, helpText) {{
  const m = monitoringModule(moduleName);
  if (!m) return '';

  const intervalText = m.interval_minutes ? String(m.interval_minutes) + ' min' : 'no interval';
  const modeText = String(m.mode || 'disabled').replace('_', ' ');
  const buttonLabel = title
    ? '↻ Modify ' + String(title).replace(/ polling$/i, '').replace(/ history$/i, '').toLowerCase() + ' polling details'
    : '↻ Modify polling details';

  return `
    <div style="margin:8px 0 12px 0;">
      <button
        id="graphModToggle-${{moduleName}}"
        onclick="toggleGraphPollingDetails('${{moduleName}}')"
        title="${{buttonLabel}}"
        style="background:rgba(15,23,42,.72);border:1px solid rgba(56,189,248,.35);color:#bae6fd;border-radius:999px;padding:7px 11px;font-size:12px;font-weight:800;"
      >${{buttonLabel}}</button>
      <span class="small" style="margin-left:8px;color:rgba(148,163,184,.85);">
        Current: ${{m.enabled ? modeText + ' · ' + intervalText : 'disabled'}}
      </span>

      <div
        id="graphModPanel-${{moduleName}}"
        style="display:none;margin-top:10px;padding:10px 12px;border:1px solid rgba(148,163,184,.22);border-radius:12px;background:rgba(15,23,42,.35);"
      >
        <div style="display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;">
          <div>
            <b>${{title}}</b>
            <div class="small">${{helpText || ''}}</div>
          </div>
          <label class="small" style="display:inline-flex;align-items:center;gap:8px;cursor:pointer;">
            <input id="graphModEnabled-${{moduleName}}" type="checkbox" ${{m.enabled ? 'checked' : ''}} style="width:auto;margin:0;">
            Enabled
          </label>
        </div>
        <div style="display:grid;grid-template-columns:1.4fr .8fr auto;gap:10px;align-items:end;margin-top:10px;">
          <div>
            <label class="small">Mode</label>
            <select id="graphModMode-${{moduleName}}">${{graphModuleModeOptions(m.mode)}}</select>
          </div>
          <div>
            <label class="small">Polling interval</label>
            <select id="graphModInterval-${{moduleName}}">${{graphModuleIntervalOptions(m.interval_minutes)}}</select>
          </div>
          <button onclick="saveGraphModuleSetting('${{moduleName}}')">Save</button>
        </div>
        <div class="small" style="margin-top:8px;color:rgba(148,163,184,.92);">
          Lower intervals provide fresher graph data but increase NCM API usage.
        </div>
        <div id="graphModStatus-${{moduleName}}" class="small"></div>
      </div>
    </div>
  `;
}}


async function saveGraphModuleSetting(moduleName) {{
  const enabledEl = document.getElementById('graphModEnabled-' + moduleName);
  const modeEl = document.getElementById('graphModMode-' + moduleName);
  const intervalEl = document.getElementById('graphModInterval-' + moduleName);
  const status = document.getElementById('graphModStatus-' + moduleName);

  if (status) status.textContent = 'Saving...';

  const payloadModules = {{}};
  payloadModules[moduleName] = {{
    enabled: enabledEl ? enabledEl.checked : false,
    mode: modeEl ? modeEl.value : 'disabled',
    interval_minutes: intervalEl && intervalEl.value ? Number(intervalEl.value) : null
  }};

  const res = await fetch('/monitoring-targets/modules', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{
      profile_id: activeProfileId(),
      router_id: '{router_id}',
      modules: payloadModules
    }})
  }});

  if (!res.ok) {{
    if (status) status.textContent = await res.text();
    return;
  }}

  if (status) status.textContent = 'Saved.';
  await loadRouter();
}}

async function loadRouter() {{
  const pid = activeProfileId();
  const params = graphRangeParams();
  params.set('profile_id', pid);
  const res = await fetch('/router/{router_id}/detail?' + params.toString());
  const data = await res.json();

  let cellular = null;
  try {{
    const cellRes = await fetch('/api/cellular/router/{router_id}/summary?profile_id=' + encodeURIComponent(pid) + '&hours=168', {{cache:'no-store'}});
    if (cellRes.ok) cellular = await cellRes.json();
  }} catch (e) {{
    cellular = null;
  }}

  routerData = data;
  const content = document.getElementById('content');

  const sims = (data.sims || []).map(s => `
    <div class="card">
      <h2>${{s.sim_label || 'SIM'}}</h2>
      <div class="pill">Carrier: ${{s.carrier || 'Unknown'}}</div>
      <div class="pill ${{s.connection_state === 'connected' ? 'ok' : 'small'}}">State: ${{s.connection_state || 'Unknown'}}</div>
      <div class="pill">Service: ${{s.service_type || 'Unknown'}}</div>
      <div class="pill">Uptime: ${{formatUptime(s.uptime)}}</div>
      <p class="small">Net Device ID: ${{s.id}}</p>
      <p class="small">Product: ${{s.mfg_product || ''}}</p>
      <p class="small">Current RSRP: <span class="${{signalClass('rsrp', s.rsrp)}}">${{s.rsrp ?? 'n/a'}}</span></p>
      <p class="small">Current RSRQ: <span class="${{signalClass('rsrq', s.rsrq)}}">${{s.rsrq ?? 'n/a'}}</span></p>
      <p class="small">Current SINR: <span class="${{signalClass('sinr', s.sinr)}}">${{s.sinr ?? 'n/a'}}</span></p>
      <p class="small">Cell context: MCC ${{s.mcc || 'n/a'}} / MNC ${{s.mnc || 'n/a'}} / TAC ${{s.tac || 'n/a'}} / Cell ${{s.cell_id || 'n/a'}}</p>
      <p class="small">Updated: ${{s.update_ts || s.updated_at || ''}}</p>
      <p class="small">Signal source: ${{s.signal_source || 'unavailable'}}</p>
    </div>
  `).join('');

  const issues = (data.issues || []).map(i => `
    <div class="card">
      <h3>${{i.severity.replace('_',' ')}}: ${{i.issue_type}}</h3>
      <p>${{i.summary || ''}}</p>
      <p class="small">Status: ${{i.status}} | First seen: ${{i.first_seen_local || ''}} | Last seen: ${{i.last_seen_local || ''}}</p>
      ${{i.status === 'open' ? `<button onclick="resolveIssue(${{i.id}}, false)">Resolve</button><button onclick="resolveIssue(${{i.id}}, true)">Resolve as Non-Incident</button>` : `<p class="small">Resolution: ${{i.resolution_note || ''}}</p>`}}
    </div>
  `).join('');

  const comments = (data.comments || []).map(c => `
    <div class="card">
      <p>${{c.comment}}</p>
      <p class="small">${{c.created_at_local || c.created_at}}</p>
    </div>
  `).join('');

  const alerts = (data.alerts || []).slice(0, 30).map(a => `
    <div class="card">
      <div class="pill">${{a.type}}</div>
      <p>${{a.friendly_info || ''}}</p>
      <p class="small">Detected local: ${{a.detected_at_local || ''}}</p>
      <p class="small">Created local: ${{a.created_at_local || ''}}</p>
    </div>
  `).join('');

  const mapCard = data.location ? `
    <div class="card">
      <h2>Router Location</h2>
      <div id="map"></div>
      <p class="small">Location: ${{data.location.location_label || 'map coordinates available'}}</p>
      <p class="small">Method: ${{data.location.method || 'unknown'}} | Accuracy: ${{data.location.accuracy || 'unknown'}}m | Updated: ${{data.location.updated_at || ''}}</p>
    </div>
  ` : `
    <div class="card"><h2>Router Location</h2><p class="small">No location stored yet.</p></div>
  `;

  const platformImage = data.platform?.image_url ? `
    <div class="card device-hero">
      <img src="${{data.platform.image_url}}" alt="${{data.platform.label || 'Router'}} platform image">
    </div>
  ` : '';

  content.innerHTML = `
    ${{platformImage}}
    <div class="card">
      <h2>Summary</h2>
      <p>Bucket: ${{data.router?.bucket || 'Unknown'}}</p>
      <p class="small">Last polled local: ${{data.router?.last_seen_local || ''}}</p>
      <p class="small">Display timezone: ${{data.local_timezone}}</p>
      <button onclick="markForReview()">Mark for Further Review</button>
    </div>

    <h2>Open / Historical Issues</h2>
    ${{issues || '<div class="card"><p class="small">No issues found.</p></div>'}}

    <div class="card">
      <h2>Add Router Note</h2>
      <textarea id="routerComment" rows="3" placeholder="Add operational context, signal notes, or admin observations..."></textarea>
      <br><br>
      <button class="primary" onclick="addRouterComment()">Save Note</button>
    </div>

    <h2>SIM / WAN Interfaces</h2>
    <div class="grid">${{sims || '<div class="card"><p class="small">No SIM data found.</p></div>'}}</div>

    ${{renderCellularMobilityCard({{...(cellular || {{}}), recent_events: (cellular?.recent_events || []).filter(e => e.event_type !== '5g_service_mode_change')}})}}

    ${{mapCard}}

    <div class="card">
      <h2 id="signalChartTitle">30-Day Signal Health — SINR, RSRQ, Cell, and 5G Mode Events</h2>
      <p class="small">Triangle markers indicate detected cell/tower identity changes. Hover a marker for old/new cell details.</p>
      ${{renderGraphModuleControl('signal_health', 'Signal history polling', 'Controls how often this router collects signal samples used by this graph.')}}
      <div class="chart-range-controls" style="display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:0 0 12px 0;">
        <select id="signalRangeSelect" style="max-width:180px;">
          <option value="7">Last 7 days</option>
          <option value="14">Last 14 days</option>
          <option value="30">Last 30 days</option>
          <option value="90">Last 90 days</option>
          <option value="custom">Custom range</option>
        </select>
        <span id="signalCustomRangeInputs" style="display:none;align-items:center;gap:8px;">
          <input id="signalStartDate" type="date" style="width:auto;margin:0;">
          <span class="small">to</span>
          <input id="signalEndDate" type="date" style="width:auto;margin:0;">
        </span>
        <button id="signalApplyButton" class="primary" onclick="applyChartRangeButton(\'signal\', this)">Apply</button>
        <button id="signalResetZoomButton" type="button" onclick="resetChartZoom(\'signal\')" style="display:none;">Reset zoom</button>
        <span id="signalRangeStatus" class="small"></span>
      </div>
      <div id="signalHistoryNote" class="small" style="display:none;margin:8px 0 10px;color:#facc15;"></div>
      <div class="chart-box"><canvas id="signalChart"></canvas><div id="signalNoData" class="no-data-overlay">No signal data found</div></div>
    </div>

    <div class="card">
      <h2 id="usageChartTitle">30-Day Data Usage</h2>
      ${{renderGraphModuleControl('sim_usage', 'Carrier/SIM usage polling', 'Controls how often this router collects carrier/SIM usage samples used by this graph.')}}
      ${{renderGraphModuleControl('router_stream_usage', 'NCM cloud traffic polling', 'Controls how often this router collects NCM cloud traffic samples used by the optional yellow overlay.')}}
      <div class="chart-range-controls" style="display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:0 0 12px 0;">
        <select id="usageRangeSelect" style="max-width:180px;">
          <option value="7">Last 7 days</option>
          <option value="14">Last 14 days</option>
          <option value="30">Last 30 days</option>
          <option value="90">Last 90 days</option>
          <option value="custom">Custom range</option>
        </select>
        <span id="usageCustomRangeInputs" style="display:none;align-items:center;gap:8px;">
          <input id="usageStartDate" type="date" style="width:auto;margin:0;">
          <span class="small">to</span>
          <input id="usageEndDate" type="date" style="width:auto;margin:0;">
        </span>
        <button id="usageApplyButton" class="primary" onclick="applyChartRangeButton(\'usage\', this)">Apply</button>
        <button id="usageResetZoomButton" type="button" onclick="resetChartZoom(\'usage\')" style="display:none;">Reset zoom</button>
        <span id="usageRangeStatus" class="small"></span>
      </div>
      <label class="small" style="display:inline-flex;align-items:center;gap:8px;margin:0 0 12px 0;cursor:pointer;">
        <input id="showNcmTrafficToggle" type="checkbox" style="width:auto;margin:0;">
        Show NCM cloud traffic
      </label>
      <div id="usageHistoryNote" class="small" style="display:none;margin:8px 0 10px;color:#facc15;"></div>
      <div class="chart-box"><canvas id="usageChart"></canvas><div id="usageNoData" class="no-data-overlay">No usage data found</div></div>
    </div>

    <div class="card">
      <h2 id="alertChartTitle">30-Day Alert Timeline</h2>
      <div class="small" style="margin:0 0 12px 0;padding:10px 12px;border:1px solid rgba(148,163,184,.22);border-radius:10px;background:rgba(15,23,42,.45);color:rgba(226,232,240,.82);">
        Alert data depends on alert rules being configured at the NCM group level. After enabling or changing alert rules, allow some time for new alerts to populate here.
      </div>
      ${{renderGraphModuleControl('alerts', 'Alert polling', 'Controls how often this router checks for alerts used by this graph.')}}
      <div class="chart-range-controls" style="display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:0 0 12px 0;">
        <select id="alertRangeSelect" style="max-width:180px;">
          <option value="7">Last 7 days</option>
          <option value="14">Last 14 days</option>
          <option value="30">Last 30 days</option>
          <option value="90">Last 90 days</option>
          <option value="custom">Custom range</option>
        </select>
        <span id="alertCustomRangeInputs" style="display:none;align-items:center;gap:8px;">
          <input id="alertStartDate" type="date" style="width:auto;margin:0;">
          <span class="small">to</span>
          <input id="alertEndDate" type="date" style="width:auto;margin:0;">
        </span>
        <button id="alertApplyButton" class="primary" onclick="applyChartRangeButton(\'alert\', this)">Apply</button>
        <button id="alertResetZoomButton" type="button" onclick="resetChartZoom(\'alert\')" style="display:none;">Reset zoom</button>
        <span id="alertRangeStatus" class="small"></span>
      </div>
      <div id="alertHistoryNote" class="small" style="display:none;margin:8px 0 10px;color:#facc15;"></div>
      <div class="chart-box"><canvas id="alertChart"></canvas><div id="alertNoData" class="no-data-overlay">No alerts found</div></div>
    </div>

    <div class="card">
      <h2>Usage Investigation</h2>
      <p class="small">Compares total SIM/WAN usage against router stream usage from NCM, then overlays NCM online/offline state churn.</p>
      <select id="usageDays" style="max-width:180px; margin-right:8px;">
        <option value="7">Last 7 days</option>
        <option value="15">Last 15 days</option>
        <option value="30" selected>Last 30 days</option>
        <option value="90">Last 90 days</option>
      </select>
      <button class="primary" onclick="loadUsageReport()">Run Usage Report</button>
      <button onclick="exportUsageReport()">Export XLSX</button>
      <div id="usageReportStatus" class="small"></div>
      <div id="usageReport"></div>
      <div id="usageBreakdownChartDisabled" style="display:none;"></div>
    </div>

    <h2>Saved Notes</h2>
    ${{comments || '<div class="card"><p class="small">No notes saved yet.</p></div>'}}

    <h2>Recent Alerts</h2>
    ${{alerts || '<div class="card"><p class="small">No alerts found.</p></div>'}}
  `;

  if (data.location) {{
    const lat = data.location.latitude;
    const lon = data.location.longitude;
    const map = L.map('map').setView([lat, lon], 14);
    L.tileLayer('https://tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
      maxZoom: 19,
      attribution: '&copy; OpenStreetMap'
    }}).addTo(map);
    L.marker([lat, lon]).addTo(map).bindPopup('Router {router_id}').openPopup();
  }}

  ensureChartRanges();
  updateAllChartRangeControls();

  window.currentSignalRows = data.daily_signal || [];
  window.currentSignalEvents = cellular?.recent_events || [];
  window.currentSignalSelectedDays = data.selected_days || 30;
  window.currentSignalStartDate = null;
  window.currentSignalEndDate = null;

  window.currentUsageRows = data.daily_usage || [];
  window.currentUsageNcmRows = data.daily_ncm_usage || [];
  window.currentUsageSelectedDays = data.selected_days || 30;
  window.currentUsageStartDate = null;
  window.currentUsageEndDate = null;

  window.currentAlertRows = data.daily_alerts || [];
  window.currentAlertSelectedDays = data.selected_days || 30;
  window.currentAlertStartDate = null;
  window.currentAlertEndDate = null;

  const signalTitle = document.getElementById('signalChartTitle');
  const usageTitle = document.getElementById('usageChartTitle');
  const alertTitle = document.getElementById('alertChartTitle');

  if (signalTitle) signalTitle.textContent = '30-Day Signal Health — SINR, RSRQ, Cell, and 5G Mode Events';
  if (usageTitle) usageTitle.textContent = '30-Day Data Usage';
  if (alertTitle) alertTitle.textContent = '30-Day Alert Timeline';

  renderSignalChart(
    window.currentSignalRows,
    window.currentSignalEvents,
    window.currentSignalSelectedDays,
    window.currentSignalStartDate,
    window.currentSignalEndDate
  );
  renderUsageChart(
    window.currentUsageRows,
    window.currentUsageNcmRows,
    window.currentUsageSelectedDays,
    document.getElementById('showNcmTrafficToggle')?.checked,
    window.currentUsageStartDate,
    window.currentUsageEndDate
  );
  renderAlertChart(
    window.currentAlertRows,
    window.currentAlertSelectedDays,
    window.currentAlertStartDate,
    window.currentAlertEndDate
  );

  window.setTimeout(() => {{
    restoreSavedChartRangePreferences();
  }}, 250);

  const ncmToggle = document.getElementById('showNcmTrafficToggle');
  if (ncmToggle && !ncmToggle.dataset.bound) {{
    ncmToggle.dataset.bound = '1';
    ncmToggle.addEventListener('change', () => {{
      renderUsageChart(
        window.currentUsageRows || [],
        window.currentUsageNcmRows || [],
        window.currentUsageSelectedDays || 30,
        ncmToggle.checked,
        window.currentUsageStartDate,
        window.currentUsageEndDate
      );
    }});
  }}
}}

function cellularEventDay(value) {{
  if (!value) return '';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value).slice(0, 10);
  return d.toISOString().slice(0, 10);
}}

function setChartNoData(id, visible) {{
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.toggle('visible', !!visible);
}}



function rowTimestampValue(row) {{
  if (!row) return null;
  const raw = row.created_at || row.time || row.timestamp || row.updated_at || row.reported_at || row.x || row.date || row.day || row.bucket;
  if (!raw) return null;
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return null;
  return d;
}}

function earliestLocalRecordInfo(rows, selectedDays, startDate) {{
  if (!Array.isArray(rows) || rows.length === 0) return null;

  const timestamps = rows
    .map(rowTimestampValue)
    .filter(d => d && !Number.isNaN(d.getTime()))
    .sort((a, b) => a - b);

  if (!timestamps.length) return null;

  const oldest = timestamps[0];
  const requestedStart = startDate instanceof Date && !Number.isNaN(startDate.getTime())
    ? startDate
    : new Date(Date.now() - (Number(selectedDays || 30) * 24 * 60 * 60 * 1000));

  const gapMs = oldest.getTime() - requestedStart.getTime();
  const gapHours = gapMs / (1000 * 60 * 60);

  // Only mark if local history starts meaningfully after the requested window.
  // Six-hour buffer avoids noise from timezone rounding or partial-day queries.
  if (gapHours < 6) return null;

  return {{
    oldest,
    requestedStart,
    labelValue: oldest.toISOString().slice(0, 10),
    label: oldest.toLocaleString([], {{
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: 'numeric',
      minute: '2-digit'
    }})
  }};
}}

function setHistoryNote(noteId, rows, selectedDays, startDate, label) {{
  const el = document.getElementById(noteId);
  const info = earliestLocalRecordInfo(rows, selectedDays, startDate);

  if (!el) return info;

  if (!info) {{
    el.style.display = 'none';
    el.textContent = '';
    return null;
  }}

  el.style.display = 'block';
  el.textContent = `${{label}} local history begins ${{info.label}}. This graph has less than ${{selectedDays || 30}} days of locally cached data.`;
  return info;
}}


const historyStartLinePlugin = {{
  id: 'historyStartLine',
  afterDatasetsDraw(chart, args, pluginOptions) {{
    const opts = pluginOptions || {{}};
    if (!opts.timestamp) return;

    const xScale = chart.scales && chart.scales.x;
    const chartArea = chart.chartArea;
    if (!xScale || !chartArea) return;

    const ts = new Date(opts.timestamp);
    if (Number.isNaN(ts.getTime())) return;

    let x = null;

    // Most router charts use category labels like YYYY-MM-DD, so place the line
    // by label index instead of asking Chart.js to map a Date object.
    const labelValue = opts.labelValue || ts.toISOString().slice(0, 10);
    const labels = chart.data && Array.isArray(chart.data.labels) ? chart.data.labels : [];
    let labelIndex = labels.indexOf(labelValue);

    // Fallback: if the exact label is missing, use the first chart label after the oldest record.
    if (labelIndex < 0) {{
      labelIndex = labels.findIndex(v => String(v) >= String(labelValue));
    }}

    if (labelIndex >= 0) {{
      try {{
        x = xScale.getPixelForValue(labelIndex);
      }} catch (e) {{
        x = null;
      }}
    }}

    // Last-resort fallback for time scales.
    if (x === null || Number.isNaN(x)) {{
      try {{
        x = xScale.getPixelForValue(labelValue);
      }} catch (e) {{
        x = null;
      }}
    }}

    if (x === null || Number.isNaN(x)) return;
    if (x < chartArea.left || x > chartArea.right) return;

    const ctx = chart.ctx;
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(x, chartArea.top);
    ctx.lineTo(x, chartArea.bottom);
    ctx.lineWidth = 2;
    ctx.strokeStyle = '#facc15';
    ctx.setLineDash([6, 5]);
    ctx.stroke();

    ctx.setLineDash([]);
    ctx.fillStyle = '#facc15';
    ctx.font = '12px Arial';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.fillText(opts.label || 'Earliest local record', Math.min(x + 6, chartArea.right - 130), chartArea.top + 6);
    ctx.restore();
  }}
}};

if (window.Chart && !window.__historyStartLinePluginRegistered) {{
  Chart.register(historyStartLinePlugin);
  window.__historyStartLinePluginRegistered = true;
}}


function renderSignalChart(rows, cellularEvents, selectedDays, startDate, endDate) {{
  let historyInfo = setHistoryNote('signalHistoryNote', rows, selectedDays, startDate, 'Signal');
  const canvas = document.getElementById('signalChart');
  if (!canvas || typeof Chart === 'undefined') return;
  if (window.signalChartObj) window.signalChartObj.destroy();

  rows = rows || [];
  let labels = buildDayLabels(selectedDays || 30, startDate, endDate);

  // For wide signal ranges, hide empty leading days before the first actual
  // plotted signal row. This keeps Last 90 Days honest while avoiding a huge
  // blank area when local history starts later than the selected range.
  const signalRowDays = rows
    .map(r => String(r.day || '').slice(0, 10))
    .filter(Boolean)
    .sort();

  const firstSignalDay = signalRowDays.length ? signalRowDays[0] : null;
  const firstSignalIndex = firstSignalDay ? labels.indexOf(firstSignalDay) : -1;

  if (firstSignalIndex > 2) {{
    const signalTrimOffset = Math.max(0, firstSignalIndex - 1);
    labels = labels.slice(signalTrimOffset);

    if (historyInfo) {{
      historyInfo = {{
        ...historyInfo,
        index: Math.max(0, Number(historyInfo.index || firstSignalIndex) - signalTrimOffset)
      }};
    }}
  }}
  rows.forEach(r => {{
    if (r.day && !labels.includes(r.day)) labels.push(r.day);
  }});
  const sims = [...new Set((rows || []).map(r => r.sim_label || 'Unknown'))];

  const datasets = [];
  sims.forEach(sim => {{
    datasets.push({{
      label: sim + ' Avg SINR',
      data: labels.map(day => {{
        const row = rows.find(r => r.day === day && (r.sim_label || 'Unknown') === sim);
        return row && row.avg_sinr !== null && row.avg_sinr !== undefined ? Number(row.avg_sinr) : null;
      }}),
      tension: 0.3
    }});

    datasets.push({{
      label: sim + ' Avg RSRQ',
      data: labels.map(day => {{
        const row = rows.find(r => r.day === day && (r.sim_label || 'Unknown') === sim);
        return row && row.avg_rsrq !== null && row.avg_rsrq !== undefined ? Number(row.avg_rsrq) : null;
      }}),
      tension: 0.3
    }});
  }});

  const labelSet = new Set(labels);
  const changeEvents = (cellularEvents || []).filter(e => e.event_type && e.event_type !== 'first_seen');
  const cellChangeEvents = changeEvents.filter(e => e.event_type !== '5g_service_mode_change');
  const serviceModeEvents = changeEvents.filter(e => e.event_type === '5g_service_mode_change');

  function cellularEventPoint(e) {{
    const day = cellularEventDay(e.detected_at);
    let y = null;

    if (e.sinr !== null && e.sinr !== undefined && !Number.isNaN(Number(e.sinr))) {{
      y = Number(e.sinr);
    }} else if (e.rsrq !== null && e.rsrq !== undefined && !Number.isNaN(Number(e.rsrq))) {{
      y = Number(e.rsrq);
    }} else if (e.rsrp !== null && e.rsrp !== undefined && !Number.isNaN(Number(e.rsrp))) {{
      y = Number(e.rsrp);
    }} else {{
      y = 0;
    }}

    return {{
      x: day,
      y,
      event_type: e.event_type,
      detected_at: e.detected_at,
      old_tac: e.old_tac,
      old_cell_id: e.old_cell_id,
      new_tac: e.new_tac,
      new_cell_id: e.new_cell_id,
      old_service_type: e.old_service_type,
      new_service_type: e.new_service_type,
      rsrp: e.rsrp,
      rsrq: e.rsrq,
      sinr: e.sinr
    }};
  }}

  const cellChangeByDay = new Map();
  cellChangeEvents.forEach(e => {{
    const p = cellularEventPoint(e);
    if (!p.x || !labelSet.has(p.x)) return;
    if (!cellChangeByDay.has(p.x)) cellChangeByDay.set(p.x, []);
    cellChangeByDay.get(p.x).push(p);
  }});

  const eventPoints = Array.from(cellChangeByDay.entries()).map(([day, points]) => {{
    points.sort((a, b) => new Date(a.detected_at || 0) - new Date(b.detected_at || 0));
    const latest = points[points.length - 1] || {{}};
    const first = points[0] || latest;

    return {{
      ...latest,
      x: day,
      y: latest.y,
      event_count: points.length,
      first_detected: first.detected_at,
      last_detected: latest.detected_at,
      grouped_event_types: [...new Set(points.map(p => p.event_type).filter(Boolean))]
    }};
  }});

  const serviceModeByDay = new Map();
  serviceModeEvents.forEach(e => {{
    const p = cellularEventPoint(e);
    if (!p.x || !labelSet.has(p.x)) return;
    if (!serviceModeByDay.has(p.x)) serviceModeByDay.set(p.x, []);
    serviceModeByDay.get(p.x).push(p);
  }});

  const serviceModePoints = Array.from(serviceModeByDay.entries()).map(([day, points]) => {{
    points.sort((a, b) => new Date(a.detected_at || 0) - new Date(b.detected_at || 0));
    const latest = points[points.length - 1] || {{}};
    const first = points[0] || latest;

    return {{
      ...latest,
      x: day,
      y: latest.y,
      event_count: points.length,
      first_detected: first.detected_at,
      last_detected: latest.detected_at,
      first_service_type: first.old_service_type,
      latest_old_service_type: latest.old_service_type,
      latest_new_service_type: latest.new_service_type
    }};
  }});

  labels.sort();

  if (eventPoints.length) {{
    datasets.push({{
      type: 'scatter',
      label: 'Cell/tower change',
      data: eventPoints,
      pointRadius: 7,
      pointHoverRadius: 9,
      pointStyle: 'triangle',
      showLine: false
    }});
  }}

  if (serviceModePoints.length) {{
    datasets.push({{
      type: 'scatter',
      label: '5G service mode change',
      data: serviceModePoints,
      pointRadius: 5,
      pointHoverRadius: 7,
      pointStyle: 'rectRot',
      showLine: false
    }});
  }}

  const hasUsableSignalData = labels.length && datasets.some(ds => {{
    const data = ds.data || [];
    return data.some(v => {{
      if (v === null || v === undefined) return false;
      if (typeof v === 'object') return v.y !== null && v.y !== undefined;
      return !Number.isNaN(Number(v));
    }});
  }});

  if (!hasUsableSignalData) {{
    setChartNoData('signalNoData', true);
    return;
  }}
  setChartNoData('signalNoData', false);

  window.signalChartObj = new Chart(canvas, {{
    type: 'line',
    data: {{ labels, datasets }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      devicePixelRatio: window.devicePixelRatio || 2,
      events: ['mousemove', 'mouseout', 'click', 'touchstart', 'touchmove', 'mousedown', 'mouseup'],
      interaction: {{
        mode: 'nearest',
        intersect: false
      }},
      onClick: function(evt, elements, chart) {{
        if (chart && chart.$dragZoom && chart.$dragZoom.suppressClick) {{
          chart.$dragZoom.suppressClick = false;
          return;
        }}
        const points = chart.getElementsAtEventForMode(evt, 'nearest', {{ intersect: true }}, true);
        if (!points || !points.length) return;
        const point = points[0];
        const ds = chart.data.datasets[point.datasetIndex] || {{}};
        const raw = (ds.data || [])[point.index];

        if ((ds.label === 'Cell/tower change' || ds.label === '5G service mode change') && raw && raw.detected_at) {{
          if (raw.event_count && Number(raw.event_count) > 1 && raw.x) {{
            openEventContextPanel(ds.label || 'Cellular event', chartDayAnchorUtc(raw.x), 720, 720, 'daily');
          }} else {{
            openEventContextPanel(ds.label || 'Cellular event', raw.detected_at);
          }}
          return;
        }}

        const day = chart.data.labels[point.index];
        openEventContextPanel(ds.label || 'Signal chart target', chartDayAnchorUtc(day), 720, 720, 'daily');
      }},
      plugins: {{
        chartDragZoom: {{ enabled: true, kind: 'signal' }},
        historyStartLine: historyInfo ? {{
          timestamp: historyInfo.oldest,
          labelValue: historyInfo.labelValue,
          label: 'Earliest local record'
        }} : false,
        legend: {{ labels: {{ color: '#e5e7eb' }} }},
        tooltip: {{
          callbacks: {{
            label: function(ctx) {{
              const raw = ctx.raw || {{}};

              if (ctx.dataset && ctx.dataset.label === 'Cell/tower change') {{
                const count = Number(raw.event_count || 1);
                const typeList = Array.isArray(raw.grouped_event_types) && raw.grouped_event_types.length
                  ? raw.grouped_event_types.join(', ')
                  : (raw.event_type || 'change');

                const lines = [
                  count > 1 ? `Cell/tower changes: ${{count}} events` : 'Cell/tower change: ' + (raw.event_type || 'change'),
                  count > 1 ? 'Event types: ' + typeList : null,
                  'First: ' + formatCellularTime(raw.first_detected || raw.detected_at),
                  count > 1 ? 'Last: ' + formatCellularTime(raw.last_detected || raw.detected_at) : null,
                  'Latest old: TAC ' + (raw.old_tac || 'n/a') + ' / Cell ' + shortCell(raw.old_cell_id),
                  'Latest new: TAC ' + (raw.new_tac || 'n/a') + ' / Cell ' + shortCell(raw.new_cell_id),
                  'Latest signal: RSRP ' + (raw.rsrp ?? 'n/a') + ' / RSRQ ' + (raw.rsrq ?? 'n/a') + ' / SINR ' + (raw.sinr ?? 'n/a')
                ];

                return lines.filter(Boolean);
              }}

              if (ctx.dataset && ctx.dataset.label === '5G service mode change') {{
                const count = Number(raw.event_count || 1);
                const lines = [
                  count > 1 ? `5G service mode changed ${{count}} times` : '5G service mode changed',
                  'First: ' + formatCellularTime(raw.first_detected || raw.detected_at),
                  count > 1 ? 'Last: ' + formatCellularTime(raw.last_detected || raw.detected_at) : null,
                  'Latest: ' + (raw.latest_old_service_type || raw.old_service_type || 'n/a') + ' → ' + (raw.latest_new_service_type || raw.new_service_type || 'n/a'),
                  'Same serving cell: TAC ' + (raw.new_tac || raw.old_tac || 'n/a') + ' / Cell ' + shortCell(raw.new_cell_id || raw.old_cell_id),
                  'Signal: RSRP ' + (raw.rsrp ?? 'n/a') + ' / RSRQ ' + (raw.rsrq ?? 'n/a') + ' / SINR ' + (raw.sinr ?? 'n/a')
                ];
                return lines.filter(Boolean);
              }}

              return (ctx.dataset.label || 'Metric') + ': ' + (ctx.parsed.y ?? 'n/a');
            }}
          }}
        }}
      }},
      scales: {{
        x: {{ ticks: {{ color: '#94a3b8' }} }},
        y: {{ ticks: {{ color: '#94a3b8' }} }}
      }}
    }}
  }});
}}


function buildDayLabels(days, startDate, endDate) {{
  const labels = [];

  if (startDate && endDate) {{
    const start = new Date(startDate + 'T00:00:00Z');
    const end = new Date(endDate + 'T00:00:00Z');
    const diffDays = Math.floor((end - start) / 86400000) + 1;

    if (!Number.isNaN(diffDays) && diffDays > 0 && diffDays <= 90) {{
      for (let i = 0; i < diffDays; i++) {{
        const d = new Date(start);
        d.setDate(start.getDate() + i);
        labels.push(d.toISOString().slice(0, 10));
      }}
      return labels;
    }}
  }}

  const count = Math.max(1, Math.min(Number(days || 30), 90));
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  for (let i = count - 1; i >= 0; i--) {{
    const d = new Date(today);
    d.setDate(today.getDate() - i);
    labels.push(d.toISOString().slice(0, 10));
  }}

  return labels;
}}

  function renderUsageChart(rows, ncmRows, selectedDays, showNcmTraffic, startDate, endDate) {{
    const canvas = document.getElementById('usageChart');
    if (!canvas || typeof Chart === 'undefined') return;
    if (window.usageChartObj) window.usageChartObj.destroy();

    rows = rows || [];
    ncmRows = ncmRows || [];

    function usageDayValue(r) {{
      if (!r || !r.day) return null;
      return String(r.day).slice(0, 10);
    }}

    function minUsageDay(dayRows) {{
      const days = (dayRows || [])
        .map(usageDayValue)
        .filter(Boolean)
        .sort();
      return days.length ? days[0] : null;
    }}

    function maxUsageDay(dayRows) {{
      const days = (dayRows || [])
        .map(usageDayValue)
        .filter(Boolean)
        .sort();
      return days.length ? days[days.length - 1] : null;
    }}

    const rangeRows = showNcmTraffic ? rows.concat(ncmRows) : rows;
    const effectiveStartDate = minUsageDay(rangeRows) || startDate;
    const effectiveEndDate = endDate || maxUsageDay(rangeRows);

    const historyInfo = setHistoryNote('usageHistoryNote', rangeRows, selectedDays, effectiveStartDate, 'Usage');
    const earliestUsageMarkerDay = minUsageDay(rangeRows);
    const earliestUsageMarkerTimestamp = earliestUsageMarkerDay ? (earliestUsageMarkerDay + 'T00:00:00Z') : null;

    const labels = buildDayLabels(selectedDays || 30, effectiveStartDate, effectiveEndDate);

    rows.forEach(r => {{
      const day = usageDayValue(r);
      if (day && !labels.includes(day)) labels.push(day);
    }});

    if (showNcmTraffic) {{
      ncmRows.forEach(r => {{
        const day = usageDayValue(r);
        if (day && !labels.includes(day)) labels.push(day);
      }});
    }}

    labels.sort();

    const sims = [...new Set(rows.map(r => r.sim_label || 'Unknown'))];
  const datasets = sims.map(sim => {{
    return {{
      label: sim + ' usage MB',
      backgroundColor: 'rgba(56, 189, 248, 0.55)',
      borderColor: 'rgba(56, 189, 248, 0.9)',
      borderWidth: 1,
      usageRowsByDay: Object.fromEntries(
        rows
          .filter(r => (r.sim_label || 'Unknown') === sim)
          .map(r => [r.day, r])
      ),
      data: labels.map(day => {{
        const row = rows.find(r => r.day === day && (r.sim_label || 'Unknown') === sim);
        return row ? Number(row.total_mb ?? (Number(row.total_bytes || 0) / (1024 ** 2))) : 0;
      }})
    }};
  }});

  if (showNcmTraffic && ncmRows.length) {{
    datasets.push({{
      label: 'NCM cloud traffic MB',
      data: labels.map(day => {{
        const row = ncmRows.find(r => r.day === day);
        return row ? Number(row.ncm_total_mb ?? (Number(row.total_bytes || 0) / (1024 ** 2))) : 0;
      }}),
      backgroundColor: 'rgba(250, 204, 21, 0.78)',
      borderColor: 'rgba(250, 204, 21, 0.95)',
      borderWidth: 1,
      ncmRowsByDay: Object.fromEntries(ncmRows.map(r => [r.day, r]))
    }});
  }}

  const hasUsableUsageData = labels.length && datasets.some(ds =>
    (ds.data || []).some(v => Number(v || 0) > 0)
  );

  if (!hasUsableUsageData) {{
    setChartNoData('usageNoData', true);
    return;
  }}
  setChartNoData('usageNoData', false);

  window.usageChartObj = new Chart(canvas, {{
    type: 'bar',
    data: {{ labels, datasets }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      devicePixelRatio: window.devicePixelRatio || 2,
      events: ['mousemove', 'mouseout', 'click', 'touchstart', 'touchmove', 'mousedown', 'mouseup'],
      interaction: {{
        mode: 'index',
        intersect: false
      }},
      onClick: function(evt, elements, chart) {{
        if (chart && chart.$dragZoom && chart.$dragZoom.suppressClick) {{
          chart.$dragZoom.suppressClick = false;
          return;
        }}
        const points = chart.getElementsAtEventForMode(evt, 'nearest', {{ intersect: true }}, true);
        if (!points || !points.length) return;
        const point = points[0];
        const ds = chart.data.datasets[point.datasetIndex] || {{}};
        const day = chart.data.labels[point.index];
        openEventContextPanel(ds.label || 'Usage chart target', chartDayAnchorUtc(day), 720, 720, 'daily');
      }},
      plugins: {{
          chartDragZoom: {{ enabled: true, kind: 'usage' }},
          historyStartLine: earliestUsageMarkerTimestamp ? {{
            timestamp: earliestUsageMarkerTimestamp,
            labelValue: earliestUsageMarkerDay,
            label: 'Earliest local record'
          }} : false,

        legend: {{ labels: {{ color: '#e5e7eb' }} }},
        tooltip: {{
          callbacks: {{
            label: function(ctx) {{
              const label = ctx.dataset.label || 'Usage';
              const value = Number(ctx.parsed.y || 0).toFixed(3);

              if (label === 'NCM cloud traffic MB') {{
                const day = ctx.label;
                const row = (ctx.dataset.ncmRowsByDay || {{}})[day] || {{}};
                return [
                  'NCM cloud traffic total: ' + Number(row.ncm_total_mb ?? value).toFixed(3) + ' MB',
                  'NCM in: ' + Number(row.ncm_in_mb || 0).toFixed(3) + ' MB',
                  'NCM out: ' + Number(row.ncm_out_mb || 0).toFixed(3) + ' MB'
                ];
              }}

              const day = ctx.label;
              const row = (ctx.dataset.usageRowsByDay || {{}})[day] || {{}};
              return [
                label.replace(' usage MB', '') + ' usage total: ' + Number(row.total_mb ?? value).toFixed(3) + ' MB',
                'In: ' + Number(row.in_mb || 0).toFixed(3) + ' MB',
                'Out: ' + Number(row.out_mb || 0).toFixed(3) + ' MB'
              ];
            }}
          }}
        }}
      }},
      scales: {{
        x: {{ stacked: false, ticks: {{ color: '#94a3b8' }} }},
        y: {{ stacked: false, ticks: {{ color: '#94a3b8' }} }}
      }}
    }}
  }});
}}

function renderAlertChart(rows, selectedDays, startDate, endDate) {{
  const historyInfo = setHistoryNote('alertHistoryNote', rows, selectedDays, startDate, 'Alert');
  rows = rows || [];
  const labels = buildDayLabels(selectedDays || 30, startDate, endDate);
  rows.forEach(r => {{
    if (r.day && !labels.includes(r.day)) labels.push(r.day);
  }});
  labels.sort();
  const types = [...new Set(rows.map(r => r.type))];

  const datasets = types.map(type => {{
    return {{
      label: type,
      data: labels.map(day => {{
        const row = rows.find(r => r.day === day && r.type === type);
        return row ? row.count : 0;
      }}),
      tension: 0.2
    }};
  }});

  const alertCanvas = document.getElementById('alertChart');
  if (!alertCanvas || typeof Chart === 'undefined') return;
  if (window.alertChartObj) window.alertChartObj.destroy();

  const hasUsableAlertData = labels.length && datasets.some(ds =>
    (ds.data || []).some(v => Number(v || 0) > 0)
  );

  if (!hasUsableAlertData) {{
    setChartNoData('alertNoData', true);
    return;
  }}
  setChartNoData('alertNoData', false);

  window.alertChartObj = new Chart(alertCanvas, {{
    type: 'bar',
    data: {{ labels, datasets }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      devicePixelRatio: window.devicePixelRatio || 2,
      events: ['mousemove', 'mouseout', 'click', 'touchstart', 'touchmove', 'mousedown', 'mouseup'],
      onClick: function(evt, elements, chart) {{
        if (chart && chart.$dragZoom && chart.$dragZoom.suppressClick) {{
          chart.$dragZoom.suppressClick = false;
          return;
        }}
        const points = chart.getElementsAtEventForMode(evt, 'nearest', {{ intersect: true }}, true);
        if (!points || !points.length) return;
        const point = points[0];
        const ds = chart.data.datasets[point.datasetIndex] || {{}};
        const day = chart.data.labels[point.index];
        openEventContextPanel(ds.label || 'Alert chart target', chartDayAnchorUtc(day), 720, 720, 'daily');
      }},
      plugins: {{
        chartDragZoom: {{ enabled: true, kind: 'alert' }},
        historyStartLine: historyInfo ? {{
          timestamp: historyInfo.oldest,
          labelValue: historyInfo.labelValue,
          label: 'Earliest local record'
        }} : false,
 legend: {{ labels: {{ color: '#e5e7eb' }} }} }},
      scales: {{
        x: {{ stacked: true, ticks: {{ color: '#94a3b8' }} }},
        y: {{ stacked: true, ticks: {{ color: '#94a3b8' }} }}
      }}
    }}
  }});
}}




function getRouterPageProfileId() {{
  const params = new URLSearchParams(window.location.search);
  return params.get('profile_id') || (typeof window.activeProfileId === 'function' ? window.activeProfileId() : null) || localStorage.getItem('ncm_active_profile_id') || '1';
}}


function chartDayAnchorUtc(day) {{
  if (!day) return new Date().toISOString();

  const dayStr = String(day).slice(0, 10);

  // Daily graph buckets are displayed to the user as calendar days.
  // Use local noon for the selected day, then convert to UTC for the backend.
  // This makes the Event Context window align to the user's local day:
  // selected day 00:00 local -> next day 00:00 local.
  const localNoon = new Date(dayStr + 'T12:00:00');
  if (Number.isNaN(localNoon.getTime())) return dayStr + 'T12:00:00Z';

  return localNoon.toISOString();
}}

function formatEventContextDelta(seconds) {{
  if (seconds === null || seconds === undefined || Number.isNaN(Number(seconds))) return '';
  const n = Number(seconds);
  const abs = Math.abs(n);
  const label = abs < 60 ? `${{abs}}s` : `${{Math.floor(abs / 60)}}m ${{abs % 60}}s`;
  if (n === 0) return 'exact event time';
  return n < 0 ? `${{label}} before event` : `${{label}} after event`;
}}

function ensureEventContextPanel() {{
  let panel = document.getElementById('eventContextPanel');
  if (panel) return panel;

  panel = document.createElement('div');
  panel.id = 'eventContextPanel';
  panel.style.cssText = 'position:fixed;top:0;right:0;width:min(620px,96vw);height:100vh;z-index:2147483000;background:#020617;color:#e5e7eb;border-left:1px solid rgba(148,163,184,.35);box-shadow:-18px 0 40px rgba(0,0,0,.45);transform:translateX(105%);transition:transform .18s ease;display:flex;flex-direction:column;';
  panel.innerHTML = `
    <div style="padding:16px;border-bottom:1px solid rgba(148,163,184,.25);display:flex;justify-content:space-between;gap:12px;align-items:flex-start;">
      <div>
        <h2 style="margin:0 0 4px 0;">Event Context</h2>
        <div id="eventContextSubtitle" class="small">Router logs around selected event</div>
      </div>
      <button onclick="closeEventContextPanel()" style="width:auto;margin:0;">Close</button>
    </div>
    <div id="eventContextBody" style="padding:14px;overflow:auto;flex:1;"></div>
    <button id="eventContextCompass" onclick="eventContextJumpToNearest()" style="display:none;position:absolute;right:18px;bottom:18px;width:auto;margin:0;padding:10px 12px;border-radius:999px;border:1px solid rgba(56,189,248,.55);background:rgba(2,6,23,.94);color:#e5e7eb;box-shadow:0 10px 30px rgba(0,0,0,.45);z-index:2;cursor:pointer;">
      <span id="eventContextCompassArrow" style="font-weight:800;margin-right:6px;">↑</span>
      <span id="eventContextCompassLabel">Selected time</span>
    </button>
  `;
  document.body.appendChild(panel);

  const body = panel.querySelector('#eventContextBody');
  if (body && !body.dataset.compassBound) {{
    body.dataset.compassBound = '1';
    body.addEventListener('scroll', eventContextUpdateCompass);
  }}

  return panel;
}}

function closeEventContextPanel() {{
  const panel = document.getElementById('eventContextPanel');
  if (panel) panel.style.transform = 'translateX(105%)';
}}

function eventContextJumpToNearest() {{
  const el = document.getElementById('eventContextNearestLog');
  if (el) el.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
  setTimeout(() => eventContextUpdateCompass(), 450);
}}

function eventContextJumpToLatest() {{
  const el = document.getElementById('eventContextLatestLog');
  if (el) el.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
}}

function eventContextUpdateCompass() {{
  const body = document.getElementById('eventContextBody');
  const nearest = document.getElementById('eventContextNearestLog');
  const compass = document.getElementById('eventContextCompass');
  const arrow = document.getElementById('eventContextCompassArrow');
  const label = document.getElementById('eventContextCompassLabel');

  if (!body || !nearest || !compass) return;

  const bodyRect = body.getBoundingClientRect();
  const nearestRect = nearest.getBoundingClientRect();

  const above = nearestRect.bottom < bodyRect.top + 8;
  const below = nearestRect.top > bodyRect.bottom - 8;

  if (!above && !below) {{
    compass.style.display = 'none';
    return;
  }}

  compass.style.display = 'block';

  if (arrow) arrow.textContent = above ? '↑' : '↓';
  if (label) label.textContent = above ? 'Selected time above' : 'Selected time below';
}}

function eventContextHideCompass() {{
  const compass = document.getElementById('eventContextCompass');
  if (compass) compass.style.display = 'none';
}}

function eventContextRefetch(beforeMinutes, afterMinutes, modeOverride) {{
  const req = window.eventContextLastRequest || {{}};
  if (!req.eventTimeUtc) return;
  openEventContextPanel(
    req.eventLabel || 'Selected event',
    req.eventTimeUtc,
    beforeMinutes,
    afterMinutes,
    modeOverride || req.contextMode || 'event'
  );
}}

function eventContextExpandBefore(extraMinutes) {{
  const req = window.eventContextLastRequest || {{}};
  const before = Number(req.beforeMinutes || 10) + Number(extraMinutes || 60);
  const after = Number(req.afterMinutes || 10);
  eventContextRefetch(before, after, req.contextMode || 'event');
}}

function eventContextExpandAfter(extraMinutes) {{
  const req = window.eventContextLastRequest || {{}};
  const before = Number(req.beforeMinutes || 10);
  const after = Number(req.afterMinutes || 10) + Number(extraMinutes || 60);
  eventContextRefetch(before, after, req.contextMode || 'event');
}}

function eventContextExpandBoth(extraMinutes) {{
  const req = window.eventContextLastRequest || {{}};
  const before = Number(req.beforeMinutes || 10) + Number(extraMinutes || 60);
  const after = Number(req.afterMinutes || 10) + Number(extraMinutes || 60);
  eventContextRefetch(before, after, req.contextMode || 'event');
}}

function eventContextSelectedDay() {{
  eventContextRefetch(720, 720, 'daily');
}}

function eventContextShiftAnchorDays(dayDelta) {{
  const req = window.eventContextLastRequest || {{}};
  if (!req.eventTimeUtc) return;

  const d = new Date(req.eventTimeUtc);
  if (Number.isNaN(d.getTime())) return;

  d.setUTCDate(d.getUTCDate() + Number(dayDelta || 0));

  openEventContextPanel(
    req.eventLabel || 'Selected chart day',
    d.toISOString(),
    720,
    720,
    'daily'
  );
}}

function eventContextPullLatestLogs() {{
  const req = window.eventContextLastRequest || {{}};
  if (!req.eventTimeUtc) return;

  const eventMs = new Date(req.eventTimeUtc).getTime();
  const nowMs = Date.now();

  let afterMinutes = Number(req.afterMinutes || 10);
  if (!Number.isNaN(eventMs) && nowMs > eventMs) {{
    afterMinutes = Math.max(afterMinutes, Math.ceil((nowMs - eventMs) / 60000) + 1);
  }}

  openEventContextPanel(
    req.eventLabel || 'Selected event',
    req.eventTimeUtc,
    Number(req.beforeMinutes || 10),
    afterMinutes,
    req.contextMode || 'event'
  );
}}

function eventContextExportCsv() {{
  const req = window.eventContextLastRequest || {{}};
  if (!req.eventTimeUtc) return;

  const profileId = getRouterPageProfileId();
  const before = Number(req.beforeMinutes || 10);
  const after = Number(req.afterMinutes || 10);

  const url = `/event-context/logs/export.csv?router_id={router_id}&profile_id=${{encodeURIComponent(profileId)}}&event_time_utc=${{encodeURIComponent(req.eventTimeUtc)}}&before_minutes=${{encodeURIComponent(before)}}&after_minutes=${{encodeURIComponent(after)}}&live_fetch=1&limit=10000`;

  window.open(url, '_blank');
}}

function renderEventContextLogRow(log, contextMode = 'event', rowIndex = 0, totalRows = 0) {{
  const flags = [];
  const isNearest = !!(log.closest || log.closest_before || log.closest_after);
  const isDailyNearest = contextMode === 'daily' && !!log.closest;
  const isEventNearest = contextMode !== 'daily' && isNearest;

  if (contextMode === 'daily') {{
    if (log.closest) flags.push('nearest log to chart anchor');
  }} else {{
    if (log.closest) flags.push('closest');
    if (log.closest_before) flags.push('closest before');
    if (log.closest_after) flags.push('closest after');
  }}

  let bg = 'background:rgba(15,23,42,.55);border-color:rgba(148,163,184,.18);';
  if (isEventNearest) bg = 'background:rgba(250,204,21,.15);border-color:rgba(250,204,21,.55);box-shadow:0 0 0 1px rgba(250,204,21,.22) inset;';
  if (isDailyNearest) bg = 'background:rgba(56,189,248,.14);border-color:rgba(56,189,248,.55);box-shadow:0 0 0 1px rgba(56,189,248,.22) inset;';

  const delta = contextMode === 'daily' ? '' : formatEventContextDelta(log.delta_seconds);
  const rowId = log.closest ? 'eventContextNearestLog' : (rowIndex === totalRows - 1 ? 'eventContextLatestLog' : '');

  return `
    <div id="${{rowId}}" style="border:1px solid;${{bg}}border-radius:10px;padding:10px 12px;margin:0 0 10px 0;">
      <div style="display:flex;justify-content:space-between;gap:10px;align-items:flex-start;">
        <div>
          <strong>${{escapeHtml(log.log_time_local || log.reported_at_local || log.created_at_local || 'Unknown time')}}</strong>
          <span class="small">${{delta ? ' — ' + escapeHtml(delta) : ''}}</span>
        </div>
        <div class="small">${{escapeHtml(flags.join(', '))}}</div>
      </div>
      <div class="small" style="margin:4px 0;color:#cbd5e1;">
        ${{escapeHtml(log.level || 'level n/a')}} · ${{escapeHtml(log.source || 'source n/a')}}
      </div>
      <div style="white-space:pre-wrap;line-height:1.35;">${{escapeHtml(log.message || log.exception || 'No message')}}</div>
    </div>
  `;
}}

async function openEventContextPanel(eventLabel, eventTimeUtc, beforeMinutes = 10, afterMinutes = 10, contextMode = 'event') {{
  const panel = ensureEventContextPanel();
  const subtitle = document.getElementById('eventContextSubtitle');
  const body = document.getElementById('eventContextBody');

  panel.style.transform = 'translateX(0)';
  eventContextHideCompass();
  window.eventContextLastRequest = {{ eventLabel, eventTimeUtc, beforeMinutes, afterMinutes, contextMode }};
  if (subtitle) subtitle.textContent = `${{eventLabel || 'Selected event'}} · loading router logs...`;
  if (body) body.innerHTML = `
    <div class="card" style="margin:0;">
      <div style="display:flex;align-items:center;gap:12px;">
        <div style="width:22px;height:22px;border:3px solid rgba(148,163,184,.35);border-top-color:#38bdf8;border-radius:50%;animation:eventContextSpin .8s linear infinite;"></div>
        <div>
          <h3 style="margin:0 0 4px 0;">Fetching router logs...</h3>
          <p class="small" style="margin:0;">${{contextMode === 'daily' ? 'Loading router logs for the selected chart day.' : `Loading logs from ${{beforeMinutes}} minutes before to ${{afterMinutes}} minutes after the selected event.`}}</p>
        </div>
      </div>
    </div>
  `;
  if (!document.getElementById('eventContextSpinStyle')) {{
    const style = document.createElement('style');
    style.id = 'eventContextSpinStyle';
    style.textContent = '@keyframes eventContextSpin {{ from {{ transform: rotate(0deg); }} to {{ transform: rotate(360deg); }} }}';
    document.head.appendChild(style);
  }}

  try {{
    const profileId = getRouterPageProfileId();
    const url = `/event-context/logs?router_id={router_id}&profile_id=${{encodeURIComponent(profileId)}}&event_time_utc=${{encodeURIComponent(eventTimeUtc)}}&before_minutes=${{encodeURIComponent(beforeMinutes)}}&after_minutes=${{encodeURIComponent(afterMinutes)}}&live_fetch=1&limit=1000`;
    const res = await fetch(url, {{
      credentials: 'same-origin',
      headers: {{ 'Accept': 'application/json' }}
    }});

    const contentType = res.headers.get('content-type') || '';
    let data = null;

    if (contentType.includes('application/json')) {{
      data = await res.json();
    }} else {{
      const text = await res.text();
      throw new Error(`Server returned ${{res.status}} ${{res.statusText}}: ${{text.slice(0, 500)}}`);
    }}

    if (!res.ok) {{
      let detail = data.detail || 'Failed to load event context.';
      if (typeof detail !== 'string') {{
        try {{
          detail = JSON.stringify(detail, null, 2);
        }} catch (e) {{
          detail = String(detail);
        }}
      }}
      throw new Error(detail);
    }}

    if (subtitle) {{
      subtitle.textContent = `${{eventLabel || 'Selected event'}} · anchor ${{data.event_time_local || data.event_time_utc}}`;
    }}

    const logs = data.logs || [];
    if (!logs.length) {{
      body.innerHTML = `
        <div class="card" style="margin:0;">
          <h3>No router logs found in this window</h3>
          <p class="small">Window: ${{escapeHtml(data.window_start_local || data.window_start_utc)}} → ${{escapeHtml(data.window_end_local || data.window_end_utc)}}</p>
          <p class="small">${{Number(data.cached_candidate_count || 0) > 0 ? 'No logs were found inside this exact window, but cached router logs do exist near this date. Try Selected day, Expand ±1 day, or a neighboring day.' : 'This usually means router logging was not enabled in NCM for this router/group, no logs were produced near this event, or the daily chart bucket is landing on the neighboring UTC/local day.'}}</p>
          <p class="small">Live NCM rows fetched: ${{data.fetched_live_count ?? 'n/a'}}<br>
          Fetch mode: ${{escapeHtml(data.live_fetch_mode || 'unknown')}}<br>
          Cached rows near this window: ${{data.cached_candidate_count ?? 'n/a'}}${{data.cached_candidate_min_local ? '<br>Nearest cached range checked: ' + escapeHtml(data.cached_candidate_min_local) + ' → ' + escapeHtml(data.cached_candidate_max_local || '') : ''}}${{data.live_fetch_error ? '<br>Live fetch warning: ' + escapeHtml(String(data.live_fetch_error).slice(0, 300)) : ''}}</p>
          <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px;">
            <button onclick="eventContextShiftAnchorDays(-1)" style="width:auto;margin:0;">Try previous day</button>
            <button onclick="eventContextShiftAnchorDays(1)" style="width:auto;margin:0;">Try next day</button>
            <button onclick="eventContextExpandBoth(1440)" style="width:auto;margin:0;">Expand ±1 day</button>
          </div>
        </div>
      `;
      return;
    }}

    body.innerHTML = `
      <div class="card" style="margin:0 0 12px 0;">
        <h3 style="margin-top:0;">${{contextMode === 'daily' ? 'Router logs for selected chart day' : 'Closest router logs around selected event'}}</h3>
        <p class="small">Window: ${{escapeHtml(data.window_start_local || data.window_start_utc)}} → ${{escapeHtml(data.window_end_local || data.window_end_utc)}}<br>
        Logs found: ${{logs.length}}. These logs are context only; they do not prove cause.</p>
        ${{data.future_capped ? '<div class="small" style="color:#facc15;margin-top:8px;padding:10px 12px;border:1px solid rgba(250,204,21,.28);border-radius:10px;background:rgba(250,204,21,.08);">Post-event window was capped at the current time because future logs are not available yet.<br><button onclick="eventContextPullLatestLogs()" style="width:auto;margin-top:8px;">Pull latest NCM logs</button></div>' : ''}}
        ${{data.live_fetch_error ? `<p class="small" style="color:#facc15;margin-top:8px;">Live NCM log fetch could not reach NCM for this window. Showing locally cached logs only.<br><span style="color:#cbd5e1;">${{String(data.live_fetch_error).includes('Temporary failure in name resolution') ? 'Detected temporary DNS/name-resolution failure on the app host.' : escapeHtml(String(data.live_fetch_error).slice(0, 300))}}</span></p>` : ''}}
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:10px;">
          <button onclick="eventContextJumpToNearest()" style="width:auto;margin:0;">Jump to selected time</button>
          <button onclick="eventContextJumpToLatest()" style="width:auto;margin:0;">Jump to latest log</button>
          <button onclick="eventContextExportCsv()" style="width:auto;margin:0;">Export CSV</button>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:10px;padding-top:10px;border-top:1px solid rgba(148,163,184,.18);">
          <span class="small" style="align-self:center;">Expand window:</span>
          <button onclick="eventContextExpandBefore(60)" style="width:auto;margin:0;">+1h before</button>
          <button onclick="eventContextExpandAfter(60)" style="width:auto;margin:0;">+1h after</button>
          <button onclick="eventContextSelectedDay()" style="width:auto;margin:0;">Selected day</button>
          <button onclick="eventContextExpandBoth(1440)" style="width:auto;margin:0;">±1 day</button>
        </div>
      </div>
      ${{logs.map((log, idx) => renderEventContextLogRow(log, contextMode, idx, logs.length)).join('')}}
    `;

    setTimeout(() => {{
      eventContextJumpToNearest();
      eventContextUpdateCompass();
    }}, 120);
  }} catch (err) {{
    if (subtitle) subtitle.textContent = `${{eventLabel || 'Selected event'}} · failed`;
    if (body) body.innerHTML = `
      <div class="card" style="margin:0;">
        <h3>Event context failed</h3>
        <p class="small">${{escapeHtml(err.message || String(err))}}</p>
      </div>
    `;
  }}
}}

async function loadUsageReport() {{
  if (window.usageReportRunning) return;
  window.usageReportRunning = true;

  const days = document.getElementById('usageDays').value;
  const status = document.getElementById('usageReportStatus');
  const box = document.getElementById('usageReport');
  const btn = document.querySelector('button[onclick="loadUsageReport()"]');

  if (btn) btn.disabled = true;
  status.innerText = 'Pulling live usage and state samples...';
  box.innerHTML = '';

  try {{
    const profileId = getRouterPageProfileId();
    const res = await fetch(`/router/{router_id}/usage-report?days=${{encodeURIComponent(days)}}&profile_id=${{encodeURIComponent(profileId)}}`, {{
      credentials: 'same-origin',
      redirect: 'follow',
      headers: {{ 'Accept': 'application/json' }}
    }});

    const contentType = res.headers.get('content-type') || '';

    if (!res.ok || !contentType.includes('application/json')) {{
      const text = await res.text();
      status.innerText = 'Usage report failed.';
      box.innerHTML = `
        <div class="card">
          <h3>Usage report failed</h3>
          <p class="small">The server did not return a valid JSON usage report. This usually means the request was redirected to login, the router is not accessible under this dashboard profile, or NCM returned an access error.</p>
          <pre class="small" style="max-height:220px; overflow:auto; white-space:pre-wrap;">${{escapeHtml(text.slice(0, 2000))}}</pre>
        </div>
      `;
      return;
    }}

    const r = await res.json();
  status.innerText = r.clamped
    ? `Report complete. Window was safely clamped to available retention. Since: ${{r.since_utc}}`
    : `Report complete. Since: ${{r.since_utc}}`;

  const simRows = (r.sim_reports || []).map(s => `
    <tr>
      <td>${{s.sim_label || ''}}</td>
      <td>${{s.carrier || 'Unknown'}}</td>
      <td>${{s.connection_state || 'Unknown'}}</td>
      <td>${{s.sample_count}}</td>
      <td>${{s.in_human}}</td>
      <td>${{s.out_human}}</td>
      <td>${{s.total_human}}</td>
      <td>${{s.direction}}</td>
    </tr>
  `).join('');

  box.innerHTML = `
    <div class="grid" style="margin-top:12px;">
      <div class="card"><h3>Total WAN Usage</h3><div class="pill">${{r.totals.wan_total_human}}</div><p class="small">In: ${{r.totals.wan_in_human}} | Out: ${{r.totals.wan_out_human}}<br>${{r.directions.wan}}</p></div>
      <div class="card"><h3>NCM Router Stream</h3><div class="pill">${{r.totals.ncm_total_human}}</div><p class="small">In: ${{r.totals.ncm_in_human}} | Out: ${{r.totals.ncm_out_human}}<br>${{(r.sample_counts && r.sample_counts.router_stream_usage) ? (r.percentages.ncm_percent_of_wan + '% of observed WAN usage.') : 'No router-stream samples returned for this window/profile.'}}</p></div>
      <div class="card"><h3>Uncategorized Usage</h3><div class="pill">${{r.totals.uncategorized_total_human}}</div><p class="small">In: ${{r.totals.uncategorized_in_human}} | Out: ${{r.totals.uncategorized_out_human}}<br>${{r.percentages.uncategorized_percent_of_wan}}% of observed WAN usage.</p></div>
      <div class="card"><h3>NCM Availability Story</h3><div class="pill">${{r.state_summary.availability_pct ?? 'n/a'}}%</div><p class="small">Offline events: ${{r.state_summary.offline_events}} | Offline hours: ${{r.state_summary.offline_hours}}</p></div>
    </div>
    <p>${{r.story.narrative}}</p>
    <p class="small">Reconnect churn: ${{r.story.reconnect_churn ? 'Yes' : 'No'}} | Poor signal indicator: ${{r.story.poor_signal ? 'Yes' : 'No'}} | Longest offline: ${{r.state_summary.longest_offline_minutes}} minutes</p>
    <table style="width:100%; border-collapse:collapse; margin-top:12px;">
      <thead><tr><th align="left">SIM</th><th align="left">Carrier</th><th align="left">State</th><th align="left">Samples</th><th align="left">Inbound</th><th align="left">Outbound</th><th align="left">Total</th><th align="left">Direction</th></tr></thead>
      <tbody>${{simRows || '<tr><td colspan="8">No SIM usage samples returned.</td></tr>'}}</tbody>
    </table>
  `;

  // renderUsageBreakdownChart disabled for v4.1.0 bugfix.
  }} catch (e) {{
    status.innerText = 'Usage report failed.';
    box.innerHTML = `<div class="card"><h3>Usage report failed</h3><p class="small">${{escapeHtml(e.message || String(e))}}</p></div>`;
  }} finally {{
    window.usageReportRunning = false;
    if (btn) btn.disabled = false;
  }}
}}

function exportUsageReport() {{
  const days = document.getElementById('usageDays').value;
  const profileId = getRouterPageProfileId();
  window.location = `/router/{router_id}/usage-report/export.xlsx?days=${{encodeURIComponent(days)}}&profile_id=${{encodeURIComponent(profileId)}}`;
}}

function renderUsageBreakdownChart(r) {{
  const box = document.getElementById('usageBreakdownChartBox');
  const canvas = document.getElementById('usageBreakdownChart');
  if (!canvas) return;
  if (box) box.style.display = 'block';
  canvas.style.maxHeight = '260px';
  if (window.usageBreakdownChartObj) {{
    window.usageBreakdownChartObj.destroy();
    window.usageBreakdownChartObj = null;
  }}
  window.usageBreakdownChartObj = new Chart(canvas, {{
    type: 'bar',
    data: {{
      labels: ['Usage Breakdown'],
      datasets: [
        {{ label: 'NCM/router stream GB', data: [r.totals.ncm_total_gb] }},
        {{ label: 'Uncategorized GB', data: [r.totals.uncategorized_gb] }}
      ]
    }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      devicePixelRatio: window.devicePixelRatio || 2,
      plugins: {{ legend: {{ labels: {{ color: '#e5e7eb' }} }} }},
      scales: {{
        x: {{ stacked: true, ticks: {{ color: '#94a3b8' }} }},
        y: {{ stacked: true, ticks: {{ color: '#94a3b8' }} }}
      }}
    }}
  }});
}}

loadRouter();
</script>


<script src="/api/odometer.js"></script>
<script src="/api/profile-header.js"></script>
</body>
</html>
    """


# =============================================================================
# Resumable Router Deep Dive Batch Jobs
# =============================================================================


def ensure_report_library_tables():
    Path(f"{BASE_DIR}/data/reports").mkdir(parents=True, exist_ok=True)

    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS exported_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id INTEGER NOT NULL DEFAULT 1,
                job_id TEXT,
                report_type TEXT,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                dashboard_name TEXT,
                days INTEGER,
                modules_json TEXT,
                router_count INTEGER DEFAULT 0
            )
        """)
        conn.commit()



def normalize_deep_dive_job_profiles():
    try:
        with db() as conn:
            conn.execute("UPDATE deep_dive_jobs SET profile_id = 1 WHERE profile_id IS NULL OR profile_id = 0")
            conn.commit()
    except Exception:
        pass


def ensure_deep_dive_job_tables():
    import sqlite3
    ensure_report_library_tables()
    normalize_deep_dive_job_profiles()
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS deep_dive_jobs (
                job_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                days INTEGER NOT NULL,
                modules_json TEXT NOT NULL,
                total INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                current_identifier TEXT,
                delay_ms INTEGER NOT NULL DEFAULT 500,
                note TEXT
            )
        """)
        # Idempotent migrations for fresh installs and upgrades.
        job_cols = [r[1] for r in conn.execute("PRAGMA table_info(deep_dive_jobs)").fetchall()]
        if "profile_id" not in job_cols:
            conn.execute("ALTER TABLE deep_dive_jobs ADD COLUMN profile_id INTEGER")
        if "delay_ms" not in job_cols:
            conn.execute("ALTER TABLE deep_dive_jobs ADD COLUMN delay_ms INTEGER NOT NULL DEFAULT 250")
        if "note" not in job_cols:
            conn.execute("ALTER TABLE deep_dive_jobs ADD COLUMN note TEXT")
        if "started_at" not in job_cols:
            conn.execute("ALTER TABLE deep_dive_jobs ADD COLUMN started_at TEXT")
        if "finished_at" not in job_cols:
            conn.execute("ALTER TABLE deep_dive_jobs ADD COLUMN finished_at TEXT")
        if "error" not in job_cols:
            conn.execute("ALTER TABLE deep_dive_jobs ADD COLUMN error TEXT")

        default_profile_id = get_default_profile_id_for_schema()
        conn.execute(
            "UPDATE deep_dive_jobs SET profile_id = ? WHERE profile_id IS NULL OR profile_id = 0",
            (default_profile_id,),
        )

        conn.execute("""
            CREATE TABLE IF NOT EXISTS deep_dive_job_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                position INTEGER NOT NULL,
                identifier TEXT NOT NULL,
                router_id TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                result_json TEXT,
                error TEXT,
                started_at TEXT,
                finished_at TEXT,
                UNIQUE(job_id, identifier)
            )
        """)


async def run_deep_dive_job_worker(job_id: str):
    import json
    import asyncio

    ensure_deep_dive_job_tables()

    with db() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM deep_dive_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if not row:
            return
        modules = json.loads(row["modules_json"])
        days = int(row["days"])
        delay_ms = int(row["delay_ms"] or 500)
        profile_id = int(row["profile_id"] or get_default_profile_id())

        conn.execute("""
            UPDATE deep_dive_jobs
            SET status = 'running', started_at = COALESCE(started_at, ?), updated_at = ?
            WHERE job_id = ?
              AND status IN ('queued', 'paused', 'running')
        """, (now_utc(), now_utc(), job_id))

        conn.execute("""
            UPDATE deep_dive_job_items
            SET status = 'pending'
            WHERE job_id = ?
              AND status = 'running'
        """, (job_id,))

    while True:
        with db() as conn:
            job = conn.execute("SELECT status FROM deep_dive_jobs WHERE job_id = ?", (job_id,)).fetchone()
            if not job or job[0] in ("cancelled", "complete"):
                return

            item = conn.execute("""
                SELECT id, identifier, attempts
                FROM deep_dive_job_items
                WHERE job_id = ?
                  AND status = 'pending'
                ORDER BY position ASC
                LIMIT 1
            """, (job_id,)).fetchone()

            if not item:
                counts = job_counts(job_id)
                final_status = "complete" if counts["pending"] == 0 and counts["running"] == 0 else "paused"
                conn.execute("""
                    UPDATE deep_dive_jobs
                    SET status = ?, finished_at = ?, updated_at = ?, current_identifier = NULL
                    WHERE job_id = ?
                """, (final_status, now_utc(), now_utc(), job_id))
                return

            item_id, identifier, attempts = item
            conn.execute("""
                UPDATE deep_dive_job_items
                SET status = 'running', attempts = attempts + 1, started_at = ?, error = NULL
                WHERE id = ?
            """, (now_utc(), item_id))
            conn.execute("""
                UPDATE deep_dive_jobs
                SET current_identifier = ?, updated_at = ?
                WHERE job_id = ?
            """, (identifier, now_utc(), job_id))

        try:
            batch = await build_router_deep_dive_reports([identifier], days, modules, profile_id=profile_id)
            result_item = (batch.get("results") or [{}])[0]

            router_id = None
            if result_item.get("report"):
                router_id = result_item["report"].get("router_id")
            elif result_item.get("router_id"):
                router_id = result_item.get("router_id")

            if result_item.get("error"):
                with db() as conn:
                    conn.execute("""
                        UPDATE deep_dive_job_items
                        SET status = 'error', router_id = ?, result_json = ?, error = ?, finished_at = ?
                        WHERE id = ?
                    """, (router_id, json.dumps(result_item), str(result_item.get("error")), now_utc(), item_id))
            else:
                with db() as conn:
                    conn.execute("""
                        UPDATE deep_dive_job_items
                        SET status = 'complete', router_id = ?, result_json = ?, error = NULL, finished_at = ?
                        WHERE id = ?
                    """, (router_id, json.dumps(result_item), now_utc(), item_id))

        except Exception as e:
            with db() as conn:
                conn.execute("""
                    UPDATE deep_dive_job_items
                    SET status = 'error', error = ?, finished_at = ?
                    WHERE id = ?
                """, (str(e), now_utc(), item_id))

        with db() as conn:
            conn.execute("""
                UPDATE deep_dive_jobs
                SET updated_at = ?
                WHERE job_id = ?
            """, (now_utc(), job_id))

        if delay_ms > 0:
            await asyncio.sleep(delay_ms / 1000)


def job_counts(job_id: str):
    ensure_deep_dive_job_tables()
    with db() as conn:
        rows = conn.execute("""
            SELECT status, COUNT(*)
            FROM deep_dive_job_items
            WHERE job_id = ?
            GROUP BY status
        """, (job_id,)).fetchall()

    counts = {"pending": 0, "running": 0, "complete": 0, "error": 0}
    for status, count in rows:
        counts[status] = count
    counts["done"] = counts["complete"] + counts["error"]
    return counts




@app.get("/api/reports")
async def list_exported_reports(profile_id: int = Query(default=None)):
    ensure_report_library_tables()
    profile_id = 1

    with db() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT id, profile_id, job_id, report_type, filename, created_at,
                   dashboard_name, days, modules_json, router_count
            FROM exported_reports
            WHERE profile_id = ?
            ORDER BY created_at DESC
            LIMIT 100
        """, (profile_id,)).fetchall()

    return {"reports": [dict(r) for r in rows], "profile_id": profile_id}


@app.get("/api/reports/{report_id}/download")
async def download_exported_report(report_id: int):
    ensure_report_library_tables()

    with db() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("""
            SELECT filename, file_path
            FROM exported_reports
            WHERE id = ?
        """, (report_id,)).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Report not found.")

    path = Path(row["file_path"])
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report file missing on disk.")

    return FileResponse(
        path=str(path),
        filename=row["filename"],
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )



@app.post("/deep-dive-jobs/start")
async def start_deep_dive_job(payload: dict = Body(default={})):
    import json
    import uuid
    import asyncio

    ensure_deep_dive_job_tables()

    identifiers = parse_router_ids(payload.get("router_ids_text", ""))
    raw_modules = payload.get("modules") or ["signal", "geo", "usage", "alerts"]
    module_map = {
        "signal": "signal_health",
        "signal_health": "signal_health",
        "geo": "geo_location",
        "location": "geo_location",
        "geo_location": "geo_location",
        "usage": "data_usage",
        "data_usage": "data_usage",
        "alerts": "alerts",
        "failover": "failover",
    }
    modules = []
    for m in raw_modules:
        normalized = module_map.get(str(m).strip())
        if normalized and normalized not in modules:
            modules.append(normalized)

    days = int(payload.get("days") or 30)
    delay_ms = int(payload.get("delay_ms") or 500)
    note = str(payload.get("note") or "")
    profile_id = payload_profile_id(payload)

    if days not in [7, 15, 30, 90]:
        raise HTTPException(status_code=400, detail="days must be 7, 15, 30, or 90")
    if not identifiers:
        raise HTTPException(status_code=400, detail="No router IDs/names were provided.")
    if not modules:
        raise HTTPException(status_code=400, detail="At least one module is required.")

    job_id = str(uuid.uuid4())
    ts = now_utc()

    with db() as conn:
        conn.execute("""
            INSERT INTO deep_dive_jobs(job_id, status, days, modules_json, total, created_at, updated_at, delay_ms, note, profile_id)
            VALUES (?, 'queued', ?, ?, ?, ?, ?, ?, ?, ?)
        """, (job_id, days, json.dumps(modules), len(identifiers), ts, ts, delay_ms, note, profile_id))

        for idx, identifier in enumerate(identifiers, start=1):
            conn.execute("""
                INSERT OR IGNORE INTO deep_dive_job_items(job_id, position, identifier, status)
                VALUES (?, ?, ?, 'pending')
            """, (job_id, idx, identifier))

    asyncio.create_task(run_deep_dive_job_worker(job_id))
    return {"job_id": job_id, "status": "queued", "total": len(identifiers)}


@app.get("/deep-dive-jobs/{job_id}/status")
async def deep_dive_job_status(job_id: str):
    import json

    ensure_deep_dive_job_tables()
    with db() as conn:
        conn.row_factory = sqlite3.Row
        job = conn.execute("SELECT * FROM deep_dive_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found.")

        counts = job_counts(job_id)
        total = int(job["total"] or 0)
        pct = round((counts["done"] / total) * 100, 1) if total else 0

        recent = conn.execute("""
            SELECT position, identifier, router_id, status, attempts, error, started_at, finished_at
            FROM deep_dive_job_items
            WHERE job_id = ?
            ORDER BY
                CASE status
                    WHEN 'running' THEN 1
                    WHEN 'error' THEN 2
                    WHEN 'complete' THEN 3
                    ELSE 4
                END,
                position DESC
            LIMIT 25
        """, (job_id,)).fetchall()

    out = dict(job)
    out["modules"] = json.loads(out.pop("modules_json") or "[]")
    out["counts"] = counts
    out["percent_complete"] = pct
    out["recent_items"] = [dict(x) for x in recent]
    return out


@app.post("/deep-dive-jobs/{job_id}/resume")
async def resume_deep_dive_job(job_id: str):
    import asyncio

    ensure_deep_dive_job_tables()
    with db() as conn:
        job = conn.execute("SELECT status FROM deep_dive_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found.")

        conn.execute("""
            UPDATE deep_dive_job_items
            SET status = 'pending'
            WHERE job_id = ?
              AND status = 'running'
        """, (job_id,))

        conn.execute("""
            UPDATE deep_dive_jobs
            SET status = 'queued', updated_at = ?
            WHERE job_id = ?
              AND status IN ('queued', 'running', 'paused')
        """, (now_utc(), job_id))

    asyncio.create_task(run_deep_dive_job_worker(job_id))
    return {"job_id": job_id, "status": "resumed"}


@app.post("/deep-dive-jobs/{job_id}/cancel")
async def cancel_deep_dive_job(job_id: str):
    ensure_deep_dive_job_tables()
    with db() as conn:
        conn.execute("""
            UPDATE deep_dive_jobs
            SET status = 'cancelled', updated_at = ?, finished_at = COALESCE(finished_at, ?)
            WHERE job_id = ?
        """, (now_utc(), now_utc(), job_id))
        conn.execute("""
            UPDATE deep_dive_job_items
            SET status = 'pending'
            WHERE job_id = ?
              AND status = 'running'
        """, (job_id,))
    return {"job_id": job_id, "status": "cancelled"}


@app.get("/deep-dive-jobs/latest")
async def latest_deep_dive_job(profile_id: int = Query(default=None)):
    ensure_deep_dive_job_tables()
    profile_id = 1

    with db() as conn:
        conn.row_factory = sqlite3.Row
        job = conn.execute("""
            SELECT job_id
            FROM deep_dive_jobs
            WHERE COALESCE(profile_id, 1) = ?
            ORDER BY created_at DESC
            LIMIT 1
        """, (profile_id,)).fetchone()

    if not job:
        return {"job_id": None, "profile_id": profile_id}

    return await deep_dive_job_status(job["job_id"])


@app.get("/deep-dive-jobs/{job_id}/export.xlsx")
async def export_deep_dive_job_xlsx(job_id: str):
    import json
    import io
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter

    ensure_deep_dive_job_tables()

    # Deep-dive jobs currently write to the legacy operational DB.
    # Keep export on the same DB until full per-dashboard DB migration is complete.
    with db() as conn:
        conn.row_factory = sqlite3.Row
        job = conn.execute("SELECT * FROM deep_dive_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found.")
        profile_id = int(job["profile_id"] or get_default_profile_id())

        items = conn.execute("""
            SELECT *
            FROM deep_dive_job_items
            WHERE job_id = ?
            ORDER BY position ASC
        """, (job_id,)).fetchall()

    wb = Workbook()
    ws = wb.active
    ws.title = "Executive Summary"

    dark = PatternFill("solid", fgColor="1F2937")
    blue = PatternFill("solid", fgColor="2563EB")
    light = PatternFill("solid", fgColor="E5E7EB")
    white_font = Font(color="FFFFFF", bold=True)
    bold = Font(bold=True)
    thin = Side(style="thin", color="CBD5E1")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)

    counts = job_counts(job_id)

    ws["A1"] = "Router Deep Dive Batch Report"
    ws["A1"].font = Font(size=18, bold=True, color="FFFFFF")
    ws["A1"].fill = blue
    ws.merge_cells("A1:F1")

    profile_meta = get_dashboard_profile_metadata(profile_id) if "get_dashboard_profile_metadata" in globals() else {"name": f"Dashboard {profile_id}"}

    summary_rows = [
        ("Account", profile_meta.get("name") or f"Dashboard {profile_id}"),
        ("Company", profile_meta.get("company_name") or ""),
        ("Purpose", profile_meta.get("purpose") or profile_meta.get("description") or ""),
        ("Job ID", job_id),
        ("Status", job["status"]),
        ("Created", job["created_at"]),
        ("Updated", job["updated_at"]),
        ("Days", job["days"]),
        ("Total Routers", job["total"]),
        ("Complete", counts["complete"]),
        ("Errors", counts["error"]),
        ("Pending", counts["pending"]),
        ("Running", counts["running"]),
    ]

    row = 3
    for k, v in summary_rows:
        ws.cell(row=row, column=1, value=k).font = bold
        ws.cell(row=row, column=2, value=v)
        row += 1

    detail = wb.create_sheet("Router Summary")
    headers = [
        "Position", "Identifier", "Router ID", "Status", "Attempts",
        "Signal", "Location",
        "WAN In", "WAN Out", "WAN Total",
        "NCM In", "NCM Out", "NCM Total",
        "Uncategorized In", "Uncategorized Out", "Uncategorized Total",
        "NCM %", "Uncategorized %",
        "SIM1 In", "SIM1 Out", "SIM1 Total",
        "SIM2 In", "SIM2 Out", "SIM2 Total",
        "Online Events", "Offline Events", "Online Hours", "Offline Hours",
        "Longest Offline Minutes", "Availability %",
        "Alerts", "Failover Records", "Failover Days", "Peak Failover Day", "SIM1→SIM2", "SIM2→SIM1", "Latest Alert Type", "Summary", "Error"
    ]
    detail.append(headers)
    for cell in detail[1]:
        cell.fill = dark
        cell.font = white_font
        cell.alignment = Alignment(horizontal="center")

    for item in items:
        report = {}
        err = item["error"] or ""
        if item["result_json"]:
            try:
                result = json.loads(item["result_json"])
                report = result.get("report") or {}
            except Exception:
                report = {}

        usage = report.get("data_usage") or {}
        totals = usage.get("totals") or {}
        state_summary = usage.get("state_summary") or {}
        signal = report.get("signal_health") or {}
        geo = report.get("geo_location") or {}
        alerts = report.get("alerts") or {}

        # Full-fidelity batch summary row. This intentionally reads the same
        # data_usage object produced by router_usage_report(), which powers the
        # flawless single-router report.
        percentages = usage.get("percentages") or {}
        sim_usage = usage.get("sim_reports") or usage.get("sim_usage") or usage.get("sims") or []
        if isinstance(sim_usage, dict):
            sim_usage = list(sim_usage.values())

        sim1 = {}
        sim2 = {}
        for sim in sim_usage:
            label = str(sim.get("sim_label") or sim.get("label") or sim.get("name") or "").upper()
            if "SIM1" in label:
                sim1 = sim
            elif "SIM2" in label:
                sim2 = sim

        signal_sims = signal.get("sims") or []
        sig1 = {}
        sig2 = {}
        for sig in signal_sims:
            label = str(sig.get("sim_label") or sig.get("label") or sig.get("name") or "").upper()
            if "SIM1" in label:
                sig1 = sig
            elif "SIM2" in label:
                sig2 = sig

        detail.append([
            item["position"],
            item["identifier"],
            item["router_id"] or report.get("router_id") or "",
            item["status"],
            item["attempts"],
            signal.get("overall", "") + (
                f" | SIM1 RSRP {sig1.get('avg_rsrp')} SINR {sig1.get('avg_sinr')}" if sig1 else ""
            ) + (
                f" | SIM2 RSRP {sig2.get('avg_rsrp')} SINR {sig2.get('avg_sinr')}" if sig2 else ""
            ),
            geo.get("label") or geo.get("method") or "",
            totals.get("wan_in_human") or totals.get("wan_bytes_in_human") or "",
            totals.get("wan_out_human") or totals.get("wan_bytes_out_human") or "",
            totals.get("wan_total_human", ""),
            totals.get("ncm_in_human") or totals.get("ncm_bytes_in_human") or "",
            totals.get("ncm_out_human") or totals.get("ncm_bytes_out_human") or "",
            totals.get("ncm_total_human", ""),
            totals.get("uncategorized_in_human") or totals.get("uncategorized_bytes_in_human") or "",
            totals.get("uncategorized_out_human") or totals.get("uncategorized_bytes_out_human") or "",
            totals.get("uncategorized_total_human", ""),
            percentages.get("ncm_percent_of_wan", ""),
            percentages.get("uncategorized_percent_of_wan", ""),
            sim1.get("bytes_in_human") or sim1.get("in_human") or human_bytes(sim1.get("bytes_in") or 0) if sim1 else "",
            sim1.get("bytes_out_human") or sim1.get("out_human") or human_bytes(sim1.get("bytes_out") or 0) if sim1 else "",
            sim1.get("total_human") or sim1.get("total_bytes_human") or human_bytes(sim1.get("total_bytes") or 0) if sim1 else "",
            sim2.get("bytes_in_human") or sim2.get("in_human") or human_bytes(sim2.get("bytes_in") or 0) if sim2 else "",
            sim2.get("bytes_out_human") or sim2.get("out_human") or human_bytes(sim2.get("bytes_out") or 0) if sim2 else "",
            sim2.get("total_human") or sim2.get("total_bytes_human") or human_bytes(sim2.get("total_bytes") or 0) if sim2 else "",
            state_summary.get("online_events", ""),
            state_summary.get("offline_events", ""),
            state_summary.get("online_hours", ""),
            state_summary.get("offline_hours", ""),
            state_summary.get("longest_offline_minutes", ""),
            state_summary.get("availability_pct", ""),
            alerts.get("total_alerts", ""),
            (alerts.get("failover_summary") or {}).get("alert_records", ""),
            (alerts.get("failover_summary") or {}).get("distinct_failover_days", ""),
            (alerts.get("failover_summary") or {}).get("most_failovers_one_day", ""),
            (alerts.get("failover_summary") or {}).get("sim1_to_sim2", ""),
            (alerts.get("failover_summary") or {}).get("sim2_to_sim1", ""),
            alerts.get("latest_type", ""),
            report.get("summary", ""),
            err,
        ])

    detail.auto_filter.ref = detail.dimensions
    detail.freeze_panes = "A2"

    errors = wb.create_sheet("Errors")
    errors.append(["Position", "Identifier", "Router ID", "Attempts", "Error"])
    for cell in errors[1]:
        cell.fill = dark
        cell.font = white_font
    for item in items:
        if item["status"] == "error":
            errors.append([item["position"], item["identifier"], item["router_id"], item["attempts"], item["error"]])

    for sheet in wb.worksheets:
        for row_cells in sheet.iter_rows():
            for cell in row_cells:
                cell.border = border
                cell.alignment = Alignment(vertical="top", wrap_text=True)
        for col in range(1, min(sheet.max_column, 20) + 1):
            letter = get_column_letter(col)
            sheet.column_dimensions[letter].width = min(max(14, len(str(sheet.cell(1, col).value or "")) + 4), 42)

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)

    filename = f"router_deep_dive_job_{job_id[:8]}.xlsx"
    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.get("/deep-dive-jobs-ui", response_class=HTMLResponse)
async def deep_dive_jobs_ui():
    return """
<!DOCTYPE html>
<html>
<head>
  <title>Router Deep Dive Batch Jobs</title>
  <style>
    body { font-family: Arial, sans-serif; background:#0f172a; color:#e5e7eb; padding:28px; }
    .card { background:#111827; border:1px solid #1f2937; border-radius:18px; padding:16px; margin-bottom:16px; }
    textarea, select, input { background:#020617; color:#e5e7eb; border:1px solid #334155; border-radius:10px; padding:10px; }
    textarea { width:100%; min-height:170px; box-sizing:border-box; }
    button { background:#1e293b; color:#e5e7eb; border:1px solid #334155; border-radius:999px; padding:9px 13px; cursor:pointer; margin:4px; }
    button.primary { background:#2563eb; border-color:#60a5fa; }
    button.danger { border-color:#fb7185; }
    .small { color:#94a3b8; font-size:13px; }
    .bar { height:22px; background:#020617; border:1px solid #334155; border-radius:999px; overflow:hidden; }
    .fill { height:100%; background:#2563eb; width:0%; transition:width .3s; }
    table { width:100%; border-collapse:collapse; margin-top:12px; }
    th, td { border:1px solid #334155; padding:8px; vertical-align:top; }
    th { background:#1f2937; }
    .ok { color:#22c55e; font-weight:bold; }
    .err { color:#fb7185; font-weight:bold; }
  </style>
</head>
<body>
<div id="activeProfileBranding" style="margin:18px 18px 10px 18px;background:linear-gradient(135deg,#102042,#0b1220);border:1px solid #263449;border-radius:20px;padding:18px 20px;display:flex;align-items:center;gap:16px;box-shadow:0 18px 40px rgba(0,0,0,.28);">
  <div id="activeProfileLogoBox" style="width:76px;height:76px;border-radius:18px;background:#020617;border:1px solid #334155;display:flex;align-items:center;justify-content:center;overflow:hidden;font-size:32px;font-weight:900;color:#60a5fa;flex:0 0 auto;">?</div>
  <div>
    <div id="activeProfileName" style="font-size:28px;font-weight:900;line-height:1.1;">Dashboard</div>
    <div id="activeProfileCompany" style="font-size:14px;color:#93c5fd;margin-top:4px;"></div>
    <div id="activeProfilePurpose" style="font-size:13px;color:#cbd5e1;margin-top:6px;"></div>
  </div>
</div>

<a id="dashboardSwitcher" href="/launcher" style="position:fixed;top:18px;left:22px;z-index:999998;background:linear-gradient(135deg,#2563eb,#1d4ed8);color:white;text-decoration:none;border-radius:14px;padding:10px 14px;font-weight:800;font-size:13px;box-shadow:0 14px 30px rgba(0,0,0,.30);border:1px solid rgba(255,255,255,.16);">Switch Dashboard</a>

<div id="apiOdometer" aria-label="NCM API odometer" style="position:fixed;top:18px;right:22px;z-index:999999;width:230px;background:linear-gradient(135deg,rgba(15,23,42,.98),rgba(30,64,105,.98));color:#f8fafc;border:1px solid rgba(255,255,255,.18);border-radius:18px;padding:13px 15px;box-shadow:0 18px 42px rgba(0,0,0,.35);text-align:right;font-family:inherit;">
  <div style="font-size:11px;font-weight:800;letter-spacing:.07em;text-transform:uppercase;opacity:.82;">NCM API Odometer</div>
  <div id="odoMonth" style="margin-top:3px;font-size:30px;line-height:1;font-weight:900;">0</div>
  <div style="margin-top:3px;font-size:11px;opacity:.72;">This Month</div>
  <div style="margin-top:8px;padding-top:8px;border-top:1px solid rgba(255,255,255,.15);font-size:11px;opacity:.85;">Today: <span id="odoToday">0</span> · Lifetime: <span id="odoLifetime">0</span></div>
</div>







  <h1>Router Deep Dive Batch Jobs</h1>
  <p class="small">Resumable server-side deep dives for large router batches. Completed routers are saved as each unit finishes.</p>

  <div class="card">
    <h2>Start Batch Job</h2>
    <textarea id="routers" placeholder="Paste router IDs or names, one per line..."></textarea><br>
    <input type="file" onchange="loadFile(event)">
    <p>
      Days:
      <select id="days">
        <option value="7">7</option>
        <option value="15">15</option>
        <option value="30" selected>30</option>
        <option value="90">90</option>
      </select>
      Delay between routers:
      <select id="delay">
        <option value="250">250 ms</option>
        <option value="500" selected>500 ms</option>
        <option value="1000">1 sec</option>
        <option value="2000">2 sec</option>
      </select>
    </p>
    <p>
      <label><input type="checkbox" class="mod" value="signal" checked> Signal Health</label>
      <label><input type="checkbox" class="mod" value="geo" checked> Geo Location</label>
      <label><input type="checkbox" class="mod" value="usage" checked> Data Usage</label>
      <label><input type="checkbox" class="mod" value="alerts" checked> Alerts</label>
      <label><input type="checkbox" class="mod" value="failover" checked> Failover Analysis</label>
    </p>
    <button class="primary" onclick="startJob()">Start Job</button>
    <button onclick="loadLatest()">Load Latest Job</button>
    <button onclick="resumeJob()">Resume</button>
    <button class="danger" onclick="cancelJob()">Cancel</button>
    <button onclick="exportJob()">Export XLSX</button>
    <button onclick="window.location='/ui?profile_id=' + encodeURIComponent(activeProfileId())">Back to Dashboard</button>
  </div>

  <div class="card">
    <h2>Progress</h2>
    <div id="jobId" class="small">No job loaded.</div>
    <div class="bar"><div id="fill" class="fill"></div></div>
    <h2 id="pct">0%</h2>
    <div id="stats" class="small"></div>
    <div id="recent"></div>
  </div>

<script>
let currentJobId = null;
let timer = null;
let pollInFlight = false;

function activeProfileId() {{
  const params = new URLSearchParams(window.location.search);
  const pid = params.get('profile_id') || localStorage.getItem('ncm_active_profile_id') || '1';
  localStorage.setItem('ncm_active_profile_id', String(pid));
  return String(pid);
}}

function lastJobKey() {
  return 'lastDeepDiveJobId_' + activeProfileId();
}

async function loadFile(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  const text = await file.text();
  const box = document.getElementById('routers');
  box.value = (box.value.trim() ? box.value.trim() + '\\n' : '') + text.trim();
}

function payload() {
  return {
    profile_id: Number(activeProfileId()),
    router_ids_text: document.getElementById('routers').value,
    days: Number(document.getElementById('days').value),
    delay_ms: Number(document.getElementById('delay').value),
    modules: Array.from(document.querySelectorAll('.mod:checked')).map(x => x.value)
  };
}

async function startJob() {
  const res = await fetch('/deep-dive-jobs/start', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify(payload())
  });
  if (!res.ok) return alert(await res.text());
  const data = await res.json();
  currentJobId = data.job_id;
  poll();
  if (timer) clearInterval(timer);
  timer = setInterval(poll, 7000);
}

async function loadLatest() {
  const res = await fetch('/deep-dive-jobs/latest?profile_id=' + encodeURIComponent(activeProfileId()), {cache:'no-store'});
  const data = await res.json();
  if (!data.job_id) {
    currentJobId = null;
    document.getElementById('jobId').textContent = 'No jobs found for this dashboard.';
    return;
  }
  currentJobId = data.job_id;
  render(data);
  if (timer) clearInterval(timer);
  timer = setInterval(poll, 7000);
}



async function poll() {
  if (!currentJobId || pollInFlight) return;
  pollInFlight = true;
  try {
    const res = await fetch(`/deep-dive-jobs/${currentJobId}/status`, {cache:'no-store'});
    if (!res.ok) return;
    const data = await res.json();
    render(data);
    if (['complete','cancelled'].includes(data.status) && timer) {
      clearInterval(timer);
      timer = null;
    }
  } finally {
    pollInFlight = false;
  }
}

async function resumeJob() {
  if (!currentJobId) return alert('No job loaded.');
  await fetch(`/deep-dive-jobs/${currentJobId}/resume`, {method:'POST'});
  poll();
  if (timer) clearInterval(timer);
  timer = setInterval(poll, 7000);
}

async function cancelJob() {
  if (!currentJobId) return alert('No job loaded.');
  if (!confirm('Cancel this job? Completed routers will remain saved.')) return;
  await fetch(`/deep-dive-jobs/${currentJobId}/cancel`, {method:'POST'});
  poll();
}

function exportJob() {
  if (!currentJobId) return alert('No job loaded.');
  window.location = `/deep-dive-jobs/${currentJobId}/export.xlsx`;
}

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}

function render(data) {
  currentJobId = data.job_id;
  document.getElementById('jobId').innerText = `Job: ${data.job_id} • Status: ${data.status} • Current: ${data.current_identifier || 'none'}`;
  document.getElementById('fill').style.width = `${data.percent_complete || 0}%`;
  document.getElementById('pct').innerText = `${data.percent_complete || 0}%`;

  const c = data.counts || {};
  document.getElementById('stats').innerHTML =
    `Total ${data.total || 0} • Complete ${c.complete || 0} • Errors ${c.error || 0} • Pending ${c.pending || 0} • Running ${c.running || 0}`;

  const rows = data.recent_items || [];
  document.getElementById('recent').innerHTML = `
    <table>
      <thead><tr><th>Pos</th><th>Identifier</th><th>Router</th><th>Status</th><th>Attempts</th><th>Error</th></tr></thead>
      <tbody>${rows.map(r => `
        <tr>
          <td>${r.position}</td>
          <td>${esc(r.identifier)}</td>
          <td>${esc(r.router_id || '')}</td>
          <td class="${r.status === 'complete' ? 'ok' : r.status === 'error' ? 'err' : ''}">${esc(r.status)}</td>
          <td>${r.attempts}</td>
          <td>${esc(r.error || '')}</td>
        </tr>
      `).join('')}</tbody>
    </table>`;
}

// loadLatest disabled for stability; use the Load Latest Job button manually;
</script>


<script src="/api/odometer.js"></script>
<script src="/api/profile-header.js">
function bootRestoreSavedChartRanges() {{
  let attempts = 0;

  const timer = window.setInterval(async () => {{
    attempts += 1;

    try {{
      const signalSelect = document.getElementById('signalRangeSelect');
      if (!signalSelect) {{
        if (attempts > 30) window.clearInterval(timer);
        return;
      }}

      const profileId = typeof getRouterPageProfileId === 'function'
        ? getRouterPageProfileId()
        : '1';

      const storageKey = `ncm-monitor:router-chart-ranges:{router_id}:profile:${{profileId || '1'}}`;
      const raw = localStorage.getItem(storageKey);

      if (!raw) {{
        window.clearInterval(timer);
        return;
      }}

      const saved = JSON.parse(raw);
      if (!saved || typeof saved !== 'object') {{
        window.clearInterval(timer);
        return;
      }}

      console.log('Boot restoring saved chart ranges:', storageKey, saved);

      ensureChartRanges();

      let appliedAny = false;

      for (const kind of ['signal', 'usage', 'alert']) {{
        const state = saved[kind];
        if (!state) continue;

        const mode = String(state.mode || '30');
        const startDate = state.startDate || null;
        const endDate = state.endDate || null;

        window.chartRanges[kind] = {{ mode, startDate, endDate }};

        const select = document.getElementById(kind + 'RangeSelect');
        const startEl = document.getElementById(kind + 'StartDate');
        const endEl = document.getElementById(kind + 'EndDate');

        if (select) select.value = mode;
        if (startEl && startDate) startEl.value = startDate;
        if (endEl && endDate) endEl.value = endDate;

        if (!(mode === '30' && !startDate && !endDate)) {{
          appliedAny = true;
        }}
      }}

      updateAllChartRangeControls();

      if (appliedAny) {{
        window.clearInterval(timer);

        for (const kind of ['signal', 'usage', 'alert']) {{
          const state = window.chartRanges && window.chartRanges[kind];
          if (!state) continue;

          const isDefault = String(state.mode || '30') === '30' && !state.startDate && !state.endDate;
          if (isDefault) continue;

          console.log('Boot auto-applying saved chart range:', kind, state);
          await applyChartRange(kind);
        }}
      }} else {{
        window.clearInterval(timer);
      }}
    }} catch (e) {{
      console.warn('Boot restore saved chart ranges failed:', e);
      window.clearInterval(timer);
    }}

    if (attempts > 30) window.clearInterval(timer);
  }}, 250);
}}

window.addEventListener('load', () => {{
  window.setTimeout(() => {{
    bootRestoreSavedChartRanges();
  }}, 500);
}});

</script>
</body>
</html>
    """
