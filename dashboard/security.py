from __future__ import annotations

import hashlib
import hmac
import os
import time


def db_path() -> str:
    return os.getenv("IPS_DB_PATH", "./ips_open.db").strip() or "./ips_open.db"


def expected_sensor_signature(secret: str, timestamp: str, body: bytes) -> str:
    payload = timestamp.encode("utf-8") + b"." + body
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify_timestamp(ts_raw: str) -> None:
    try:
        ts = int(ts_raw)
    except (TypeError, ValueError):
        raise ValueError("invalid timestamp format")
    now_ts = int(time.time())
    if abs(now_ts - ts) > 300:
        raise ValueError("timestamp expired")
