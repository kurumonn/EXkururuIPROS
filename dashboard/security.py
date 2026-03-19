from __future__ import annotations

import hashlib
import hmac
import os
import re
import time

from .replay_cache import replay_cache_from_env

_NONCE_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{8,80}$")
_REPLAY_GUARD = replay_cache_from_env(
    namespace="ips",
    backend_env="IPS_REPLAY_BACKEND",
    redis_url_env="IPS_REDIS_URL",
    fallback_env="IPS_REPLAY_FALLBACK_TO_MEMORY",
    max_items_env="IPS_REPLAY_CACHE_MAX_ITEMS",
    ttl_env="IPS_REPLAY_TTL_SEC",
)


def _env_bool(name: str, default: bool) -> bool:
    raw = str(os.getenv(name, "1" if default else "0") or "").strip().lower()
    return raw in {"1", "true", "on", "yes"}


def _env_int(name: str, default: int, min_value: int, max_value: int) -> int:
    raw = str(os.getenv(name, str(default)) or "").strip()
    try:
        value = int(raw)
    except ValueError:
        value = default
    return max(min_value, min(max_value, value))


def db_path() -> str:
    return os.getenv("IPS_DB_PATH", "./ips_open.db").strip() or "./ips_open.db"


def expected_sensor_signature(secret: str, timestamp: str, body: bytes) -> str:
    payload = timestamp.encode("utf-8") + b"." + body
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def expected_sensor_signature_v2(secret: str, timestamp: str, body: bytes, nonce: str = "") -> str:
    nonce_value = str(nonce or "").strip()
    if nonce_value:
        payload = timestamp.encode("utf-8") + b"." + nonce_value.encode("utf-8") + b"." + body
    else:
        payload = timestamp.encode("utf-8") + b"." + body
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def nonce_required() -> bool:
    return _env_bool("IPS_REQUIRE_NONCE", True)


def validate_nonce(nonce: str, *, required: bool) -> str:
    value = str(nonce or "").strip()
    if required and not value:
        raise ValueError("missing nonce")
    if value and not _NONCE_PATTERN.fullmatch(value):
        raise ValueError("invalid nonce")
    return value


def verify_timestamp(ts_raw: str, max_skew_sec: int | None = None) -> None:
    try:
        ts = int(ts_raw)
    except (TypeError, ValueError):
        raise ValueError("invalid timestamp format")
    now_ts = int(time.time())
    skew = max_skew_sec
    if skew is None:
        skew = _env_int("IPS_SIGNATURE_MAX_SKEW_SEC", 300, 30, 3600)
    if abs(now_ts - ts) > max(1, int(skew)):
        raise ValueError("timestamp expired")


def replay_guard_add(raw_key: str, *, ttl_sec: int | None = None, max_items: int | None = None) -> bool:
    return _REPLAY_GUARD.add(raw_key, ttl_sec=ttl_sec, max_items=max_items)
