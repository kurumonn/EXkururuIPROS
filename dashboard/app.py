from __future__ import annotations

import asyncio
import json
import os
import re
import threading
import time
import ipaddress
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import urllib.error
import urllib.parse
import urllib.request

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .notifier import send_webhook
from .parser import aggregate_lines
from .e2e_eval import (
    bucket_5m_utc as _bucket_5m_utc_impl,
    e2e_profile_defaults as _e2e_profile_defaults_impl,
    e2e_regressions as _e2e_regressions_impl,
    evaluate_action_latency_breaches as _evaluate_action_latency_breaches_impl,
    evaluate_e2e_events as _evaluate_e2e_events_impl,
    extract_latency_ms as _extract_latency_ms_impl,
    is_blocked as _is_blocked_impl,
    is_mitigated as _is_mitigated_impl,
    percentile as _percentile_impl,
    scenario_class as _scenario_class_impl,
    to_float as _to_float_impl,
)
from .live_panel import (
    dashboard_summary_with_stack_panel as _dashboard_summary_with_stack_panel_impl,
    http_json_get as _http_json_get_impl,
    probe_edr_live as _probe_edr_live_impl,
    probe_soc_live as _probe_soc_live_impl,
    probe_xdr_live as _probe_xdr_live_impl,
    stack_live_panel as _stack_live_panel_impl,
)
from .security import (
    expected_sensor_signature,
    expected_sensor_signature_v2,
    nonce_required,
    replay_guard_add,
    validate_nonce,
    verify_timestamp,
)
from .xdr_adapter import export_events_to_xdr, export_source_heartbeat_to_xdr
from .storage import (
    ack_action,
    cancel_block_actions_for_target,
    create_block_action,
    dashboard_summary,
    fetch_pending_actions,
    get_source_heartbeat_snapshot,
    get_sensor,
    get_enabled_notification_channels,
    list_notification_events,
    list_e2e_eval_runs,
    list_soc_incidents,
    list_remote_actions,
    list_xdr_event_links,
    list_rule_feedback_stats,
    list_rule_overrides,
    list_sensors_summary,
    list_threat_intel_entries,
    list_threat_intel_sync_runs,
    lookup_threat_intel_ip_all,
    upsert_threat_intel_entry,
    upsert_threat_intel_entries_bulk,
    record_rule_feedback,
    upsert_rule_override,
    list_security_events_for_eval,
    record_action_latency_alert,
    soc_chain_summary,
    triage_soc_incident,
    get_workspace_setting,
    get_workspace_kpi_setting,
    list_workspace_assets,
    set_workspace_kpi_setting,
    upsert_workspace_asset,
    list_test_ip_allowlist,
    upsert_test_ip_allowlist_entry,
    set_test_ip_allowlist_status,
    get_active_control_policy,
    control_plane_overview,
    create_control_policy_version,
    publish_control_policy_version,
    list_control_policy_versions,
    list_control_policy_distributions,
    get_pending_policy_distribution,
    ack_policy_distribution,
    init_db,
    insert_security_events,
    list_notification_channels,
    record_notification_event,
    record_admin_audit_log,
    register_sensor,
    save_e2e_eval_run,
    set_workspace_waf,
    set_remote_action_result,
    prune_admin_audit_logs,
    list_admin_audit_logs,
    touch_sensor,
    upsert_remote_action,
    upsert_metrics,
    upsert_notification_channel,
)


BASE_DIR = Path(__file__).resolve().parent
templates = Environment(
    loader=FileSystemLoader(str(BASE_DIR / "templates")),
    autoescape=select_autoescape(["html", "xml"]),
)
_RATE_LIMIT_LOCK = threading.Lock()
_RATE_LIMIT_WINDOWS: dict[str, list[float]] = {}
_TRUSTED_PROXY_LOCK = threading.Lock()
_TRUSTED_PROXY_CACHE: tuple[str, list[ipaddress._BaseNetwork]] | None = None
_MAINT_LOCK = threading.Lock()
_LAST_AUDIT_PRUNE_TS = 0.0
_OIDC_CACHE_LOCK = threading.Lock()
_OIDC_CACHE: dict[str, tuple[float, dict | None]] = {}
_STACK_LIVE_CACHE_LOCK = threading.Lock()
_STACK_LIVE_CACHE: dict[str, object] = {"at": 0.0, "data": None}


def _reason(status: int) -> str:
    return {
        200: "OK",
        201: "Created",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        500: "Internal Server Error",
    }.get(status, "OK")


_MAX_BODY_BYTES = int(os.getenv("IPS_MAX_BODY_BYTES", "10485760"))  # 10 MB


async def _read_body(receive) -> bytes:
    body = b""
    while True:
        message = await receive()
        if message["type"] != "http.request":
            continue
        body += message.get("body", b"")
        if len(body) > _MAX_BODY_BYTES:
            raise ValueError("request body too large")
        if not message.get("more_body", False):
            break
    return body


def _json_response(payload: dict, status: int = 200):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return status, [(b"content-type", b"application/json; charset=utf-8")], body


def _html_response(html: str, status: int = 200):
    return status, [(b"content-type", b"text/html; charset=utf-8")], html.encode("utf-8")


def _text_response(text: str, status: int = 200, content_type: bytes = b"text/plain; charset=utf-8"):
    return status, [(b"content-type", content_type)], text.encode("utf-8")


def _headers(scope) -> dict[str, str]:
    return {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}


def _query_params(scope) -> dict[str, list[str]]:
    return parse_qs(scope.get("query_string", b"").decode("utf-8"))


def _security_headers(scope, status: int) -> list[tuple[bytes, bytes]]:
    headers: list[tuple[bytes, bytes]] = [
        (b"x-content-type-options", b"nosniff"),
        (b"x-frame-options", b"DENY"),
        (b"referrer-policy", b"no-referrer"),
        (b"permissions-policy", b"geolocation=(), microphone=(), camera=()"),
    ]
    path = scope.get("path", "")
    if path == "/" or path.startswith("/static/"):
        headers.append(
            (
                b"content-security-policy",
                b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            )
        )
    if os.getenv("IPS_ENABLE_HSTS", "0").strip().lower() in {"1", "true", "on", "yes"}:
        headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
    return headers


def _cors_headers(scope) -> list[tuple[bytes, bytes]]:
    origin = _headers(scope).get("origin", "").strip()
    if not origin:
        return []
    allowed_raw = os.getenv("IPS_CORS_ALLOW_ORIGINS", "").strip()
    if not allowed_raw:
        return []
    allowed = {x.strip() for x in allowed_raw.split(",") if x.strip()}
    if "*" not in allowed and origin not in allowed:
        return []
    return [
        (b"access-control-allow-origin", origin.encode("utf-8")),
        (b"access-control-allow-methods", b"GET,POST,OPTIONS"),
        (
            b"access-control-allow-headers",
            b"Authorization,Content-Type,X-Admin-Actor,X-IPS-Sensor-Id,X-IPS-Signature,X-IPS-Timestamp,X-IPS-Nonce",
        ),
        (b"access-control-max-age", b"600"),
        (b"vary", b"Origin"),
    ]


def _admin_extra_header_ok(scope) -> bool:
    name = os.getenv("IPS_ADMIN_EXTRA_HEADER_NAME", "").strip().lower()
    value = os.getenv("IPS_ADMIN_EXTRA_HEADER_VALUE", "").strip()
    if not name or not value:
        return True
    return _headers(scope).get(name, "").strip() == value


def _audit_maintenance_tick() -> None:
    global _LAST_AUDIT_PRUNE_TS
    now = time.monotonic()
    interval_sec = max(60, _env_int("IPS_AUDIT_PRUNE_INTERVAL_SEC", 3600, 60, 86400))
    if now - _LAST_AUDIT_PRUNE_TS < interval_sec:
        return
    with _MAINT_LOCK:
        if now - _LAST_AUDIT_PRUNE_TS < interval_sec:
            return
        prune_admin_audit_logs(_env_int("IPS_AUDIT_RETENTION_DAYS", 30, 1, 3650))
        _LAST_AUDIT_PRUNE_TS = now


def _normalize_ip_token(token: str) -> str:
    value = str(token or "").strip()
    if not value:
        return ""
    if value.startswith("[") and "]" in value:
        return value[1 : value.find("]")]
    if value.count(":") == 1 and "." in value:
        return value.split(":", 1)[0]
    return value


def _parse_ip(value: str) -> ipaddress._BaseAddress | None:
    raw = _normalize_ip_token(value)
    if not raw:
        return None
    try:
        return ipaddress.ip_address(raw)
    except ValueError:
        return None


def _is_private_target_host(hostname: str) -> bool:
    host = str(hostname or "").strip().lower()
    if not host:
        return True
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        return True
    ip = _parse_ip(host)
    if not ip:
        return False
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _validate_webhook_url(url: str) -> tuple[bool, str]:
    value = str(url or "").strip()
    if not value or len(value) > 2048:
        return False, "webhook_url is invalid"
    try:
        parsed = urlparse(value)
    except Exception:
        return False, "webhook_url parse failed"
    allow_http = os.getenv("IPS_ALLOW_INSECURE_WEBHOOK_HTTP", "0").strip().lower() in {"1", "true", "on", "yes"}
    allowed_schemes = {"https"} | ({"http"} if allow_http else set())
    if parsed.scheme.lower() not in allowed_schemes:
        return False, "webhook_url scheme is not allowed"
    if parsed.username or parsed.password:
        return False, "webhook_url must not include userinfo"
    if not parsed.hostname:
        return False, "webhook_url hostname is required"
    if parsed.port is not None and not (1 <= int(parsed.port) <= 65535):
        return False, "webhook_url port is invalid"
    allow_private = os.getenv("IPS_ALLOW_PRIVATE_WEBHOOK_TARGETS", "0").strip().lower() in {"1", "true", "on", "yes"}
    if not allow_private and _is_private_target_host(parsed.hostname):
        return False, "webhook_url private target is not allowed"
    return True, ""


def _load_trusted_proxy_networks() -> list[ipaddress._BaseNetwork]:
    global _TRUSTED_PROXY_CACHE
    raw = os.getenv("IPS_TRUSTED_PROXIES", "").strip()
    with _TRUSTED_PROXY_LOCK:
        if _TRUSTED_PROXY_CACHE and _TRUSTED_PROXY_CACHE[0] == raw:
            return _TRUSTED_PROXY_CACHE[1]
        nets: list[ipaddress._BaseNetwork] = []
        for token in [x.strip() for x in raw.split(",") if x.strip()]:
            try:
                if "/" in token:
                    nets.append(ipaddress.ip_network(token, strict=False))
                else:
                    ip = ipaddress.ip_address(token)
                    prefix = 32 if ip.version == 4 else 128
                    nets.append(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
            except ValueError:
                continue
        _TRUSTED_PROXY_CACHE = (raw, nets)
        return nets


def _is_trusted_proxy(ip: ipaddress._BaseAddress, trusted_networks: list[ipaddress._BaseNetwork]) -> bool:
    for net in trusted_networks:
        if ip.version == net.version and ip in net:
            return True
    return False


def _client_ip(scope) -> str:
    client = scope.get("client")
    remote_raw = str(client[0]) if client and isinstance(client, (tuple, list)) and client else ""
    remote_ip = _parse_ip(remote_raw)
    if not remote_ip:
        return _normalize_ip_token(remote_raw) or "unknown"

    if os.getenv("IPS_TRUST_PROXY_ENABLED", "0").strip().lower() not in {"1", "true", "on", "yes"}:
        return str(remote_ip)

    trusted_networks = _load_trusted_proxy_networks()
    if not trusted_networks:
        return str(remote_ip)
    if not _is_trusted_proxy(remote_ip, trusted_networks):
        return str(remote_ip)

    headers = _headers(scope)
    xff_raw = headers.get("x-forwarded-for", "")
    xff_ips: list[ipaddress._BaseAddress] = []
    for token in [x.strip() for x in xff_raw.split(",") if x.strip()]:
        ip = _parse_ip(token)
        if ip:
            xff_ips.append(ip)
    if not xff_ips:
        return str(remote_ip)

    # Walk right-to-left across XFF + remote and choose the first non-trusted address.
    chain = xff_ips + [remote_ip]
    for ip in reversed(chain):
        if not _is_trusted_proxy(ip, trusted_networks):
            return str(ip)
    return str(xff_ips[0])


def _env_int(name: str, default: int, min_value: int = 1, max_value: int = 100000) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(min_value, min(value, max_value))


def _env_float(name: str, default: float, min_value: float = 0.0, max_value: float = 3600.0) -> float:
    raw = str(os.getenv(name, str(default)) or "").strip()
    try:
        value = float(raw)
    except ValueError:
        return float(default)
    return max(float(min_value), min(float(value), float(max_value)))


def _ingest_shard_count() -> int:
    return _env_int("IPS_INGEST_SHARD_COUNT", 1, 1, 128)


def _ingest_shard_index(shard_count: int) -> int:
    return _env_int("IPS_INGEST_SHARD_INDEX", 0, 0, max(0, shard_count - 1))


def _ingest_shard_enforce() -> bool:
    return os.getenv("IPS_INGEST_SHARD_ENFORCE", "0").strip().lower() in {"1", "true", "on", "yes"}


def _cloud_k8s_connectors_enabled() -> bool:
    return os.getenv("IPS_CLOUD_K8S_CONNECTORS_ENABLED", "0").strip().lower() in {"1", "true", "on", "yes"}


def _ransomware_connectors_enabled() -> bool:
    return os.getenv("IPS_RANSOMWARE_CONNECTORS_ENABLED", "0").strip().lower() in {"1", "true", "on", "yes"}


def _sensor_home_shard(workspace_slug: str, sensor_id: str, shard_count: int) -> int:
    if shard_count <= 1:
        return 0
    key = f"{workspace_slug}:{sensor_id}".encode("utf-8")
    digest = hashlib.sha256(key).hexdigest()[:8]
    return int(digest, 16) % shard_count


def _rate_limit_rule(path: str) -> tuple[int, int] | None:
    if path in {"/", "/healthz"} or path.startswith("/static/"):
        return None
    if path.startswith("/kurucha/") or path.startswith("/api/v1/kurucha/"):
        return (
            _env_int("IPS_RATE_LIMIT_KURUCHA_LIMIT", 30),
            _env_int("IPS_RATE_LIMIT_KURUCHA_WINDOW_SEC", 60),
        )
    if path == "/api/v1/admin/logs/ingest/":
        return (
            _env_int("IPS_RATE_LIMIT_ADMIN_INGEST_LIMIT", 30),
            _env_int("IPS_RATE_LIMIT_ADMIN_INGEST_WINDOW_SEC", 60),
        )
    if path == "/api/v1/admin/e2e/evaluate/":
        return (
            _env_int("IPS_RATE_LIMIT_ADMIN_E2E_LIMIT", 3),
            _env_int("IPS_RATE_LIMIT_ADMIN_E2E_WINDOW_SEC", 300),
        )
    if re.fullmatch(r"/api/v1/workspaces/[^/]+/sensors/[^/]+/events/batch/?", path):
        return (
            _env_int("IPS_RATE_LIMIT_SENSOR_EVENTS_LIMIT", 180),
            _env_int("IPS_RATE_LIMIT_SENSOR_EVENTS_WINDOW_SEC", 60),
        )
    if path.startswith("/api/v1/admin/"):
        return (
            _env_int("IPS_RATE_LIMIT_ADMIN_LIMIT", 60),
            _env_int("IPS_RATE_LIMIT_ADMIN_WINDOW_SEC", 60),
        )
    if path.startswith("/api/"):
        return (
            _env_int("IPS_RATE_LIMIT_API_LIMIT", 240),
            _env_int("IPS_RATE_LIMIT_API_WINDOW_SEC", 60),
        )
    return (
        _env_int("IPS_RATE_LIMIT_DEFAULT_LIMIT", 180),
        _env_int("IPS_RATE_LIMIT_DEFAULT_WINDOW_SEC", 60),
    )


def _check_rate_limit(scope, path: str) -> tuple[bool, int]:
    if os.getenv("IPS_RATE_LIMIT_ENABLED", "1").strip().lower() in {"0", "false", "off", "no"}:
        return True, 0
    rule = _rate_limit_rule(path)
    if not rule:
        return True, 0
    limit, window_sec = rule
    now = time.monotonic()
    ip = _client_ip(scope)
    key = f"{ip}|{path}|{window_sec}"
    with _RATE_LIMIT_LOCK:
        items = _RATE_LIMIT_WINDOWS.get(key)
        if not items:
            items = []
            _RATE_LIMIT_WINDOWS[key] = items
        cutoff = now - float(window_sec)
        while items and items[0] < cutoff:
            items.pop(0)
        if len(items) >= limit:
            retry_after = int(max(1, (items[0] + float(window_sec)) - now))
            return False, retry_after
        items.append(now)
    return True, 0


_ADMIN_ROLE_ORDER = {"viewer": 1, "operator": 2, "admin": 3}


def _normalize_admin_role(value: str | None) -> str:
    v = str(value or "").strip().lower()
    if v in _ADMIN_ROLE_ORDER:
        return v
    return "viewer"


def _default_min_role_for_scope(scope) -> str:
    method = str(scope.get("method") or "").upper()
    if method in {"GET", "HEAD"}:
        return "viewer"
    return "operator"


def _load_admin_identities() -> list[dict]:
    # Preferred: IPS_ADMIN_TOKENS_JSON='[{"token":"...","role":"admin","name":"alice"}]'
    raw = str(os.getenv("IPS_ADMIN_TOKENS_JSON", "") or "").strip()
    identities: list[dict] = []
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = []
        if isinstance(parsed, list):
            for item in parsed:
                if not isinstance(item, dict):
                    continue
                token = str(item.get("token") or "").strip()
                if not token:
                    continue
                role = _normalize_admin_role(str(item.get("role") or "viewer"))
                name = str(item.get("name") or item.get("actor") or role).strip() or role
                identities.append({"token": token, "role": role, "name": name})
    if identities:
        return identities
    legacy = str(os.getenv("IPS_ADMIN_TOKEN", "") or "").strip()
    if legacy:
        return [{"token": legacy, "role": "admin", "name": "admin"}]
    return []


def _is_scope_from_trusted_proxy(scope) -> bool:
    client = scope.get("client")
    remote_raw = str(client[0]) if client and isinstance(client, (tuple, list)) and client else ""
    remote_ip = _parse_ip(remote_raw)
    if not remote_ip:
        return False
    trusted_networks = _load_trusted_proxy_networks()
    if not trusted_networks:
        return False
    return _is_trusted_proxy(remote_ip, trusted_networks)


def _parse_sso_role_from_groups(groups_raw: str) -> str:
    groups = {
        x.strip().lower()
        for x in re.split(r"[,\s;|]+", str(groups_raw or ""))
        if x.strip()
    }
    if not groups:
        return _normalize_admin_role(os.getenv("IPS_SSO_DEFAULT_ROLE", "viewer"))
    role_map_raw = str(
        os.getenv(
            "IPS_SSO_ROLE_MAP",
            "admins=admin,admin=admin,operators=operator,ops=operator,viewers=viewer,readonly=viewer",
        )
        or ""
    ).strip()
    role_scores: list[int] = []
    for token in [x.strip() for x in role_map_raw.split(",") if x.strip()]:
        key, sep, value = token.partition("=")
        if not sep:
            continue
        group_key = key.strip().lower()
        role = _normalize_admin_role(value)
        if group_key in groups:
            role_scores.append(_ADMIN_ROLE_ORDER.get(role, 1))
    if not role_scores:
        return _normalize_admin_role(os.getenv("IPS_SSO_DEFAULT_ROLE", "viewer"))
    max_score = max(role_scores)
    for role, score in _ADMIN_ROLE_ORDER.items():
        if score == max_score:
            return role
    return "viewer"


def _parse_role_from_groups(groups_raw, role_map_raw: str, default_role: str = "viewer") -> str:
    groups = set()
    if isinstance(groups_raw, list):
        groups = {str(x).strip().lower() for x in groups_raw if str(x).strip()}
    else:
        groups = {
            x.strip().lower()
            for x in re.split(r"[,\s;|]+", str(groups_raw or ""))
            if x.strip()
        }
    if not groups:
        return _normalize_admin_role(default_role)
    role_scores: list[int] = []
    for token in [x.strip() for x in str(role_map_raw or "").split(",") if x.strip()]:
        key, sep, value = token.partition("=")
        if not sep:
            continue
        if key.strip().lower() in groups:
            role_scores.append(_ADMIN_ROLE_ORDER.get(_normalize_admin_role(value), 1))
    if not role_scores:
        return _normalize_admin_role(default_role)
    max_score = max(role_scores)
    for role, score in _ADMIN_ROLE_ORDER.items():
        if score == max_score:
            return role
    return _normalize_admin_role(default_role)


def _sso_identity(scope) -> dict | None:
    if os.getenv("IPS_SSO_ENABLED", "0").strip().lower() not in {"1", "true", "on", "yes"}:
        return None
    if os.getenv("IPS_SSO_REQUIRE_TRUSTED_PROXY", "1").strip().lower() in {"1", "true", "on", "yes"}:
        if not _is_scope_from_trusted_proxy(scope):
            return None
    headers = _headers(scope)
    user_header = str(os.getenv("IPS_SSO_USER_HEADER", "x-auth-request-user") or "x-auth-request-user").strip().lower()
    role_header = str(os.getenv("IPS_SSO_ROLE_HEADER", "x-auth-request-role") or "x-auth-request-role").strip().lower()
    groups_header = str(os.getenv("IPS_SSO_GROUPS_HEADER", "x-auth-request-groups") or "x-auth-request-groups").strip().lower()
    user_name = str(headers.get(user_header, "") or "").strip()
    if not user_name:
        return None
    role_raw = str(headers.get(role_header, "") or "").strip().lower()
    role = _normalize_admin_role(role_raw) if role_raw in _ADMIN_ROLE_ORDER else _parse_role_from_groups(
        headers.get(groups_header, ""),
        os.getenv(
            "IPS_SSO_ROLE_MAP",
            "admins=admin,admin=admin,operators=operator,ops=operator,viewers=viewer,readonly=viewer",
        ),
        default_role=os.getenv("IPS_SSO_DEFAULT_ROLE", "viewer"),
    )
    return {"name": user_name, "role": role, "auth_type": "sso"}


def _oidc_extract_claim(claims: dict, key: str, default=None):
    if not key:
        return default
    current = claims
    for part in str(key).split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default
    return current


def _as_lower_set(value) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        return {str(x).strip().lower() for x in value if str(x).strip()}
    raw = str(value).strip()
    if not raw:
        return set()
    return {x.strip().lower() for x in re.split(r"[,\s;|]+", raw) if x.strip()}


def _oidc_validate_issuer_audience(claims: dict) -> bool:
    expected_issuers = _as_lower_set(os.getenv("IPS_OIDC_EXPECTED_ISSUER", ""))
    expected_audiences = _as_lower_set(os.getenv("IPS_OIDC_EXPECTED_AUDIENCE", ""))
    if expected_issuers:
        iss = str(claims.get("iss") or "").strip().lower()
        if not iss or iss not in expected_issuers:
            return False
    if expected_audiences:
        aud = claims.get("aud")
        actual_aud = _as_lower_set(aud)
        if not actual_aud.intersection(expected_audiences):
            return False
    return True


def _oidc_http_json(
    url: str,
    *,
    bearer_token: str | None = None,
    form: dict | None = None,
    basic_user: str | None = None,
    basic_password: str | None = None,
) -> dict | None:
    timeout_sec = float(os.getenv("IPS_OIDC_HTTP_TIMEOUT_SEC", "2.5") or 2.5)
    headers = {"Accept": "application/json"}
    data = None
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    if form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if basic_user:
        raw = f"{basic_user}:{basic_password or ''}".encode("utf-8")
        token = __import__("base64").b64encode(raw).decode("ascii")
        headers["Authorization"] = f"Basic {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            if int(getattr(resp, "status", 200)) >= 400:
                return None
            raw_body = resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        return None
    try:
        payload = json.loads(raw_body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _looks_like_jwt(token: str) -> bool:
    parts = str(token or "").split(".")
    return len(parts) == 3 and all(parts)


def _oidc_claims_from_jwt(token: str) -> dict | None:
    jwks_url = str(os.getenv("IPS_OIDC_JWKS_URL", "") or "").strip()
    if not jwks_url:
        return None
    if not _looks_like_jwt(token):
        return None
    try:
        import jwt
    except Exception:
        return None
    algs_raw = str(os.getenv("IPS_OIDC_JWT_ALGORITHMS", "RS256,ES256") or "RS256,ES256")
    algorithms = [x.strip() for x in algs_raw.split(",") if x.strip()]
    if not algorithms:
        algorithms = ["RS256"]
    try:
        jwk_client = jwt.PyJWKClient(jwks_url)
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=algorithms,
            options={
                "verify_signature": True,
                "verify_exp": os.getenv("IPS_OIDC_VERIFY_EXP", "1").strip().lower() in {"1", "true", "on", "yes"},
                "verify_aud": False,
                "verify_iss": False,
            },
        )
    except Exception:
        return None
    return claims if isinstance(claims, dict) else None


def _oidc_identity_from_bearer(token: str) -> dict | None:
    if os.getenv("IPS_OIDC_ENABLED", "0").strip().lower() not in {"1", "true", "on", "yes"}:
        return None
    t = str(token or "").strip()
    if not t:
        return None
    cache_sec = max(0, min(_env_int("IPS_OIDC_CACHE_SEC", 60, 0, 3600), 3600))
    cache_key = hashlib.sha256(t.encode("utf-8")).hexdigest()
    now_mono = time.monotonic()
    with _OIDC_CACHE_LOCK:
        cached = _OIDC_CACHE.get(cache_key)
        if cached and cached[0] > now_mono:
            return dict(cached[1]) if isinstance(cached[1], dict) else None

    claims = None
    jwt_claims = _oidc_claims_from_jwt(t)
    if isinstance(jwt_claims, dict):
        claims = dict(jwt_claims)
    require_jwt_verify = os.getenv("IPS_OIDC_REQUIRE_JWT_VERIFY", "0").strip().lower() in {"1", "true", "on", "yes"}
    if claims is None and require_jwt_verify and str(os.getenv("IPS_OIDC_JWKS_URL", "") or "").strip() and _looks_like_jwt(t):
        with _OIDC_CACHE_LOCK:
            if cache_sec > 0:
                _OIDC_CACHE[cache_key] = (now_mono + float(cache_sec), None)
        return None
    introspection_url = str(os.getenv("IPS_OIDC_INTROSPECTION_URL", "") or "").strip()
    userinfo_url = str(os.getenv("IPS_OIDC_USERINFO_URL", "") or "").strip()
    if claims is None and introspection_url:
        client_id = str(os.getenv("IPS_OIDC_CLIENT_ID", "") or "").strip()
        client_secret = str(os.getenv("IPS_OIDC_CLIENT_SECRET", "") or "").strip()
        claims = _oidc_http_json(
            introspection_url,
            form={"token": t},
            basic_user=client_id if client_id else None,
            basic_password=client_secret if client_id else None,
        )
        if not claims or not bool(claims.get("active")):
            claims = None
    if claims is None and userinfo_url:
        claims = _oidc_http_json(userinfo_url, bearer_token=t)
    if not isinstance(claims, dict):
        with _OIDC_CACHE_LOCK:
            if cache_sec > 0:
                _OIDC_CACHE[cache_key] = (now_mono + float(cache_sec), None)
        return None
    if not _oidc_validate_issuer_audience(claims):
        with _OIDC_CACHE_LOCK:
            if cache_sec > 0:
                _OIDC_CACHE[cache_key] = (now_mono + float(cache_sec), None)
        return None

    user_claim = str(os.getenv("IPS_OIDC_USERNAME_CLAIM", "preferred_username") or "preferred_username")
    role_claim = str(os.getenv("IPS_OIDC_ROLE_CLAIM", "role") or "role")
    groups_claim = str(os.getenv("IPS_OIDC_GROUPS_CLAIM", "groups") or "groups")
    name = str(_oidc_extract_claim(claims, user_claim, "") or claims.get("sub") or "").strip()
    if not name:
        with _OIDC_CACHE_LOCK:
            if cache_sec > 0:
                _OIDC_CACHE[cache_key] = (now_mono + float(cache_sec), None)
        return None
    role_raw = str(_oidc_extract_claim(claims, role_claim, "") or "").strip().lower()
    if role_raw in _ADMIN_ROLE_ORDER:
        role = _normalize_admin_role(role_raw)
    else:
        role = _parse_role_from_groups(
            _oidc_extract_claim(claims, groups_claim, []),
            os.getenv(
                "IPS_OIDC_ROLE_MAP",
                "admins=admin,admin=admin,operators=operator,ops=operator,viewers=viewer,readonly=viewer",
            ),
            default_role=os.getenv("IPS_OIDC_DEFAULT_ROLE", "viewer"),
        )
    identity = {"name": name, "role": role, "auth_type": "oidc"}
    with _OIDC_CACHE_LOCK:
        if cache_sec > 0:
            _OIDC_CACHE[cache_key] = (now_mono + float(cache_sec), dict(identity))
    return identity


def _http_json_get(url: str, *, headers: dict[str, str] | None = None, timeout_sec: float = 1.5) -> tuple[bool, int, dict, str, float]:
    return _http_json_get_impl(url, headers=headers, timeout_sec=timeout_sec)


def _probe_xdr_live(timeout_sec: float) -> dict[str, object]:
    return _probe_xdr_live_impl(timeout_sec)


def _probe_soc_live(timeout_sec: float) -> dict[str, object]:
    return _probe_soc_live_impl(timeout_sec)


def _probe_edr_live(timeout_sec: float) -> dict[str, object]:
    return _probe_edr_live_impl(timeout_sec)


def _stack_live_panel() -> dict[str, object]:
    return _stack_live_panel_impl()


def _dashboard_summary_with_stack_panel() -> dict:
    return _dashboard_summary_with_stack_panel_impl()



def _require_admin_auth(scope, min_role: str | None = None) -> tuple[bool, tuple[int, list[tuple[bytes, bytes]], bytes] | None]:
    headers = _headers(scope)
    auth = headers.get("authorization", "")
    matched = None
    if auth.startswith("Bearer "):
        identities = _load_admin_identities()
        token = auth[7:].strip()
        if identities:
            if os.getenv("IPS_ALLOW_WEAK_SECRETS", "0").strip().lower() not in {"1", "true", "on", "yes"}:
                for item in identities:
                    if len(str(item.get("token") or "")) < 20:
                        return False, _json_response({"ok": False, "error": "admin token must be >=20 chars in production"}, 500)
            for item in identities:
                expected = str(item.get("token") or "")
                if expected and hmac.compare_digest(token.encode("utf-8"), expected.encode("utf-8")):
                    matched = dict(item)
                    matched["auth_type"] = "bearer"
                    break
        if not matched:
            matched = _oidc_identity_from_bearer(token)
        if not matched:
            return False, _json_response({"ok": False, "error": "invalid bearer token"}, 403)
    else:
        matched = _sso_identity(scope)
        if not matched:
            return False, _json_response({"ok": False, "error": "missing bearer token or sso identity"}, 401)
    actual_role = _normalize_admin_role(str(matched.get("role") or "viewer"))
    required_role = _normalize_admin_role(min_role or _default_min_role_for_scope(scope))
    if _ADMIN_ROLE_ORDER.get(actual_role, 0) < _ADMIN_ROLE_ORDER.get(required_role, 0):
        return False, _json_response(
            {
                "ok": False,
                "error": "insufficient role",
                "required_role": required_role,
                "actual_role": actual_role,
            },
            403,
        )
    if not _admin_extra_header_ok(scope):
        return False, _json_response({"ok": False, "error": "admin extra header check failed"}, 403)
    scope["_admin_role"] = actual_role
    scope["_admin_name"] = str(matched.get("name") or actual_role)
    scope["_admin_auth_type"] = str(matched.get("auth_type") or "unknown")
    return True, None


def _require_xdr_connector_auth(scope) -> tuple[bool, tuple[int, list[tuple[bytes, bytes]], bytes] | None]:
    token = str(os.getenv("IPS_XDR_CONNECTOR_TOKEN", "") or "").strip()
    if not token:
        token = str(os.getenv("XDR_ORCHESTRATOR_TOKEN", "") or "").strip()
    if not token:
        return False, _json_response({"ok": False, "error": "xdr connector token is not configured"}, 500)
    if os.getenv("IPS_ALLOW_WEAK_SECRETS", "0").strip().lower() not in {"1", "true", "on", "yes"}:
        if len(token) < 20:
            return False, _json_response({"ok": False, "error": "xdr connector token must be >=20 chars in production"}, 500)
    auth = _headers(scope).get("authorization", "")
    if not auth.startswith("Bearer "):
        return False, _json_response({"ok": False, "error": "missing bearer token"}, 401)
    got = auth[7:].strip()
    if not got or not hmac.compare_digest(got.encode("utf-8"), token.encode("utf-8")):
        return False, _json_response({"ok": False, "error": "invalid xdr connector token"}, 403)
    return True, None


def _xdr_allowed_workspaces() -> set[str]:
    raw = str(os.getenv("IPS_XDR_ALLOWED_WORKSPACES", "") or "").strip()
    if raw:
        out = {x.strip() for x in raw.split(",") if x.strip()}
        if out:
            return out
    default_ws = str(os.getenv("IPROS_DEFAULT_WORKSPACE", "lab") or "lab").strip() or "lab"
    return {default_ws}


def _authenticate_sensor(scope, workspace_slug: str, sensor_id: str, body: bytes):
    headers = _headers(scope)
    req_sensor_id = headers.get("x-ips-sensor-id", "").strip()
    signature = headers.get("x-ips-signature", "").strip()
    timestamp = headers.get("x-ips-timestamp", "").strip()
    nonce = headers.get("x-ips-nonce", "").strip()
    if not req_sensor_id or not signature or not timestamp:
        return None, _json_response({"ok": False, "error": "missing auth headers"}, 401)
    if req_sensor_id != sensor_id:
        return None, _json_response({"ok": False, "error": "sensor mismatch"}, 403)
    require_nonce = nonce_required()
    try:
        nonce = validate_nonce(nonce, required=require_nonce)
    except ValueError as exc:
        message = str(exc).strip().lower()
        if "missing" in message:
            return None, _json_response({"ok": False, "error": "missing nonce"}, 401)
        return None, _json_response({"ok": False, "error": "invalid nonce"}, 401)
    try:
        verify_timestamp(timestamp)
    except Exception:
        return None, _json_response({"ok": False, "error": "timestamp expired"}, 401)
    sensor = get_sensor(workspace_slug, sensor_id)
    if not sensor:
        return None, _json_response({"ok": False, "error": "sensor not found"}, 404)
    expected = expected_sensor_signature_v2(sensor["shared_secret"], timestamp, body, nonce=nonce)
    legacy = expected_sensor_signature(sensor["shared_secret"], timestamp, body)
    if not hmac.compare_digest(signature.encode("utf-8"), expected.encode("utf-8")) and not (
        not require_nonce and hmac.compare_digest(signature.encode("utf-8"), legacy.encode("utf-8"))
    ):
        return None, _json_response({"ok": False, "error": "invalid signature"}, 403)
    method = str(scope.get("method", "GET") or "GET").upper()
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        replay_raw = f"{workspace_slug}:{sensor_id}:{scope.get('path','')}:{timestamp}:{signature}:{nonce}"
        if not replay_guard_add(replay_raw):
            return None, _json_response({"ok": False, "error": "replay_detected"}, 409)
    touch_sensor(workspace_slug, sensor_id)
    return sensor, None


def _parse_json_body(body: bytes):
    try:
        return json.loads(body.decode("utf-8") or "{}"), None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, _json_response({"ok": False, "error": "invalid json"}, 400)


def _extract_source_event_keys(rows: list[dict] | list, limit: int = 5000) -> list[str]:
    if not isinstance(rows, list):
        return []
    seen: set[str] = set()
    out: list[str] = []
    max_len = max(1, min(int(limit), 10000))
    for row in rows:
        source_key = ""
        if isinstance(row, dict):
            source_key = str(row.get("event_id") or row.get("source_event_key") or "").strip()[:140]
        else:
            source_key = str(row or "").strip()[:140]
        if not source_key or source_key in seen:
            continue
        seen.add(source_key)
        out.append(source_key)
        if len(out) >= max_len:
            break
    return out


def _prometheus_metrics(payload: dict) -> str:
    kpi = payload.get("kpis") or {}
    waf = payload.get("waf") or {}
    lines = [
        "# HELP ips_requests_total_24h Total requests in last 24h",
        "# TYPE ips_requests_total_24h gauge",
        f"ips_requests_total_24h {int(kpi.get('total_requests_24h') or 0)}",
        "# HELP ips_blocked_429_total_24h Blocked(429) in last 24h",
        "# TYPE ips_blocked_429_total_24h gauge",
        f"ips_blocked_429_total_24h {int(kpi.get('blocked_429_24h') or 0)}",
        "# HELP ips_avg_response_time_ms_24h Avg response time in ms in last 24h",
        "# TYPE ips_avg_response_time_ms_24h gauge",
        f"ips_avg_response_time_ms_24h {float(kpi.get('avg_response_time_ms_24h') or 0.0)}",
        "# HELP ips_waf_enabled Workspace WAF enabled (1 or 0)",
        "# TYPE ips_waf_enabled gauge",
        f"ips_waf_enabled{{workspace=\"{waf.get('workspace_slug', 'lab')}\"}} {1 if waf.get('enabled') else 0}",
    ]
    return "\n".join(lines) + "\n"


def _notify_workspace(workspace_slug: str, event_type: str, payload: dict) -> dict:
    channels = get_enabled_notification_channels(workspace_slug)
    sent = 0
    failed = 0
    for channel in channels:
        ok, detail = send_webhook(
            channel_type=str(channel.get("channel_type") or "").strip().lower(),
            webhook_url=str(channel.get("webhook_url") or "").strip(),
            event=payload,
            secret_token=str(channel.get("secret_token") or ""),
        )
        record_notification_event(
            workspace_slug=workspace_slug,
            channel_type=str(channel.get("channel_type") or "unknown"),
            event_type=event_type,
            status="sent" if ok else "failed",
            detail=detail,
        )
        if ok:
            sent += 1
        else:
            failed += 1
    return {"channels": len(channels), "sent": sent, "failed": failed}


def _to_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    sorted_values = sorted(values)
    index = (len(sorted_values) - 1) * p
    low = int(index)
    high = min(low + 1, len(sorted_values) - 1)
    weight = index - low
    return float(sorted_values[low] * (1.0 - weight) + sorted_values[high] * weight)


def _is_mitigated(action: str) -> bool:
    return action in {
        "limit",
        "challenge",
        "block",
        "captcha",
        "throttle",
        "deny",
        "drop",
        "reject",
        "waf_block",
    }


def _is_blocked(action: str) -> bool:
    return action in {"block", "deny", "drop", "reject", "waf_block", "403", "429"}


def _bucket_5m_utc() -> str:
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    now = now.replace(minute=(now.minute // 5) * 5)
    return now.strftime("%Y%m%d_%H%M")


def _extract_latency_ms(event: dict) -> float | None:
    for key in ("processing_ms", "latency_ms", "response_ms", "rt_ms"):
        v = _to_float(event.get(key), -1.0)
        if v >= 0:
            return v
    rt = _to_float(event.get("rt"), -1.0)
    if rt >= 0:
        return rt * 1000.0
    return None


def _evaluate_action_latency_breaches(events: list[dict]) -> list[dict]:
    threshold_p95_ms = _to_float(__import__("os").getenv("IPS_ACTION_P95_MS_MAX", "120"), 120.0)
    threshold_p99_ms = _to_float(__import__("os").getenv("IPS_ACTION_P99_MS_MAX", "300"), 300.0)
    min_samples = int(_to_float(__import__("os").getenv("IPS_ACTION_SLO_MIN_SAMPLES", "20"), 20))
    action_samples: dict[str, list[float]] = {}
    for ev in events:
        if not isinstance(ev, dict):
            continue
        latency_ms = _extract_latency_ms(ev)
        if latency_ms is None:
            continue
        action = str(ev.get("action") or "alert").strip().lower() or "alert"
        action_samples.setdefault(action, []).append(latency_ms)

    breaches = []
    for action, values in action_samples.items():
        if len(values) < min_samples:
            continue
        p95_ms = _percentile(values, 0.95)
        p99_ms = _percentile(values, 0.99)
        if p95_ms > threshold_p95_ms or p99_ms > threshold_p99_ms:
            breaches.append(
                {
                    "action": action,
                    "samples": len(values),
                    "p95_ms": round(p95_ms, 3),
                    "p99_ms": round(p99_ms, 3),
                    "threshold_p95_ms": threshold_p95_ms,
                    "threshold_p99_ms": threshold_p99_ms,
                }
            )
    return breaches


def _e2e_profile_defaults(profile: str) -> dict:
    p = str(profile or "default").strip().lower()
    base = {
        "attack_mitigation_min": 0.9,
        "attack_block_min": 0.5,
        "benign_mitigation_max": 0.1,
        "benign_block_max": 0.02,
        "p95_ms_max": 120.0,
        "p99_ms_max": 300.0,
        "min_labeled_events": 1,
        "scenario_min_events": 1,
        "advanced_threat_coverage_min": 0.55,
        "app_user_context_visibility_min": 0.5,
        "attack_chain_visibility_min": 0.5,
    }
    if p in {"soc_commercial_v1", "commercial", "strict"}:
        return {
            **base,
            "attack_mitigation_min": 0.95,
            "attack_block_min": 0.6,
            "benign_mitigation_max": 0.03,
            "benign_block_max": 0.01,
            "p95_ms_max": 100.0,
            "p99_ms_max": 250.0,
            "min_labeled_events": 100,
            "scenario_min_events": 10,
            "advanced_threat_coverage_min": 0.75,
            "app_user_context_visibility_min": 0.75,
            "attack_chain_visibility_min": 0.75,
        }
    return base


def _scenario_class(name: str) -> str:
    s = str(name or "").strip().lower()
    if any(x in s for x in {"brute", "credential", "stuff"}):
        return "credential_abuse"
    if any(x in s for x in {"scrape", "crawler", "bot"}):
        return "automation"
    if any(x in s for x in {"recon", "scan", "enum"}):
        return "recon"
    if "api" in s and "abuse" in s:
        return "api_abuse"
    if any(x in s for x in {"internal", "noisy"}):
        return "internal_noise"
    if any(x in s for x in {"mobile", "carrier", "fluctuation"}):
        return "mobile_network"
    return "other"


def _evaluate_e2e_events(events: list[dict], thresholds: dict) -> tuple[dict, list[dict]]:
    attack_labels = {"attack", "malicious", "tp", "true_positive"}
    benign_labels = {"benign", "normal", "fp", "false_positive", "noisy_benign"}

    attack_events = 0
    benign_events = 0
    attack_mitigated = 0
    attack_blocked = 0
    benign_mitigated = 0
    benign_blocked = 0
    latency_values = []
    scenario_stats: dict[str, dict] = {}
    unknown_attack_events = 0
    unknown_attack_mitigated = 0
    ti_attack_hits = 0
    sandbox_attack_hits = 0
    app_context_events = 0
    user_context_events = 0
    app_user_context_events = 0
    chain_context_events = 0

    for row in events:
        raw = row.get("raw_event") if isinstance(row.get("raw_event"), dict) else {}
        action = str(raw.get("action") or row.get("action") or "").strip().lower()
        label = str(raw.get("ground_truth") or "").strip().lower()
        scenario = str(
            raw.get("scenario")
            or raw.get("attack_type")
            or raw.get("traffic_type")
            or "unknown"
        ).strip().lower()
        processing_ms = _to_float(raw.get("processing_ms"), -1.0)
        if processing_ms >= 0:
            latency_values.append(processing_ms)

        app_name = str(raw.get("app_name") or raw.get("application") or raw.get("app_id") or "").strip()
        user_name = str(raw.get("user_id") or raw.get("user") or raw.get("username") or raw.get("principal") or "").strip()
        if app_name:
            app_context_events += 1
        if user_name:
            user_context_events += 1
        if app_name and user_name:
            app_user_context_events += 1
        if str(raw.get("kill_chain_stage") or raw.get("attack_chain_stage") or raw.get("chain_id") or raw.get("incident_key") or "").strip():
            chain_context_events += 1

        s = scenario_stats.setdefault(
            scenario,
            {
                "scenario": scenario,
                "total": 0,
                "attack": 0,
                "benign": 0,
                "mitigated": 0,
                "blocked": 0,
                "attack_mitigated": 0,
                "attack_blocked": 0,
                "benign_mitigated": 0,
                "benign_blocked": 0,
            },
        )
        s["total"] += 1
        if _is_mitigated(action):
            s["mitigated"] += 1
        if _is_blocked(action):
            s["blocked"] += 1

        if label in attack_labels:
            attack_events += 1
            s["attack"] += 1
            scenario_lc = scenario.lower()
            is_unknown_like = any(x in scenario_lc for x in {"zero", "0day", "unknown", "apt", "novel"})
            if is_unknown_like:
                unknown_attack_events += 1
            if _is_mitigated(action):
                attack_mitigated += 1
                s["attack_mitigated"] += 1
                if is_unknown_like:
                    unknown_attack_mitigated += 1
            if _is_blocked(action):
                attack_blocked += 1
                s["attack_blocked"] += 1
            ti_hits = raw.get("threat_intel")
            if (isinstance(ti_hits, list) and len(ti_hits) > 0) or bool(raw.get("ti_match")):
                ti_attack_hits += 1
            if bool(raw.get("sandbox_hit")) or str(raw.get("sandbox_verdict") or "").strip().lower() in {"malicious", "suspicious"}:
                sandbox_attack_hits += 1
        elif label in benign_labels:
            benign_events += 1
            s["benign"] += 1
            if _is_mitigated(action):
                benign_mitigated += 1
                s["benign_mitigated"] += 1
            if _is_blocked(action):
                benign_blocked += 1
                s["benign_blocked"] += 1

    attack_mitigation_rate = (attack_mitigated / attack_events) if attack_events else 0.0
    attack_block_rate = (attack_blocked / attack_events) if attack_events else 0.0
    benign_mitigation_rate = (benign_mitigated / benign_events) if benign_events else 0.0
    benign_block_rate = (benign_blocked / benign_events) if benign_events else 0.0

    p95_ms = _percentile(latency_values, 0.95)
    p99_ms = _percentile(latency_values, 0.99)
    unknown_attack_mitigation_rate = (unknown_attack_mitigated / unknown_attack_events) if unknown_attack_events else 0.0
    threat_intel_hit_rate = (ti_attack_hits / attack_events) if attack_events else 0.0
    sandbox_coverage_rate = (sandbox_attack_hits / attack_events) if attack_events else 0.0
    advanced_threat_coverage = (
        (unknown_attack_mitigation_rate + threat_intel_hit_rate + sandbox_coverage_rate) / 3.0
        if attack_events
        else 0.0
    )
    app_context_visibility_rate = (app_context_events / len(events)) if events else 0.0
    user_context_visibility_rate = (user_context_events / len(events)) if events else 0.0
    app_user_context_visibility_rate = (app_user_context_events / len(events)) if events else 0.0
    attack_chain_visibility_rate = (chain_context_events / len(events)) if events else 0.0
    labeled_events = attack_events + benign_events
    min_labeled_events = int(thresholds.get("min_labeled_events", 1))
    passed = (
        labeled_events >= min_labeled_events
        and attack_mitigation_rate >= _to_float(thresholds.get("attack_mitigation_min"), 0.9)
        and attack_block_rate >= _to_float(thresholds.get("attack_block_min"), 0.5)
        and benign_mitigation_rate <= _to_float(thresholds.get("benign_mitigation_max"), 0.1)
        and benign_block_rate <= _to_float(thresholds.get("benign_block_max"), 0.02)
        and p95_ms <= _to_float(thresholds.get("p95_ms_max"), 120.0)
        and p99_ms <= _to_float(thresholds.get("p99_ms_max"), 300.0)
        and advanced_threat_coverage >= _to_float(thresholds.get("advanced_threat_coverage_min"), 0.55)
        and app_user_context_visibility_rate >= _to_float(thresholds.get("app_user_context_visibility_min"), 0.5)
        and attack_chain_visibility_rate >= _to_float(thresholds.get("attack_chain_visibility_min"), 0.5)
    )

    summary = {
        "total_events": len(events),
        "labeled_events": labeled_events,
        "attack_events": attack_events,
        "benign_events": benign_events,
        "attack_mitigated": attack_mitigated,
        "attack_blocked": attack_blocked,
        "benign_mitigated": benign_mitigated,
        "benign_blocked": benign_blocked,
        "attack_mitigation_rate": round(attack_mitigation_rate, 6),
        "attack_block_rate": round(attack_block_rate, 6),
        "benign_mitigation_rate": round(benign_mitigation_rate, 6),
        "benign_block_rate": round(benign_block_rate, 6),
        "p95_ms": round(p95_ms, 3),
        "p99_ms": round(p99_ms, 3),
        "unknown_attack_events": unknown_attack_events,
        "unknown_attack_mitigated": unknown_attack_mitigated,
        "unknown_attack_mitigation_rate": round(unknown_attack_mitigation_rate, 6),
        "threat_intel_hit_rate": round(threat_intel_hit_rate, 6),
        "sandbox_coverage_rate": round(sandbox_coverage_rate, 6),
        "advanced_threat_coverage": round(advanced_threat_coverage, 6),
        "app_context_visibility_rate": round(app_context_visibility_rate, 6),
        "user_context_visibility_rate": round(user_context_visibility_rate, 6),
        "app_user_context_visibility_rate": round(app_user_context_visibility_rate, 6),
        "attack_chain_visibility_rate": round(attack_chain_visibility_rate, 6),
        "passed": bool(passed),
    }
    scenario_min_events = max(1, int(thresholds.get("scenario_min_events", 1)))
    scenarios = []
    for item in sorted(scenario_stats.values(), key=lambda x: x["scenario"]):
        attack = int(item.get("attack") or 0)
        benign = int(item.get("benign") or 0)
        total = int(item.get("total") or 0)
        attack_mitigated = int(item.get("attack_mitigated") or 0)
        benign_mitigated = int(item.get("benign_mitigated") or 0)
        attack_blocked = int(item.get("attack_blocked") or 0)
        benign_blocked = int(item.get("benign_blocked") or 0)
        attack_mitigation_rate = (attack_mitigated / attack) if attack else 0.0
        attack_block_rate = (attack_blocked / attack) if attack else 0.0
        benign_mitigation_rate = (benign_mitigated / benign) if benign else 0.0
        benign_block_rate = (benign_blocked / benign) if benign else 0.0
        scenario_pass = True
        if total < scenario_min_events:
            scenario_pass = False
        if attack and attack_mitigation_rate < _to_float(thresholds.get("attack_mitigation_min"), 0.9):
            scenario_pass = False
        if attack and attack_block_rate < _to_float(thresholds.get("attack_block_min"), 0.5):
            scenario_pass = False
        if benign and benign_mitigation_rate > _to_float(thresholds.get("benign_mitigation_max"), 0.1):
            scenario_pass = False
        if benign and benign_block_rate > _to_float(thresholds.get("benign_block_max"), 0.02):
            scenario_pass = False
        scenarios.append(
            {
                **item,
                "scenario_class": _scenario_class(item.get("scenario")),
                "attack_mitigation_rate": round(attack_mitigation_rate, 6),
                "attack_block_rate": round(attack_block_rate, 6),
                "benign_mitigation_rate": round(benign_mitigation_rate, 6),
                "benign_block_rate": round(benign_block_rate, 6),
                "pass": bool(scenario_pass),
            }
        )
    return summary, scenarios


def _e2e_regressions(current: dict, previous: dict | None) -> list[str]:
    if not isinstance(previous, dict):
        return []
    issues: list[str] = []
    if _to_float(current.get("attack_mitigation_rate"), 0.0) + 1e-9 < _to_float(previous.get("attack_mitigation_rate"), 0.0):
        issues.append("attack_mitigation_rate_down")
    if _to_float(current.get("attack_block_rate"), 0.0) + 1e-9 < _to_float(previous.get("attack_block_rate"), 0.0):
        issues.append("attack_block_rate_down")
    if _to_float(current.get("benign_block_rate"), 0.0) > _to_float(previous.get("benign_block_rate"), 0.0) + 1e-9:
        issues.append("benign_block_rate_up")
    if _to_float(current.get("p95_ms"), 0.0) > _to_float(previous.get("p95_ms"), 0.0) + 1e-9:
        issues.append("p95_ms_up")
    if _to_float(current.get("p99_ms"), 0.0) > _to_float(previous.get("p99_ms"), 0.0) + 1e-9:
        issues.append("p99_ms_up")
    if _to_float(current.get("advanced_threat_coverage"), 0.0) + 1e-9 < _to_float(previous.get("advanced_threat_coverage"), 0.0):
        issues.append("advanced_threat_coverage_down")
    if _to_float(current.get("app_user_context_visibility_rate"), 0.0) + 1e-9 < _to_float(previous.get("app_user_context_visibility_rate"), 0.0):
        issues.append("app_user_context_visibility_down")
    if _to_float(current.get("attack_chain_visibility_rate"), 0.0) + 1e-9 < _to_float(previous.get("attack_chain_visibility_rate"), 0.0):
        issues.append("attack_chain_visibility_down")
    return issues


def _static_response(path: str):
    rel = path.removeprefix("/static/").strip("/")
    target = (BASE_DIR / "static" / rel).resolve()
    if not str(target).startswith(str((BASE_DIR / "static").resolve())) or not target.is_file():
        return _json_response({"ok": False, "error": "not found"}, 404)
    content_type = b"application/octet-stream"
    if target.suffix == ".js":
        content_type = b"application/javascript; charset=utf-8"
    elif target.suffix == ".css":
        content_type = b"text/css; charset=utf-8"
    return 200, [(b"content-type", content_type)], target.read_bytes()


async def app(scope, receive, send):
    if scope["type"] == "websocket":
        await _handle_websocket(scope, receive, send)
        return
    if scope["type"] != "http":
        await send({"type": "http.response.start", "status": 404, "headers": []})
        await send({"type": "http.response.body", "body": b""})
        return

    init_db()
    _audit_maintenance_tick()
    method = scope["method"].upper()
    path = scope["path"]
    if method == "OPTIONS" and path.startswith("/api/"):
        headers = _security_headers(scope, 204) + _cors_headers(scope) + [(b"cache-control", b"no-store")]
        await send({"type": "http.response.start", "status": 204, "headers": headers})
        await send({"type": "http.response.body", "body": b""})
        return
    body = await _read_body(receive)
    allowed, retry_after = _check_rate_limit(scope, path)
    if not allowed:
        status, headers, payload = _json_response(
            {"ok": False, "error": "rate limited", "retry_after_sec": retry_after},
            429,
        )
        headers = headers + [(b"retry-after", str(retry_after).encode("ascii"))]
        headers = headers + _security_headers(scope, status) + _cors_headers(scope) + [(b"cache-control", b"no-store")]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": payload})
        return

    try:
        response = await _dispatch(scope, method, path, body)
    except Exception as exc:
        response = _json_response({"ok": False, "error": f"internal error: {exc}"}, 500)

    status, headers, payload = response
    if path.startswith("/api/v1/admin/"):
        actor = str((_headers(scope).get("x-admin-actor") or "admin")).strip() or "admin"
        result_status = "success" if 200 <= status < 400 else "error"
        record_admin_audit_log(actor=actor, action=f"{method} {path}", status=result_status, path=path, detail=f"status={status}")
    elif path.startswith("/api/v1/integrations/xdr/"):
        result_status = "success" if 200 <= status < 400 else "error"
        record_admin_audit_log(
            actor="xdr_connector",
            action=f"{method} {path}",
            status=result_status,
            path=path,
            detail=f"status={status}",
        )
    headers = headers + _security_headers(scope, status) + _cors_headers(scope) + [(b"cache-control", b"no-store")]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": payload})


async def _handle_websocket(scope, receive, send):
    init_db()
    _audit_maintenance_tick()
    path = scope.get("path", "")
    m = re.fullmatch(r"/ws/secops/workspaces/([^/]+)/?", path)
    if not m:
        await send({"type": "websocket.close", "code": 1008})
        return
    workspace_slug = str(m.group(1) or "").strip() or "lab"
    interval_sec = _env_int("IPS_WS_PUSH_INTERVAL_SEC", 3, 1, 30)
    await send({"type": "websocket.accept"})
    await send(
        {
            "type": "websocket.send",
            "text": json.dumps(
                {
                    "ok": True,
                    "type": "hello",
                    "workspace_slug": workspace_slug,
                    "interval_sec": interval_sec,
                    "ts": datetime.now(timezone.utc).isoformat(),
                },
                ensure_ascii=False,
            ),
        }
    )
    while True:
        payload = {
            "ok": True,
            "type": "summary",
            "workspace_slug": workspace_slug,
            "summary": _dashboard_summary_with_stack_panel(),
        }
        await send({"type": "websocket.send", "text": json.dumps(payload, ensure_ascii=False)})
        try:
            message = await asyncio.wait_for(receive(), timeout=float(interval_sec))
        except asyncio.TimeoutError:
            continue
        if message.get("type") == "websocket.disconnect":
            break
        if message.get("type") == "websocket.receive":
            text = str(message.get("text") or "").strip().lower()
            if text == "close":
                await send({"type": "websocket.close", "code": 1000})
                break
            if text == "ping":
                await send({"type": "websocket.send", "text": json.dumps({"ok": True, "type": "pong"}, ensure_ascii=False)})


async def _dispatch(scope, method: str, path: str, body: bytes):
    if method == "GET" and path == "/":
        html = templates.get_template("index.html").render()
        return _html_response(html)
    if method == "GET" and path == "/healthz":
        return _json_response({"ok": True})
    if method == "GET" and path.startswith("/static/"):
        return _static_response(path)
    if method == "GET" and path == "/api/v1/dashboard/summary/":
        return _json_response(_dashboard_summary_with_stack_panel())
    if method == "GET" and path == "/api/v1/metrics/prometheus":
        return _text_response(_prometheus_metrics(dashboard_summary()), 200, b"text/plain; version=0.0.4; charset=utf-8")

    if method == "GET" and path == "/api/v1/admin/rbac/me/":
        ok, auth_response = _require_admin_auth(scope, min_role="viewer")
        if not ok:
            return auth_response
        return _json_response(
            {
                "ok": True,
                "identity": {
                    "name": str(scope.get("_admin_name") or "admin"),
                    "role": str(scope.get("_admin_role") or "viewer"),
                    "auth_type": str(scope.get("_admin_auth_type") or "unknown"),
                },
                "roles": ["viewer", "operator", "admin"],
            }
        )

    if method == "GET" and path == "/api/v1/admin/workspaces/waf/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        workspace_slug = str((_query_params(scope).get("workspace_slug") or [""])[0]).strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        return _json_response({"ok": True, "waf": get_workspace_setting(workspace_slug)})

    if method == "POST" and path == "/api/v1/admin/workspaces/waf/":
        ok, auth_response = _require_admin_auth(scope, min_role="admin")
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        workspace_slug = str(payload.get("workspace_slug") or "").strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        waf_enabled = bool(payload.get("waf_enabled", True))
        waf_mode = str(payload.get("waf_mode") or "block").strip().lower()
        setting = set_workspace_waf(workspace_slug, waf_enabled=waf_enabled, waf_mode=waf_mode)
        return _json_response({"ok": True, "waf": setting})

    if method == "GET" and path == "/api/v1/admin/workspaces/control-plane/overview/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        workspace_slug = str((_query_params(scope).get("workspace_slug") or [""])[0]).strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        return _json_response({"ok": True, "overview": control_plane_overview(workspace_slug)})

    if method == "GET" and path == "/api/v1/admin/workspaces/kpi-settings/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        workspace_slug = str((_query_params(scope).get("workspace_slug") or [""])[0]).strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        return _json_response({"ok": True, "settings": get_workspace_kpi_setting(workspace_slug)})

    if method == "POST" and path == "/api/v1/admin/workspaces/kpi-settings/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        workspace_slug = str(payload.get("workspace_slug") or "").strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        exclude_test_ip_on_kpi = bool(payload.get("exclude_test_ip_on_kpi", True))
        settings = set_workspace_kpi_setting(
            workspace_slug,
            exclude_test_ip_on_kpi=exclude_test_ip_on_kpi,
        )
        return _json_response({"ok": True, "settings": settings})

    if method == "GET" and path == "/api/v1/admin/workspaces/assets/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        query = _query_params(scope)
        workspace_slug = str((query.get("workspace_slug") or [""])[0]).strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        active_only = str((query.get("active_only") or ["1"])[0]).strip().lower() not in {"0", "false", "off"}
        try:
            limit = int((query.get("limit") or ["300"])[0])
        except ValueError:
            limit = 300
        rows = list_workspace_assets(workspace_slug, active_only=active_only, limit=limit)
        return _json_response({"ok": True, "workspace_slug": workspace_slug, "assets": rows})

    if method == "POST" and path == "/api/v1/admin/workspaces/assets/":
        ok, auth_response = _require_admin_auth(scope, min_role="admin")
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        workspace_slug = str(payload.get("workspace_slug") or "").strip()
        asset_key = str(payload.get("asset_key") or "").strip()
        if not workspace_slug or not asset_key:
            return _json_response({"ok": False, "error": "workspace_slug and asset_key are required"}, 400)
        try:
            row = upsert_workspace_asset(
                workspace_slug,
                asset_key=asset_key,
                display_name=str(payload.get("display_name") or "").strip(),
                host=str(payload.get("host") or "").strip(),
                ip_cidr=str(payload.get("ip_cidr") or "").strip(),
                service_port=payload.get("service_port"),
                exposure=str(payload.get("exposure") or "external").strip(),
                criticality=int(payload.get("criticality") or 3),
                status=str(payload.get("status") or "active").strip(),
                tags=payload.get("tags") if isinstance(payload.get("tags"), list) else [],
                note=str(payload.get("note") or "").strip(),
            )
        except (TypeError, ValueError) as exc:
            return _json_response({"ok": False, "error": str(exc)}, 400)
        return _json_response({"ok": True, "asset": row}, 201)

    if method == "GET" and path == "/api/v1/admin/workspaces/test-ips/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        query = _query_params(scope)
        workspace_slug = str((query.get("workspace_slug") or [""])[0]).strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        active_only = str((query.get("active_only") or ["0"])[0]).strip().lower() in {"1", "true", "on"}
        include_expired = str((query.get("include_expired") or ["1"])[0]).strip().lower() not in {"0", "false", "off"}
        try:
            limit = int((query.get("limit") or ["200"])[0])
        except ValueError:
            limit = 200
        entries = list_test_ip_allowlist(
            workspace_slug,
            active_only=active_only,
            include_expired=include_expired,
            limit=limit,
        )
        return _json_response({"ok": True, "workspace_slug": workspace_slug, "entries": entries})

    if method == "POST" and path == "/api/v1/admin/workspaces/test-ips/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        workspace_slug = str(payload.get("workspace_slug") or "").strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        ip_cidr = str(payload.get("ip_cidr") or "").strip()
        if not ip_cidr:
            return _json_response({"ok": False, "error": "ip_cidr is required"}, 400)
        actor = str((_headers(scope).get("x-admin-actor") or payload.get("actor") or "admin")).strip() or "admin"
        try:
            row = upsert_test_ip_allowlist_entry(
                workspace_slug,
                ip_cidr,
                note=str(payload.get("note") or "").strip(),
                actor=actor,
                expires_at=str(payload.get("expires_at") or "").strip() or None,
            )
        except ValueError as exc:
            return _json_response({"ok": False, "error": str(exc)}, 400)
        return _json_response({"ok": True, "entry": row}, 201)

    m = re.fullmatch(r"/api/v1/admin/workspaces/test-ips/(\d+)/deactivate/?", path)
    if method == "POST" and m:
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        workspace_slug = str(payload.get("workspace_slug") or "").strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        row = set_test_ip_allowlist_status(workspace_slug, int(m.group(1)), status="inactive")
        if not row:
            return _json_response({"ok": False, "error": "entry not found"}, 404)
        return _json_response({"ok": True, "entry": row})

    if method == "GET" and path == "/api/v1/admin/workspaces/policies/active/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        workspace_slug = str((_query_params(scope).get("workspace_slug") or [""])[0]).strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        active = get_active_control_policy(workspace_slug)
        return _json_response({"ok": True, "active_policy": active})

    if method == "GET" and path == "/api/v1/admin/workspaces/policies/versions/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        query = _query_params(scope)
        workspace_slug = str((query.get("workspace_slug") or [""])[0]).strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        try:
            limit = max(1, min(int((query.get("limit") or ["20"])[0]), 200))
        except ValueError:
            limit = 20
        return _json_response({"ok": True, "versions": list_control_policy_versions(workspace_slug, limit=limit)})

    if method == "POST" and path == "/api/v1/admin/workspaces/policies/versions/create/":
        ok, auth_response = _require_admin_auth(scope, min_role="admin")
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        workspace_slug = str(payload.get("workspace_slug") or "").strip()
        policy = payload.get("policy")
        if not workspace_slug or not isinstance(policy, dict):
            return _json_response({"ok": False, "error": "workspace_slug and policy(object) are required"}, 400)
        actor = _headers(scope).get("x-admin-actor", "admin")
        created = create_control_policy_version(
            workspace_slug,
            policy,
            title=str(payload.get("title") or "policy-version").strip()[:160],
            actor=actor,
            note=str(payload.get("note") or "").strip()[:600],
            activate=bool(payload.get("activate", False)),
        )
        return _json_response({"ok": True, "version": created}, 201)

    if method == "POST" and path == "/api/v1/admin/workspaces/policies/publish/":
        ok, auth_response = _require_admin_auth(scope, min_role="admin")
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        workspace_slug = str(payload.get("workspace_slug") or "").strip()
        try:
            version_id = int(payload.get("version_id"))
        except (TypeError, ValueError):
            return _json_response({"ok": False, "error": "version_id is required"}, 400)
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        actor = _headers(scope).get("x-admin-actor", "admin")
        published = publish_control_policy_version(workspace_slug, version_id, actor=actor)
        if not published:
            return _json_response({"ok": False, "error": "policy version not found"}, 404)
        return _json_response({"ok": True, "published": published})

    if method == "GET" and path == "/api/v1/admin/workspaces/policies/distributions/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        query = _query_params(scope)
        workspace_slug = str((query.get("workspace_slug") or [""])[0]).strip()
        sensor_id = str((query.get("sensor_id") or [""])[0]).strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        try:
            limit = max(1, min(int((query.get("limit") or ["50"])[0]), 500))
        except ValueError:
            limit = 50
        rows = list_control_policy_distributions(workspace_slug, sensor_id=sensor_id, limit=limit)
        return _json_response({"ok": True, "distributions": rows})

    if method == "GET" and path == "/api/v1/admin/notifications/channels/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        workspace_slug = str((_query_params(scope).get("workspace_slug") or [""])[0]).strip() or None
        channels = list_notification_channels(workspace_slug=workspace_slug)
        return _json_response({"ok": True, "channels": channels})

    if method == "GET" and path == "/api/v1/admin/notifications/events/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        query = _query_params(scope)
        workspace_slug = str((query.get("workspace_slug") or [""])[0]).strip() or None
        try:
            limit = int((query.get("limit") or ["50"])[0])
        except ValueError:
            limit = 50
        events = list_notification_events(workspace_slug=workspace_slug, limit=limit)
        return _json_response({"ok": True, "events": events})

    if method == "GET" and path == "/api/v1/admin/sensors/summary/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        query = _query_params(scope)
        workspace_slug = str((query.get("workspace_slug") or [""])[0]).strip() or None
        return _json_response({"ok": True, "summary": list_sensors_summary(workspace_slug)})

    if method == "GET" and path == "/api/v1/admin/threat-intel/entries/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        query = _query_params(scope)
        active_only = str((query.get("active_only") or ["1"])[0]).strip() not in {"0", "false", "off"}
        try:
            limit = int((query.get("limit") or ["200"])[0])
        except ValueError:
            limit = 200
        rows = list_threat_intel_entries(active_only=active_only, limit=limit)
        return _json_response({"ok": True, "entries": rows})

    if method == "GET" and path == "/api/v1/admin/threat-intel/sync-runs/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        query = _query_params(scope)
        try:
            limit = int((query.get("limit") or ["50"])[0])
        except ValueError:
            limit = 50
        rows = list_threat_intel_sync_runs(limit=limit)
        return _json_response({"ok": True, "runs": rows})

    if method == "POST" and path == "/api/v1/admin/threat-intel/entries/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        entry = upsert_threat_intel_entry(
            indicator_type=str(payload.get("indicator_type") or "ip"),
            indicator_value=str(payload.get("indicator_value") or ""),
            source=str(payload.get("source") or ""),
            category=str(payload.get("category") or ""),
            severity=str(payload.get("severity") or "medium"),
            confidence=_to_float(payload.get("confidence"), 0.5),
            status=str(payload.get("status") or "active"),
            note=str(payload.get("note") or ""),
            ttl_hours=int(payload.get("ttl_hours")) if payload.get("ttl_hours") is not None else None,
        )
        if not entry:
            return _json_response({"ok": False, "error": "invalid threat intel entry payload"}, 400)
        return _json_response({"ok": True, "entry": entry}, 201)

    if method == "POST" and path == "/api/v1/admin/threat-intel/bulk/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        entries = payload.get("entries")
        if not isinstance(entries, list) or not entries:
            return _json_response({"ok": False, "error": "entries list is required"}, 400)
        try:
            default_ttl_hours = (
                int(payload.get("default_ttl_hours")) if payload.get("default_ttl_hours") is not None else None
            )
        except (TypeError, ValueError):
            return _json_response({"ok": False, "error": "default_ttl_hours must be integer"}, 400)
        result = upsert_threat_intel_entries_bulk(
            entries=entries,
            feed_source=str(payload.get("feed_source") or ""),
            feed_name=str(payload.get("feed_name") or ""),
            feed_version=str(payload.get("feed_version") or ""),
            default_ttl_hours=default_ttl_hours,
        )
        status_code = 202 if int(result.get("accepted_count") or 0) > 0 else 400
        return _json_response({"ok": status_code < 400, **result}, status_code)

    if method == "GET" and path == "/api/v1/admin/threat-intel/lookup/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        query = _query_params(scope)
        ip = str((query.get("ip") or [""])[0]).strip()
        if not ip:
            return _json_response({"ok": False, "error": "ip is required"}, 400)
        matches = lookup_threat_intel_ip_all(ip)
        return _json_response({"ok": True, "ip": ip, "matches": matches, "matched": bool(matches)})

    if method == "GET" and path == "/api/v1/admin/cloud-k8s/connectors/status/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        return _json_response(
            {
                "ok": True,
                "profile": "public_stub",
                "cloud_k8s_connectors_enabled": _cloud_k8s_connectors_enabled(),
                "supports_live_connectors": False,
                "note": "Public profile provides feature-gated stubs only.",
            }
        )

    if method == "POST" and path == "/api/v1/admin/cloud-k8s/audit-events/":
        ok, auth_response = _require_admin_auth(scope, min_role="admin")
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        entries = payload.get("entries")
        if not isinstance(entries, list) or not entries:
            return _json_response({"ok": False, "error": "entries list is required"}, 400)
        if not _cloud_k8s_connectors_enabled():
            return _json_response(
                {
                    "ok": False,
                    "error": "cloud_k8s_connectors_disabled",
                    "profile": "public_stub",
                    "hint": "Set IPS_CLOUD_K8S_CONNECTORS_ENABLED=1 for stub accept mode.",
                },
                503,
            )
        return _json_response(
            {
                "ok": True,
                "profile": "public_stub",
                "accepted_count": len(entries),
                "processed_count": 0,
                "status": "stub_noop",
                "note": "Public distribution does not run cloud/k8s live connectors.",
            },
            202,
        )

    if method == "GET" and path == "/api/v1/admin/ransomware/connectors/status/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        return _json_response(
            {
                "ok": True,
                "profile": "public_stub",
                "ransomware_connectors_enabled": _ransomware_connectors_enabled(),
                "supports_live_connectors": False,
                "note": "Public profile provides feature-gated stubs only.",
            }
        )

    if method == "POST" and path == "/api/v1/admin/ransomware/precursor-events/":
        ok, auth_response = _require_admin_auth(scope, min_role="admin")
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        entries = payload.get("entries")
        if not isinstance(entries, list) or not entries:
            return _json_response({"ok": False, "error": "entries list is required"}, 400)
        if not _ransomware_connectors_enabled():
            return _json_response(
                {
                    "ok": False,
                    "error": "ransomware_connectors_disabled",
                    "profile": "public_stub",
                    "hint": "Set IPS_RANSOMWARE_CONNECTORS_ENABLED=1 for stub accept mode.",
                },
                503,
            )
        return _json_response(
            {
                "ok": True,
                "profile": "public_stub",
                "accepted_count": len(entries),
                "processed_count": 0,
                "status": "stub_noop",
                "note": "Public distribution does not run ransomware live connectors.",
            },
            202,
        )

    if method == "POST" and path == "/api/v1/admin/rules/feedback/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        workspace_slug = str(payload.get("workspace_slug") or "").strip()
        rule_key = str(payload.get("rule_key") or payload.get("signature") or "").strip()
        verdict = str(payload.get("verdict") or "false_positive").strip().lower()
        if not workspace_slug or not rule_key:
            return _json_response({"ok": False, "error": "workspace_slug and rule_key are required"}, 400)
        actor = str((_headers(scope).get("x-admin-actor") or payload.get("actor") or "admin")).strip() or "admin"
        result = record_rule_feedback(
            workspace_slug=workspace_slug,
            rule_key=rule_key,
            verdict=verdict,
            actor=actor,
            note=str(payload.get("note") or "").strip(),
            source_event_key=str(payload.get("source_event_key") or "").strip(),
        )
        if result.get("auto_override"):
            _notify_workspace(
                workspace_slug=workspace_slug,
                event_type="rule_auto_adjusted",
                payload={
                    "title": "Rule auto-adjusted from feedback",
                    "severity": "medium",
                    "message": f"rule={result.get('rule_key')} action=observe fp_rate={result.get('recent_false_positive_rate')}",
                    "workspace_slug": workspace_slug,
                },
            )
        if result.get("auto_recovered"):
            _notify_workspace(
                workspace_slug=workspace_slug,
                event_type="rule_auto_recovered",
                payload={
                    "title": "Rule auto-recovered from feedback",
                    "severity": "info",
                    "message": f"rule={result.get('rule_key')} action=observe->inactive tp_rate={result.get('recent_true_positive_rate')}",
                    "workspace_slug": workspace_slug,
                },
            )
        return _json_response({"ok": True, "result": result}, 201)

    if method == "GET" and path == "/api/v1/admin/rules/feedback/stats/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        query = _query_params(scope)
        workspace_slug = str((query.get("workspace_slug") or [""])[0]).strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        try:
            limit = int((query.get("limit") or ["50"])[0])
        except ValueError:
            limit = 50
        stats = list_rule_feedback_stats(workspace_slug, limit=limit)
        return _json_response({"ok": True, "workspace_slug": workspace_slug, "stats": stats})

    if method == "GET" and path == "/api/v1/admin/rules/overrides/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        query = _query_params(scope)
        workspace_slug = str((query.get("workspace_slug") or [""])[0]).strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        active_only = str((query.get("active_only") or ["1"])[0]).strip() not in {"0", "false", "off"}
        try:
            limit = int((query.get("limit") or ["100"])[0])
        except ValueError:
            limit = 100
        rows = list_rule_overrides(workspace_slug, active_only=active_only, limit=limit)
        return _json_response({"ok": True, "workspace_slug": workspace_slug, "overrides": rows})

    if method == "POST" and path == "/api/v1/admin/rules/overrides/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        workspace_slug = str(payload.get("workspace_slug") or "").strip()
        rule_key = str(payload.get("rule_key") or payload.get("signature") or "").strip()
        action = str(payload.get("action") or "observe").strip().lower()
        if not workspace_slug or not rule_key:
            return _json_response({"ok": False, "error": "workspace_slug and rule_key are required"}, 400)
        actor = str((_headers(scope).get("x-admin-actor") or payload.get("actor") or "admin")).strip() or "admin"
        override = upsert_rule_override(
            workspace_slug=workspace_slug,
            rule_key=rule_key,
            action=action,
            reason=str(payload.get("reason") or "").strip(),
            actor=actor,
            ttl_hours=int(payload.get("ttl_hours") or 24),
        )
        if not override:
            return _json_response({"ok": False, "error": "invalid rule override payload"}, 400)
        return _json_response({"ok": True, "override": override}, 201)

    if method == "GET" and path == "/api/v1/admin/audit/logs/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        query = _query_params(scope)
        try:
            limit = int((query.get("limit") or ["100"])[0])
        except ValueError:
            limit = 100
        return _json_response({"ok": True, "logs": list_admin_audit_logs(limit)})

    if method == "GET" and path == "/api/v1/admin/soc/chain/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        query = _query_params(scope)
        workspace_slug = str((query.get("workspace_slug") or [""])[0]).strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        try:
            hours = int((query.get("hours") or ["24"])[0])
        except ValueError:
            hours = 24
        return _json_response({"ok": True, "workspace_slug": workspace_slug, "chain": soc_chain_summary(workspace_slug, hours)})

    if method == "GET" and path == "/api/v1/admin/soc/incidents/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        query = _query_params(scope)
        workspace_slug = str((query.get("workspace_slug") or [""])[0]).strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        try:
            limit = int((query.get("limit") or ["50"])[0])
        except ValueError:
            limit = 50
        return _json_response({"ok": True, "workspace_slug": workspace_slug, "incidents": list_soc_incidents(workspace_slug, limit)})

    if method == "GET" and path == "/api/v1/admin/xdr/links/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        query = _query_params(scope)
        workspace_slug = str((query.get("workspace_slug") or [""])[0]).strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        try:
            limit = int((query.get("limit") or ["100"])[0])
        except ValueError:
            limit = 100
        return _json_response({"ok": True, "workspace_slug": workspace_slug, "links": list_xdr_event_links(workspace_slug, limit)})

    if method == "POST" and path == "/api/v1/admin/xdr/export/events/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        workspace_slug = str(payload.get("workspace_slug") or "").strip()
        sensor_id = str(payload.get("sensor_id") or "vps-01").strip() or "vps-01"
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        try:
            limit = int(payload.get("limit") or 200)
        except (TypeError, ValueError):
            limit = 200
        result = export_events_to_xdr(workspace_slug=workspace_slug, sensor_id=sensor_id, limit=max(1, min(limit, 5000)))
        code = 200 if bool(result.get("ok")) else 502
        return _json_response({"ok": bool(result.get("ok")), "workspace_slug": workspace_slug, "result": result}, code)

    if method == "GET" and path == "/api/v1/admin/xdr/remote-actions/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        query = _query_params(scope)
        workspace_slug = str((query.get("workspace_slug") or [""])[0]).strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        try:
            limit = int((query.get("limit") or ["100"])[0])
        except ValueError:
            limit = 100
        return _json_response(
            {"ok": True, "workspace_slug": workspace_slug, "actions": list_remote_actions(workspace_slug, max(1, min(limit, 500)))}
        )

    if method == "POST" and path == "/api/v1/admin/xdr/export/heartbeat/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        workspace_slug = str(payload.get("workspace_slug") or "").strip()
        sensor_id_raw = str(payload.get("sensor_id") or "").strip()
        sensor_id = sensor_id_raw or None
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        result = export_source_heartbeat_to_xdr(workspace_slug=workspace_slug, sensor_id=sensor_id)
        code = 200 if bool(result.get("ok")) else 502
        return _json_response({"ok": bool(result.get("ok")), "workspace_slug": workspace_slug, "result": result}, code)

    if method == "GET" and path == "/api/v1/integrations/xdr/source-heartbeat/":
        ok, auth_response = _require_xdr_connector_auth(scope)
        if not ok:
            return auth_response
        query = _query_params(scope)
        workspace_slug = str((query.get("workspace_slug") or [os.getenv("IPROS_DEFAULT_WORKSPACE", "lab")])[0]).strip()
        if workspace_slug not in _xdr_allowed_workspaces():
            return _json_response({"ok": False, "error": "workspace not allowed for xdr connector"}, 403)
        sensor_id_raw = str((query.get("sensor_id") or [""])[0]).strip()
        snapshot = get_source_heartbeat_snapshot(workspace_slug=workspace_slug, sensor_id=(sensor_id_raw or None))
        return _json_response({"ok": True, "heartbeat": snapshot})

    if method == "POST" and path == "/api/v1/integrations/xdr/remote-action/":
        ok, auth_response = _require_xdr_connector_auth(scope)
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        target = payload.get("target")
        if not isinstance(target, dict):
            target = {}
        workspace_slug = str(
            payload.get("workspace_slug")
            or target.get("workspace_slug")
            or os.getenv("IPROS_DEFAULT_WORKSPACE", "lab")
        ).strip()
        if workspace_slug not in _xdr_allowed_workspaces():
            return _json_response({"ok": False, "error": "workspace not allowed for xdr connector"}, 403)
        try:
            xdr_action_id = int(payload.get("action_id"))
        except (TypeError, ValueError):
            xdr_action_id = 0
        if xdr_action_id <= 0:
            return _json_response({"ok": False, "error": "action_id (positive integer) is required"}, 400)
        action_type = str(payload.get("action_type") or "").strip().lower()
        if not action_type:
            return _json_response({"ok": False, "error": "action_type is required"}, 400)
        if action_type not in {"block_ip", "unblock_ip", "set_enforcement"}:
            return _json_response({"ok": False, "error": "unsupported action_type"}, 400)
        remote = upsert_remote_action(
            {
                "workspace_slug": workspace_slug,
                "xdr_action_id": xdr_action_id,
                "incident_id": payload.get("incident_id"),
                "case_id": payload.get("case_id"),
                "action_type": action_type,
                "target": target,
                "requested_by": payload.get("requested_by"),
                "requested_at": payload.get("requested_at"),
                "status": "received",
            }
        )
        # Replay-safe behavior: same xdr_action_id should not trigger a second execution.
        if str(remote.get("status") or "").lower() in {"completed", "failed"} and remote.get("executed_at"):
            return _json_response(
                {
                    "ok": str(remote.get("status") or "").lower() == "completed",
                    "workspace_slug": workspace_slug,
                    "deduplicated": True,
                    "remote_action": remote,
                    "result_summary": remote.get("result_summary"),
                    "result_meta": remote.get("result_meta"),
                },
                200,
            )
        remote_id = int(remote.get("id") or 0)
        result_summary = "unsupported_action_type"
        result_meta: dict = {"action_type": action_type}
        status_value = "failed"
        if action_type == "block_ip":
            target_value = str(target.get("ip") or target.get("target_value") or target.get("value") or "").strip()
            if not target_value:
                return _json_response({"ok": False, "error": "target ip is required for block action"}, 400)
            try:
                ipaddress.ip_address(target_value)
            except ValueError:
                return _json_response({"ok": False, "error": "target ip is invalid"}, 400)
            try:
                ttl_seconds = int(target.get("ttl_seconds") or payload.get("ttl_seconds") or 900)
            except (TypeError, ValueError):
                ttl_seconds = 900
            ttl_seconds = max(30, min(ttl_seconds, 86400))
            stage = str(target.get("stage") or payload.get("stage") or "xdr_remote").strip() or "xdr_remote"
            action = create_block_action(
                {
                    "workspace_slug": workspace_slug,
                    "target_type": "ip",
                    "target_value": target_value,
                    "stage": stage,
                    "ttl_seconds": ttl_seconds,
                    "reason": "xdr_remote_action",
                }
            )
            status_value = "completed"
            result_summary = f"block_action_created:{action.get('id')}"
            result_meta = {"block_action_id": action.get("id"), "target_ip": target_value, "ttl_seconds": ttl_seconds}
        elif action_type == "unblock_ip":
            target_value = str(target.get("ip") or target.get("target_value") or target.get("value") or "").strip()
            if not target_value:
                return _json_response({"ok": False, "error": "target ip is required for unblock action"}, 400)
            try:
                ipaddress.ip_address(target_value)
            except ValueError:
                return _json_response({"ok": False, "error": "target ip is invalid"}, 400)
            canceled = cancel_block_actions_for_target(workspace_slug, "ip", target_value, reason="xdr_remote_unblock")
            status_value = "completed"
            result_summary = f"block_actions_canceled:{canceled}"
            result_meta = {"canceled_count": canceled, "target_ip": target_value}
        elif action_type == "set_enforcement":
            mode = str(target.get("mode") or payload.get("mode") or "block").strip().lower()
            enabled_raw = target.get("enabled")
            if enabled_raw is None:
                enabled_raw = payload.get("enabled", True)
            enabled = bool(enabled_raw)
            setting = set_workspace_waf(workspace_slug, waf_enabled=enabled, waf_mode=mode)
            status_value = "completed"
            result_summary = f"waf_updated:{'on' if enabled else 'off'}:{mode}"
            result_meta = {"waf": setting}
        saved = set_remote_action_result(
            workspace_slug=workspace_slug,
            remote_action_id=remote_id,
            status=status_value,
            result_summary=result_summary,
            result_meta=result_meta,
        )
        code = 200 if status_value == "completed" else 400
        return _json_response(
            {
                "ok": status_value == "completed",
                "workspace_slug": workspace_slug,
                "remote_action": saved or remote,
                "result_summary": result_summary,
                "result_meta": result_meta,
            },
            code,
        )

    m = re.fullmatch(r"/api/v1/admin/soc/incidents/(\d+)/triage/?", path)
    if method == "POST" and m:
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        incident_id = int(m.group(1))
        payload, err = _parse_json_body(body)
        if err:
            return err
        workspace_slug = str(payload.get("workspace_slug") or "").strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        action = str(payload.get("action") or "triage").strip().lower()
        note = str(payload.get("note") or "").strip()
        actor = str((_headers(scope).get("x-admin-actor") or "admin")).strip() or "admin"
        incident = triage_soc_incident(workspace_slug, incident_id, actor=actor, action=action, note=note)
        if not incident:
            return _json_response({"ok": False, "error": "incident not found"}, 404)
        return _json_response({"ok": True, "incident": incident})

    if method == "POST" and path == "/api/v1/admin/e2e/evaluate/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        workspace_slug = str(payload.get("workspace_slug") or "").strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        profile = str(payload.get("profile") or "default").strip() or "default"
        try:
            limit = max(1, min(int(payload.get("limit") or 50000), 200000))
        except (TypeError, ValueError):
            limit = 50000
        try:
            eval_window_hours = max(1, min(int(payload.get("since_hours") or 24), 24 * 30))
        except (TypeError, ValueError):
            eval_window_hours = 24
        since_iso = None
        if "since_iso" in payload and str(payload.get("since_iso") or "").strip():
            since_iso = str(payload.get("since_iso")).strip()
        else:
            if eval_window_hours > 0:
                since_iso = (datetime.now(timezone.utc) - timedelta(hours=eval_window_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        thresholds = payload.get("thresholds") if isinstance(payload.get("thresholds"), dict) else {}
        profile_defaults = _e2e_profile_defaults(profile)
        effective_thresholds = {
            "attack_mitigation_min": _to_float(thresholds.get("attack_mitigation_min"), _to_float(profile_defaults.get("attack_mitigation_min"), 0.9)),
            "attack_block_min": _to_float(thresholds.get("attack_block_min"), _to_float(profile_defaults.get("attack_block_min"), 0.5)),
            "benign_mitigation_max": _to_float(thresholds.get("benign_mitigation_max"), _to_float(profile_defaults.get("benign_mitigation_max"), 0.1)),
            "benign_block_max": _to_float(thresholds.get("benign_block_max"), _to_float(profile_defaults.get("benign_block_max"), 0.02)),
            "p95_ms_max": _to_float(thresholds.get("p95_ms_max"), _to_float(profile_defaults.get("p95_ms_max"), 120.0)),
            "p99_ms_max": _to_float(thresholds.get("p99_ms_max"), _to_float(profile_defaults.get("p99_ms_max"), 300.0)),
            "min_labeled_events": int(thresholds.get("min_labeled_events") or int(profile_defaults.get("min_labeled_events") or 1)),
            "scenario_min_events": int(thresholds.get("scenario_min_events") or int(profile_defaults.get("scenario_min_events") or 1)),
            "advanced_threat_coverage_min": _to_float(
                thresholds.get("advanced_threat_coverage_min"),
                _to_float(profile_defaults.get("advanced_threat_coverage_min"), 0.55),
            ),
            "app_user_context_visibility_min": _to_float(
                thresholds.get("app_user_context_visibility_min"),
                _to_float(profile_defaults.get("app_user_context_visibility_min"), 0.5),
            ),
            "attack_chain_visibility_min": _to_float(
                thresholds.get("attack_chain_visibility_min"),
                _to_float(profile_defaults.get("attack_chain_visibility_min"), 0.5),
            ),
        }
        events = list_security_events_for_eval(workspace_slug=workspace_slug, since_iso=since_iso, limit=limit)
        summary, scenarios = _evaluate_e2e_events(events, effective_thresholds)
        chain_snapshot = soc_chain_summary(workspace_slug, hours=eval_window_hours)
        previous_runs = list_e2e_eval_runs(workspace_slug=workspace_slug, limit=2)
        previous_summary = previous_runs[0]["summary"] if previous_runs else None
        regressions = _e2e_regressions(summary, previous_summary)
        run = save_e2e_eval_run(
            workspace_slug=workspace_slug,
            profile=profile,
            thresholds=effective_thresholds,
            summary=summary,
            scenarios=scenarios,
        )
        if regressions:
            _notify_workspace(
                workspace_slug=workspace_slug,
                event_type="e2e_regression_detected",
                payload={
                    "title": "E2E regression detected",
                    "severity": "high",
                    "message": f"profile={profile} regressions={','.join(regressions)}",
                    "workspace_slug": workspace_slug,
                    "regressions": regressions,
                },
            )
        return _json_response(
            {
                "ok": True,
                "workspace_slug": workspace_slug,
                "profile": profile,
                "since_iso": since_iso,
                "thresholds": effective_thresholds,
                "summary": summary,
                "soc_chain": chain_snapshot,
                "scenarios": scenarios,
                "regressions": regressions,
                "run": run,
            },
            201,
        )

    if method == "GET" and path == "/api/v1/admin/e2e/profiles/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        profiles = {
            "default": _e2e_profile_defaults("default"),
            "soc_commercial_v1": _e2e_profile_defaults("soc_commercial_v1"),
        }
        return _json_response({"ok": True, "profiles": profiles})

    if method == "GET" and path == "/api/v1/admin/e2e/runs/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        query = _query_params(scope)
        workspace_slug = str((query.get("workspace_slug") or [""])[0]).strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        try:
            limit = int((query.get("limit") or ["20"])[0])
        except ValueError:
            limit = 20
        runs = list_e2e_eval_runs(workspace_slug=workspace_slug, limit=limit)
        return _json_response({"ok": True, "workspace_slug": workspace_slug, "runs": runs})

    if method == "POST" and path == "/api/v1/admin/notifications/channels/":
        ok, auth_response = _require_admin_auth(scope, min_role="admin")
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        workspace_slug = str(payload.get("workspace_slug") or "").strip()
        channel_type = str(payload.get("channel_type") or "").strip().lower()
        webhook_url = str(payload.get("webhook_url") or "").strip()
        if not workspace_slug or channel_type not in {"discord", "slack", "grafana", "webhook"}:
            return _json_response({"ok": False, "error": "workspace_slug / channel_type / webhook_url are invalid"}, 400)
        ok_url, reason = _validate_webhook_url(webhook_url)
        if not ok_url:
            return _json_response({"ok": False, "error": reason}, 400)
        channel = upsert_notification_channel(
            {
                "workspace_slug": workspace_slug,
                "channel_type": channel_type,
                "webhook_url": webhook_url,
                "is_enabled": bool(payload.get("is_enabled", True)),
                "secret_token": str(payload.get("secret_token") or ""),
            }
        )
        return _json_response({"ok": True, "channel": channel}, 201)

    if method == "POST" and path == "/api/v1/admin/notifications/test/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        workspace_slug = str(payload.get("workspace_slug") or "").strip()
        if not workspace_slug:
            return _json_response({"ok": False, "error": "workspace_slug is required"}, 400)
        result = _notify_workspace(
            workspace_slug=workspace_slug,
            event_type="notify_test",
            payload={
                "title": "exkururuIPROS NGIPS Notification Test",
                "severity": "info",
                "message": "Webhook integration test succeeded.",
                "workspace_slug": workspace_slug,
            },
        )
        return _json_response({"ok": True, **result})

    if method == "POST" and path == "/api/v1/admin/sensors/register/":
        ok, auth_response = _require_admin_auth(scope, min_role="admin")
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        required = ["workspace_slug", "sensor_id", "name", "shared_secret"]
        if any(not str(payload.get(k) or "").strip() for k in required):
            return _json_response({"ok": False, "error": "missing required fields"}, 400)
        workspace_slug = str(payload["workspace_slug"]).strip()
        sensor_id = str(payload["sensor_id"]).strip()
        shard_count = _ingest_shard_count()
        default_shard = _sensor_home_shard(workspace_slug, sensor_id, shard_count)
        meta_json = payload.get("meta_json") if isinstance(payload.get("meta_json"), dict) else {}
        meta_json = dict(meta_json)
        if "ingest_shard" not in meta_json:
            meta_json["ingest_shard"] = int(default_shard)
        if "ingest_shard_count" not in meta_json:
            meta_json["ingest_shard_count"] = int(shard_count)
        sensor = register_sensor(
            {
                "workspace_slug": workspace_slug,
                "sensor_id": sensor_id,
                "name": str(payload["name"]).strip(),
                "sensor_type": str(payload.get("sensor_type") or "hybrid").strip(),
                "policy_mode": str(payload.get("policy_mode") or "balanced").strip(),
                "shared_secret": str(payload["shared_secret"]).strip(),
                "meta_json": meta_json,
            }
        )
        sensor.pop("shared_secret", None)
        return _json_response({"ok": True, "sensor": sensor}, 201)

    if method == "POST" and path == "/api/v1/admin/actions/block/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        if not str(payload.get("workspace_slug") or "").strip() or not str(payload.get("target_value") or "").strip():
            return _json_response({"ok": False, "error": "workspace_slug and target_value are required"}, 400)
        action = create_block_action(
            {
                "workspace_slug": str(payload["workspace_slug"]).strip(),
                "target_type": str(payload.get("target_type") or "ip").strip(),
                "target_value": str(payload["target_value"]).strip(),
                "stage": str(payload.get("stage") or "xdp_short").strip(),
                "ttl_seconds": int(payload.get("ttl_seconds") or 300),
                "reason": str(payload.get("reason") or "").strip(),
            }
        )
        if action.get("status") == "pending":
            _notify_workspace(
                workspace_slug=action["workspace_slug"],
                event_type="block_action_created",
                payload={
                    "title": "WAF block action queued",
                    "severity": "medium",
                    "message": f"target={action['target_value']} stage={action['stage']} ttl={action['ttl_seconds']}s",
                    "workspace_slug": action["workspace_slug"],
                    "action_id": action["id"],
                },
            )
        return _json_response({"ok": True, "action": action}, 201)

    if method == "POST" and path == "/api/v1/admin/logs/ingest/":
        ok, auth_response = _require_admin_auth(scope)
        if not ok:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        lines = payload.get("lines", [])
        if not isinstance(lines, list):
            return _json_response({"ok": False, "error": "lines must be list"}, 400)
        upsert_metrics(aggregate_lines([str(line) for line in lines]))
        return _json_response({"ok": True, "accepted_lines": len(lines)})

    m = re.fullmatch(r"/api/v1/workspaces/([^/]+)/sensors/([^/]+)/policy/?", path)
    if method == "GET" and m:
        workspace_slug, sensor_id = m.groups()
        sensor, auth_response = _authenticate_sensor(scope, workspace_slug, sensor_id, b"")
        if auth_response:
            return auth_response
        setting = get_workspace_setting(workspace_slug)
        active_policy = get_active_control_policy(workspace_slug)
        policy = dict(active_policy.get("policy_json") or {})
        if not isinstance(policy, dict):
            policy = {}
        if not policy:
            policy = {
                "mode": sensor["policy_mode"],
                "short_ttl_sec": 300,
                "long_ttl_sec": 3600,
                "rate_threshold_pps": 2000,
                "whitelist_cidr": [],
            }
        if "mode" not in policy:
            policy["mode"] = sensor["policy_mode"]
        meta_policy = (sensor.get("meta_json") or {}).get("policy")
        if isinstance(meta_policy, dict):
            policy.update(meta_policy)
        pending_dist = get_pending_policy_distribution(workspace_slug, sensor_id)
        policy["rule_overrides"] = list_rule_overrides(workspace_slug, active_only=True, limit=200)
        return _json_response(
            {
                "ok": True,
                "workspace": workspace_slug,
                "sensor_id": sensor_id,
                "sensor_type": sensor["sensor_type"],
                "waf_enabled": bool(setting.get("waf_enabled")),
                "waf_mode": setting.get("waf_mode", "block"),
                "effective_policy": policy,
                "control_plane": {
                    "policy_version_id": active_policy.get("id"),
                    "policy_version_no": active_policy.get("version_no"),
                    "distribution_id": pending_dist.get("id") if isinstance(pending_dist, dict) else None,
                    "published_at": active_policy.get("activated_at"),
                },
            }
        )

    m = re.fullmatch(r"/api/v1/workspaces/([^/]+)/sensors/([^/]+)/policy/ack/?", path)
    if method == "POST" and m:
        workspace_slug, sensor_id = m.groups()
        sensor, auth_response = _authenticate_sensor(scope, workspace_slug, sensor_id, body)
        if auth_response:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        try:
            distribution_id = int(payload.get("distribution_id"))
        except (TypeError, ValueError):
            return _json_response({"ok": False, "error": "distribution_id is required"}, 400)
        status_value = str(payload.get("status") or "").strip().lower()
        if status_value not in {"applied", "failed", "ignored"}:
            return _json_response({"ok": False, "error": "invalid status"}, 400)
        acked = ack_policy_distribution(
            workspace_slug,
            sensor["sensor_id"],
            distribution_id,
            status_value,
            detail=payload.get("meta") if isinstance(payload.get("meta"), dict) else {},
        )
        if not acked:
            return _json_response({"ok": False, "error": "distribution not found"}, 404)
        return _json_response({"ok": True, "distribution": acked})

    m = re.fullmatch(r"/api/v1/workspaces/([^/]+)/sensors/([^/]+)/actions/pending/?", path)
    if method == "GET" and m:
        workspace_slug, sensor_id = m.groups()
        sensor, auth_response = _authenticate_sensor(scope, workspace_slug, sensor_id, b"")
        if auth_response:
            return auth_response
        query = _query_params(scope)
        try:
            limit = max(1, min(int((query.get("limit") or ["50"])[0]), 200))
        except ValueError:
            limit = 50
        return _json_response({"ok": True, "sensor_id": sensor["sensor_id"], "actions": fetch_pending_actions(workspace_slug, sensor_id, limit)})

    m = re.fullmatch(r"/api/v1/workspaces/([^/]+)/sensors/([^/]+)/actions/(\d+)/ack/?", path)
    if method == "POST" and m:
        workspace_slug, sensor_id, action_id = m.groups()
        sensor, auth_response = _authenticate_sensor(scope, workspace_slug, sensor_id, body)
        if auth_response:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        status_value = str(payload.get("status") or "").strip().lower()
        if status_value not in {"applied", "failed", "canceled"}:
            return _json_response({"ok": False, "error": "invalid status"}, 400)
        action = ack_action(workspace_slug, int(action_id), sensor["sensor_id"], status_value, payload.get("meta") or {})
        if not action:
            return _json_response({"ok": False, "error": "action not found"}, 404)
        if status_value in {"failed", "canceled"}:
            _notify_workspace(
                workspace_slug=workspace_slug,
                event_type="block_action_ack",
                payload={
                    "title": "WAF action acknowledge",
                    "severity": "high" if status_value == "failed" else "info",
                    "message": f"action_id={action_id} status={status_value}",
                    "workspace_slug": workspace_slug,
                    "action_id": int(action_id),
                },
            )
        return _json_response({"ok": True, "action_id": int(action_id), "status": status_value})

    m = re.fullmatch(r"/api/v1/workspaces/([^/]+)/sensors/([^/]+)/events/batch/?", path)
    if method == "POST" and m:
        workspace_slug, sensor_id = m.groups()
        sensor, auth_response = _authenticate_sensor(scope, workspace_slug, sensor_id, body)
        if auth_response:
            return auth_response
        payload, err = _parse_json_body(body)
        if err:
            return err
        events = payload if isinstance(payload, list) else payload.get("events", [])
        if not isinstance(events, list):
            return _json_response({"ok": False, "error": "events must be list"}, 400)
        headers = _headers(scope)
        ts_raw = headers.get("x-ips-timestamp", "").strip()
        sig_raw = headers.get("x-ips-signature", "").strip()
        nonce_raw = headers.get("x-ips-nonce", "").strip()
        for source_key in _extract_source_event_keys(events):
            scoped_raw = f"{workspace_slug}:{sensor_id}:{source_key}:{ts_raw}:{sig_raw}:{nonce_raw}"
            if not replay_guard_add(scoped_raw):
                return _json_response(
                    {
                        "ok": False,
                        "error": "replay_detected",
                        "source_event_key": source_key,
                    },
                    409,
                )
        shard_count = _ingest_shard_count()
        node_shard_index = _ingest_shard_index(shard_count)
        sensor_meta = sensor.get("meta_json") if isinstance(sensor.get("meta_json"), dict) else {}
        try:
            sensor_shard = int(sensor_meta.get("ingest_shard"))
        except (TypeError, ValueError):
            sensor_shard = _sensor_home_shard(workspace_slug, sensor["sensor_id"], shard_count)
        sensor_shard = max(0, min(sensor_shard, max(0, shard_count - 1)))
        owned_by_node = bool(sensor_shard == node_shard_index)
        enforce_shard = _ingest_shard_enforce()
        if enforce_shard and not owned_by_node:
            return _json_response(
                {
                    "ok": False,
                    "error": "sensor_not_owned_by_this_shard",
                    "workspace_slug": workspace_slug,
                    "sensor_id": sensor["sensor_id"],
                    "sensor_shard": sensor_shard,
                    "node_shard_index": node_shard_index,
                    "shard_count": shard_count,
                },
                409,
            )
        result = insert_security_events(workspace_slug, sensor["sensor_id"], events)
        incident_result = result.get("incident_result") if isinstance(result.get("incident_result"), dict) else {}
        created_incidents = int(incident_result.get("created") or 0)
        if created_incidents > 0:
            _notify_workspace(
                workspace_slug=workspace_slug,
                event_type="soc_incident_created",
                payload={
                    "title": "SOC incident created",
                    "severity": "high",
                    "message": f"new_incidents={created_incidents}",
                    "workspace_slug": workspace_slug,
                },
            )
        threat_intel_hits = int(result.get("threat_intel_hits") or 0)
        if threat_intel_hits > 0:
            _notify_workspace(
                workspace_slug=workspace_slug,
                event_type="threat_intel_hit",
                payload={
                    "title": "Threat intel match detected",
                    "severity": "high",
                    "message": f"matched_events={threat_intel_hits}",
                    "workspace_slug": workspace_slug,
                },
            )
        flow_anomaly_hits = int(result.get("flow_anomaly_hits") or 0)
        if flow_anomaly_hits > 0:
            _notify_workspace(
                workspace_slug=workspace_slug,
                event_type="flow_anomaly_detected",
                payload={
                    "title": "Flow anomaly detected",
                    "severity": "high",
                    "message": f"flow_anomaly_events={flow_anomaly_hits}",
                    "workspace_slug": workspace_slug,
                    "signals": result.get("flow_signal_counts") or {},
                },
            )
        breaches = _evaluate_action_latency_breaches(events)
        if breaches:
            bucket = _bucket_5m_utc()
            for breach in breaches:
                created = record_action_latency_alert(
                    workspace_slug=workspace_slug,
                    bucket=bucket,
                    action=str(breach["action"]),
                    p95_ms=float(breach["p95_ms"]),
                    p99_ms=float(breach["p99_ms"]),
                    threshold_p95_ms=float(breach["threshold_p95_ms"]),
                    threshold_p99_ms=float(breach["threshold_p99_ms"]),
                )
                if not created:
                    continue
                _notify_workspace(
                    workspace_slug=workspace_slug,
                    event_type="action_latency_slo_breach",
                    payload={
                        "title": "Action latency SLO breached",
                        "severity": "high",
                        "message": (
                            f"action={breach['action']} p95={breach['p95_ms']}ms "
                            f"p99={breach['p99_ms']}ms samples={breach['samples']}"
                        ),
                        "workspace_slug": workspace_slug,
                        "bucket": bucket,
                        "threshold_p95_ms": breach["threshold_p95_ms"],
                        "threshold_p99_ms": breach["threshold_p99_ms"],
                    },
                )
        high_hits = 0
        for ev in events:
            severity = str((ev or {}).get("severity") or "").strip().lower()
            if severity in {"critical", "high"}:
                high_hits += 1
        if high_hits > 0:
            _notify_workspace(
                workspace_slug=workspace_slug,
                event_type="security_events_high",
                payload={
                    "title": "High severity IPS events detected",
                    "severity": "high",
                    "message": f"high_events={high_hits}, accepted={result.get('accepted', 0)}",
                    "workspace_slug": workspace_slug,
                },
            )
        return _json_response(
            {
                "ok": True,
                "sensor_id": sensor["sensor_id"],
                "latency_breaches": breaches,
                "sharding": {
                    "sensor_shard": sensor_shard,
                    "node_shard_index": node_shard_index,
                    "shard_count": shard_count,
                    "owned_by_node": owned_by_node,
                    "enforce": enforce_shard,
                },
                **result,
            }
        )

    if path.startswith("/api/"):
        return _json_response({"ok": False, "error": "not found"}, 404)
    return _text_response(f"{method} {path} not found", 404)


def _to_float(value, default: float = 0.0) -> float:
    return _to_float_impl(value, default)


def _percentile(values: list[float], p: float) -> float:
    return _percentile_impl(values, p)


def _is_mitigated(action: str) -> bool:
    return _is_mitigated_impl(action)


def _is_blocked(action: str) -> bool:
    return _is_blocked_impl(action)


def _bucket_5m_utc() -> str:
    return _bucket_5m_utc_impl()


def _extract_latency_ms(event: dict) -> float | None:
    return _extract_latency_ms_impl(event)


def _evaluate_action_latency_breaches(events: list[dict]) -> list[dict]:
    return _evaluate_action_latency_breaches_impl(events)


def _e2e_profile_defaults(profile: str) -> dict:
    return _e2e_profile_defaults_impl(profile)


def _scenario_class(name: str) -> str:
    return _scenario_class_impl(name)


def _evaluate_e2e_events(events: list[dict], thresholds: dict) -> tuple[dict, list[dict]]:
    return _evaluate_e2e_events_impl(events, thresholds)


def _e2e_regressions(current: dict, previous: dict | None) -> list[str]:
    return _e2e_regressions_impl(current, previous)
