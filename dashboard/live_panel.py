from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any

from .storage import dashboard_summary


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


def _to_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _http_json_get(url: str, *, headers: dict[str, str] | None = None, timeout_sec: float = 1.5) -> tuple[bool, int, dict, str, float]:
    started = time.monotonic()
    req = __import__("urllib.request").request.Request(url, headers=headers or {}, method="GET")
    try:
        with __import__("urllib.request").request.urlopen(req, timeout=float(timeout_sec)) as resp:
            status_code = int(getattr(resp, "status", 200))
            raw_body = resp.read()
        elapsed_ms = (time.monotonic() - started) * 1000.0
    except __import__("urllib.error").error.HTTPError as exc:
        elapsed_ms = (time.monotonic() - started) * 1000.0
        try:
            raw = exc.read().decode("utf-8")
            payload = json.loads(raw) if raw else {}
        except Exception:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        return False, int(exc.code), payload, f"http_error:{exc.code}", round(elapsed_ms, 3)
    except Exception as exc:
        elapsed_ms = (time.monotonic() - started) * 1000.0
        return False, 0, {}, f"url_error:{exc}", round(elapsed_ms, 3)
    try:
        payload = json.loads(raw_body.decode("utf-8") or "{}")
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    return 200 <= status_code < 300, status_code, payload, "", round(elapsed_ms, 3)


def _probe_xdr_live(timeout_sec: float) -> dict[str, object]:
    base_url = str(os.getenv("IPROS_XDR_BASE_URL", "http://127.0.0.1:8810") or "").strip().rstrip("/")
    if not base_url:
        return {"service": "xdr", "configured": False, "reachable": False, "status": "not_configured", "latency_ms": None, "dashboard_url": "", "health": {}, "metrics": {}, "error": ""}
    ok, status_code, health_payload, error, latency_ms = _http_json_get(f"{base_url}/healthz", timeout_sec=timeout_sec)
    service = {
        "service": "xdr",
        "configured": True,
        "reachable": bool(ok),
        "status": "ok" if ok else "down",
        "latency_ms": latency_ms,
        "dashboard_url": f"{base_url}/dashboard",
        "health": {"sources": _to_int(health_payload.get("sources"), 0), "events": _to_int(health_payload.get("events"), 0)},
        "metrics": {},
        "error": str(error or ""),
    }
    admin_token = str(os.getenv("IPROS_XDR_ADMIN_TOKEN", "") or "").strip()
    if admin_token:
        headers = {"Authorization": f"Bearer {admin_token}"}
        incidents_ok, _, incidents_payload, incidents_error, _ = _http_json_get(f"{base_url}/api/v1/incidents?limit=100", headers=headers, timeout_sec=timeout_sec)
        if incidents_ok:
            items = incidents_payload.get("items") if isinstance(incidents_payload.get("items"), list) else []
            open_count = 0
            for item in items:
                if not isinstance(item, dict):
                    continue
                status_value = str(item.get("status") or "open").strip().lower()
                if status_value in {"open", "new"}:
                    open_count += 1
            service["metrics"]["incident_sample_count"] = len(items)
            service["metrics"]["incident_open_sample"] = open_count
        elif incidents_error:
            service["metrics"]["incident_fetch_error"] = incidents_error
        actions_ok, _, actions_payload, actions_error, _ = _http_json_get(f"{base_url}/api/v1/actions?limit=100", headers=headers, timeout_sec=timeout_sec)
        if actions_ok:
            items = actions_payload.get("items") if isinstance(actions_payload.get("items"), list) else []
            requested_count = 0
            completed_count = 0
            for item in items:
                if not isinstance(item, dict):
                    continue
                status_value = str(item.get("status") or "").strip().lower()
                if status_value in {"requested", "pending", "queued"}:
                    requested_count += 1
                if status_value in {"completed", "done", "acked"}:
                    completed_count += 1
            service["metrics"]["action_sample_count"] = len(items)
            service["metrics"]["action_requested_sample"] = requested_count
            service["metrics"]["action_completed_sample"] = completed_count
        elif actions_error:
            service["metrics"]["action_fetch_error"] = actions_error
    else:
        service["metrics"]["admin_api"] = "token_not_set"
    return service


def _probe_soc_live(timeout_sec: float) -> dict[str, object]:
    base_url = str(os.getenv("IPROS_SOC_BASE_URL", "http://127.0.0.1:8820") or "").strip().rstrip("/")
    if not base_url:
        return {"service": "soc", "configured": False, "reachable": False, "status": "not_configured", "latency_ms": None, "dashboard_url": "", "health": {}, "metrics": {}, "error": ""}
    ok, _, health_payload, error, latency_ms = _http_json_get(f"{base_url}/healthz", timeout_sec=timeout_sec)
    service = {
        "service": "soc",
        "configured": True,
        "reachable": bool(ok),
        "status": "ok" if ok else "down",
        "latency_ms": latency_ms,
        "dashboard_url": f"{base_url}/secops/soc/dashboard/",
        "health": {"status": str(health_payload.get("status") or ""), "service_name": str(health_payload.get("service") or ""), "env": str(health_payload.get("env") or "")},
        "metrics": {},
        "error": str(error or ""),
    }
    admin_token = str(os.getenv("IPROS_SOC_ADMIN_TOKEN", "") or "").strip()
    if admin_token:
        cmd_ok, _, cmd_payload, cmd_error, _ = _http_json_get(f"{base_url}/api/v1/command-center", headers={"x-admin-token": admin_token}, timeout_sec=timeout_sec)
        if cmd_ok:
            service["metrics"]["candidate_count"] = _to_int(cmd_payload.get("candidate_count"), 0)
            service["metrics"]["source_count"] = _to_int(cmd_payload.get("source_count"), 0)
            service["metrics"]["source_active_count"] = _to_int(cmd_payload.get("source_active_count"), 0)
            status_counts = cmd_payload.get("candidate_status_counts")
            if isinstance(status_counts, dict):
                service["metrics"]["candidate_status_counts"] = {str(k): _to_int(v, 0) for k, v in status_counts.items()}
        elif cmd_error:
            service["metrics"]["command_center_error"] = cmd_error
    else:
        service["metrics"]["admin_api"] = "token_not_set"
    return service


def _probe_edr_live(timeout_sec: float) -> dict[str, object]:
    base_url = str(os.getenv("IPROS_EDR_BASE_URL", "") or "").strip().rstrip("/")
    if not base_url:
        return {"service": "edr", "configured": False, "reachable": False, "status": "not_configured", "latency_ms": None, "dashboard_url": "", "health": {}, "metrics": {}, "error": ""}
    ok, _, health_payload, error, latency_ms = _http_json_get(f"{base_url}/healthz", timeout_sec=timeout_sec)
    service = {
        "service": "edr",
        "configured": True,
        "reachable": bool(ok),
        "status": "ok" if ok else "down",
        "latency_ms": latency_ms,
        "dashboard_url": f"{base_url}/dashboard",
        "health": {"events": _to_int(health_payload.get("events"), 0)},
        "metrics": {},
        "error": str(error or ""),
    }
    alerts_ok, _, alerts_payload, alerts_error, _ = _http_json_get(f"{base_url}/api/v1/alerts?limit=50", timeout_sec=timeout_sec)
    if alerts_ok:
        alerts = alerts_payload.get("alerts") if isinstance(alerts_payload.get("alerts"), list) else []
        service["metrics"]["alert_sample_count"] = len(alerts)
    elif alerts_error:
        service["metrics"]["alert_fetch_error"] = alerts_error
    responses_ok, _, responses_payload, responses_error, _ = _http_json_get(f"{base_url}/api/v1/responses?limit=50", timeout_sec=timeout_sec)
    if responses_ok:
        responses = responses_payload.get("responses") if isinstance(responses_payload.get("responses"), list) else []
        service["metrics"]["response_sample_count"] = len(responses)
    elif responses_error:
        service["metrics"]["response_fetch_error"] = responses_error
    return service


def stack_live_panel() -> dict[str, object]:
    cache_sec = _env_int("IPS_STACK_LIVE_CACHE_SEC", 10, 1, 120)
    now_mono = time.monotonic()
    timeout_sec = _env_float("IPS_STACK_LIVE_HTTP_TIMEOUT_SEC", 1.5, 0.2, 10.0)
    services = [_probe_xdr_live(timeout_sec), _probe_soc_live(timeout_sec), _probe_edr_live(timeout_sec)]
    configured_services = sum(1 for item in services if bool(item.get("configured")))
    reachable_services = sum(1 for item in services if bool(item.get("reachable")))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cache_sec": cache_sec,
        "services": services,
        "summary": {
            "configured_services": configured_services,
            "reachable_services": reachable_services,
            "all_reachable": configured_services > 0 and configured_services == reachable_services,
        },
        "cached_at": now_mono,
    }


def dashboard_summary_with_stack_panel() -> dict:
    payload = dict(dashboard_summary())
    integration = payload.get("integration") if isinstance(payload.get("integration"), dict) else {}
    integration = dict(integration)
    integration["live_panel"] = stack_live_panel()
    payload["integration"] = integration
    return payload


def http_json_get(url: str, *, headers: dict[str, str] | None = None, timeout_sec: float = 1.5) -> tuple[bool, int, dict, str, float]:
    return _http_json_get(url, headers=headers, timeout_sec=timeout_sec)


def probe_xdr_live(timeout_sec: float) -> dict[str, object]:
    return _probe_xdr_live(timeout_sec)


def probe_soc_live(timeout_sec: float) -> dict[str, object]:
    return _probe_soc_live(timeout_sec)


def probe_edr_live(timeout_sec: float) -> dict[str, object]:
    return _probe_edr_live(timeout_sec)
