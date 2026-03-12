from __future__ import annotations

import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .storage import (
    get_source_heartbeat_snapshot,
    list_security_events_for_eval,
    resolve_event_incident_links,
    upsert_xdr_event_links,
)


def _base_url() -> str:
    return str(os.getenv("IPROS_XDR_BASE_URL", "http://127.0.0.1:8810")).rstrip("/")


def _source_key(workspace_slug: str) -> str:
    return str(os.getenv("IPROS_XDR_SOURCE_KEY", f"ipros-{workspace_slug}"))


def _display_name() -> str:
    return str(os.getenv("IPROS_XDR_DISPLAY_NAME", "EXkururuIPROS Export"))


def _timeout_sec() -> int:
    raw = str(os.getenv("IPROS_XDR_TIMEOUT_SEC", "5")).strip()
    try:
        return max(1, min(int(raw), 30))
    except ValueError:
        return 5


def _to_common_security_event(row: dict, link: dict | None) -> dict:
    raw = row.get("raw_event") if isinstance(row.get("raw_event"), dict) else {}
    event_id = str(row.get("source_event_key") or raw.get("event_id") or "")
    severity = str(row.get("severity") or raw.get("severity") or "medium").lower()
    score = raw.get("score")
    try:
        score_v = float(score)
    except (TypeError, ValueError):
        score_v = 80.0 if severity in {"high", "critical"} else 50.0
    labels = raw.get("labels")
    if not isinstance(labels, list):
        labels = ["ipros", "export"]
    payload = {
        "schema_version": "common_security_event_v1",
        "event_id": event_id,
        "time": str(row.get("detected_at") or raw.get("detected_at") or ""),
        "product": "exkururuipros",
        "category": str(raw.get("category") or "network"),
        "event_type": str(raw.get("signature") or raw.get("rule") or "IPROS_EVENT"),
        "severity": severity,
        "score": max(0.0, min(100.0, score_v)),
        "labels": labels,
        "src_ip": raw.get("src_ip") or None,
        "dst_ip": raw.get("dst_ip") or None,
        "raw_ref": f"ipros:{event_id}",
    }
    if link:
        payload["local_incident_id"] = link.get("local_incident_id")
        payload["local_correlation_key"] = link.get("local_correlation_key")
    return payload


def _post_json(path: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    url = _base_url() + path
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = Request(url=url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=_timeout_sec()) as resp:
            parsed = json.loads(resp.read().decode("utf-8") or "{}")
            if not isinstance(parsed, dict):
                parsed = {"raw": parsed}
            return int(resp.getcode()), parsed
    except HTTPError as exc:
        raw = exc.read().decode("utf-8") if exc.fp else ""
        return int(exc.code), {"error": raw or str(exc)}
    except URLError as exc:
        return 0, {"error": f"url_error:{exc}"}


def _ensure_source(workspace_slug: str) -> tuple[bool, int, dict[str, Any]]:
    source_key = _source_key(workspace_slug)
    status, source_resp = _post_json(
        "/api/v1/sources",
        {"source_key": source_key, "product": "exkururuipros", "display_name": _display_name()},
    )
    return status in {201, 409}, status, source_resp


def export_events_to_xdr(workspace_slug: str, sensor_id: str, limit: int = 200) -> dict[str, Any]:
    rows = list_security_events_for_eval(workspace_slug, since_iso=None, limit=max(1, limit))
    links = resolve_event_incident_links(workspace_slug, sensor_id, rows)
    links_by_key = {str(x.get("source_event_key") or ""): x for x in links}
    events = []
    link_rows = []
    for row in rows:
        key = str(row.get("source_event_key") or "")
        link = links_by_key.get(key)
        payload = _to_common_security_event(row, link)
        events.append(payload)
        link_rows.append(
            {
                "source_event_key": key,
                "local_incident_id": (link or {}).get("local_incident_id"),
                "local_correlation_key": (link or {}).get("local_correlation_key"),
                "xdr_event_id": payload.get("event_id"),
                "export_status": "prepared",
                "detail": {"workspace_slug": workspace_slug},
            }
        )

    source_key = _source_key(workspace_slug)
    source_ok, status, source_resp = _ensure_source(workspace_slug)
    if not source_ok:
        return {"ok": False, "stage": "create_source", "status": status, "response": source_resp}

    status, resp = _post_json(
        "/api/v1/import/json",
        {
            "source_key": source_key,
            "display_name": _display_name(),
            "product": "exkururuipros",
            "events": events,
        },
    )
    ok = 200 <= status < 300
    for row in link_rows:
        row["export_status"] = "exported" if ok else "failed"
        row["detail"] = {"status": status, "response": resp}
    saved_links = upsert_xdr_event_links(workspace_slug, sensor_id, source_key, link_rows)
    return {
        "ok": ok,
        "status": status,
        "exported_events": len(events),
        "saved_links": saved_links,
        "response": resp,
    }


def export_source_heartbeat_to_xdr(workspace_slug: str, sensor_id: str | None = None) -> dict[str, Any]:
    source_ok, status, source_resp = _ensure_source(workspace_slug)
    if not source_ok:
        return {"ok": False, "stage": "create_source", "status": status, "response": source_resp}

    snapshot = get_source_heartbeat_snapshot(workspace_slug, sensor_id=sensor_id)
    source_key = _source_key(workspace_slug)
    heartbeat_id = (
        f"ipros-heartbeat-{workspace_slug}-"
        f"{str(snapshot.get('generated_at') or '').replace(':', '').replace('-', '').replace('T', '').replace('.', '')}"
    )
    event = {
        "schema_version": "common_security_event_v1",
        "event_id": heartbeat_id[:120],
        "time": str(snapshot.get("generated_at") or ""),
        "product": "exkururuipros",
        "category": "control",
        "event_type": "IPROS_SOURCE_HEARTBEAT",
        "severity": "low",
        "score": 5.0,
        "labels": ["ipros", "heartbeat", "source_health"],
        "src_ip": None,
        "dst_ip": None,
        "raw_ref": f"ipros:heartbeat:{workspace_slug}",
        "source_health": snapshot,
    }
    status, resp = _post_json(
        "/api/v1/import/json",
        {
            "source_key": source_key,
            "display_name": _display_name(),
            "product": "exkururuipros",
            "events": [event],
        },
    )
    return {
        "ok": 200 <= status < 300,
        "status": status,
        "workspace_slug": workspace_slug,
        "sensor_id": sensor_id or "",
        "source_key": source_key,
        "heartbeat_event_id": event["event_id"],
        "response": resp,
    }
