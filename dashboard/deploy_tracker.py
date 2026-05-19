"""Deploy event tracking and warmup-aware metric classification for EXkururuIPROS.

Deployments cause transient spikes in response time, cache misses, and source
health lag.  This module records deploy events and provides warmup-aware
classification so the SOC dashboard does not penalise normal post-deploy noise.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

from .storage import connect, utcnow

DEPLOY_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS deploy_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL DEFAULT 'default',
  deploy_id TEXT NOT NULL,
  commit_hash TEXT NOT NULL DEFAULT '',
  image_tag TEXT NOT NULL DEFAULT '',
  actor TEXT NOT NULL DEFAULT 'system',
  status TEXT NOT NULL DEFAULT 'started',
  warmup_minutes INTEGER NOT NULL DEFAULT 15,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  warmup_until TEXT,
  notes TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_deploy_events_id ON deploy_events (workspace_slug, deploy_id);
CREATE INDEX IF NOT EXISTS idx_deploy_events_recent ON deploy_events (workspace_slug, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_deploy_events_status ON deploy_events (workspace_slug, status, created_at DESC);

CREATE TABLE IF NOT EXISTS policy_audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL DEFAULT 'default',
  action TEXT NOT NULL,
  actor TEXT NOT NULL DEFAULT 'system',
  policy_id TEXT NOT NULL DEFAULT '',
  target_type TEXT NOT NULL DEFAULT '',
  target_value TEXT NOT NULL DEFAULT '',
  detail_json TEXT NOT NULL DEFAULT '{}',
  outcome TEXT NOT NULL DEFAULT 'ok',
  ip_address TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_policy_audit_action ON policy_audit_logs (workspace_slug, action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_policy_audit_actor ON policy_audit_logs (workspace_slug, actor, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_policy_audit_recent ON policy_audit_logs (workspace_slug, created_at DESC);
"""

# Policy actions that MUST produce an audit log entry
AUDITABLE_ACTIONS = frozenset({
    "policy_create",
    "policy_activate",
    "policy_rollback",
    "whitelist_add",
    "whitelist_remove",
    "ban_create",
    "ban_expire",
    "response_execute",
    "replay_run",
    "baseline_save",
    "block_create",
    "block_cancel",
})


# ──────────────────────────────────────────────────────────────────────────────
# Deploy lifecycle
# ──────────────────────────────────────────────────────────────────────────────

def mark_deploy_started(
    deploy_id: str,
    commit_hash: str = "",
    actor: str = "system",
    workspace_slug: str = "default",
    image_tag: str = "",
    notes: str = "",
    warmup_minutes: int = 15,
) -> int:
    now = utcnow()
    with connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO deploy_events
              (workspace_slug, deploy_id, commit_hash, image_tag, actor,
               status, warmup_minutes, started_at, created_at, notes)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(workspace_slug, deploy_id) DO UPDATE SET
              status='started', started_at=excluded.started_at, notes=excluded.notes
            """,
            (workspace_slug, deploy_id, commit_hash, image_tag, actor,
             "started", warmup_minutes, now, now, notes),
        )
        return cur.lastrowid or 0


def mark_deploy_succeeded(
    deploy_id: str,
    workspace_slug: str = "default",
    warmup_minutes: int | None = None,
) -> None:
    now_dt = datetime.now(timezone.utc)
    now_str = now_dt.isoformat()

    with connect() as conn:
        row = conn.execute(
            "SELECT warmup_minutes FROM deploy_events WHERE workspace_slug=? AND deploy_id=?",
            (workspace_slug, deploy_id),
        ).fetchone()

        wm = warmup_minutes
        if wm is None and row:
            wm = int(row["warmup_minutes"] or 15)
        if wm is None:
            wm = 15

        warmup_until = (now_dt + timedelta(minutes=wm)).isoformat()

        conn.execute(
            """
            UPDATE deploy_events
            SET status='succeeded', finished_at=?, warmup_until=?
            WHERE workspace_slug=? AND deploy_id=?
            """,
            (now_str, warmup_until, workspace_slug, deploy_id),
        )


def mark_deploy_failed(
    deploy_id: str,
    reason: str = "",
    workspace_slug: str = "default",
) -> None:
    with connect() as conn:
        conn.execute(
            """
            UPDATE deploy_events
            SET status='failed', finished_at=?, notes=?
            WHERE workspace_slug=? AND deploy_id=?
            """,
            (utcnow(), reason[:500], workspace_slug, deploy_id),
        )


def get_current_deploy(workspace_slug: str = "default") -> dict | None:
    with connect() as conn:
        row = conn.execute(
            """
            SELECT id, deploy_id, commit_hash, image_tag, actor, status,
                   warmup_minutes, started_at, finished_at, warmup_until, notes
            FROM deploy_events
            WHERE workspace_slug=?
            ORDER BY created_at DESC LIMIT 1
            """,
            (workspace_slug,),
        ).fetchone()
    return dict(row) if row else None


def is_warmup_now(workspace_slug: str = "default") -> tuple[bool, dict | None]:
    """Returns (in_warmup, deploy_event_or_None)."""
    with connect() as conn:
        row = conn.execute(
            """
            SELECT id, deploy_id, commit_hash, status, started_at, finished_at,
                   warmup_until, warmup_minutes
            FROM deploy_events
            WHERE workspace_slug=? AND status='succeeded' AND warmup_until IS NOT NULL
            ORDER BY finished_at DESC LIMIT 1
            """,
            (workspace_slug,),
        ).fetchone()

    if not row:
        return False, None

    row_dict = dict(row)
    wu_str = str(row_dict.get("warmup_until") or "").strip()
    if not wu_str:
        return False, row_dict

    try:
        if wu_str.endswith("Z"):
            wu_str = wu_str[:-1] + "+00:00"
        wu_dt = datetime.fromisoformat(wu_str)
        if wu_dt.tzinfo is None:
            wu_dt = wu_dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return False, row_dict

    now = datetime.now(timezone.utc)
    return now <= wu_dt, row_dict


# ──────────────────────────────────────────────────────────────────────────────
# Warmup-aware metric classification
# ──────────────────────────────────────────────────────────────────────────────

def classify_response_time(
    avg_ms: float,
    p95_ms: float,
    workspace_slug: str = "default",
) -> dict[str, Any]:
    in_warmup, deploy = is_warmup_now(workspace_slug)
    if in_warmup:
        return {
            "status": "warming",
            "score_impact": "excluded",
            "avg_ms": avg_ms,
            "p95_ms": p95_ms,
            "message": "Post-deploy warmup — excluded from SLO evaluation.",
            "deploy_id": deploy.get("deploy_id") if deploy else None,
            "warmup_until": deploy.get("warmup_until") if deploy else None,
        }

    if p95_ms <= 300 and avg_ms <= 100:
        status = "good"
    elif p95_ms <= 800:
        status = "degraded"
    else:
        status = "critical"

    return {
        "status": status,
        "score_impact": "normal",
        "avg_ms": avg_ms,
        "p95_ms": p95_ms,
    }


def classify_source_health(
    source_key: str,
    lag_seconds: int,
    grace_until_iso: str | None = None,
) -> str:
    """Returns active / warming / degraded / stale, honouring grace period."""
    if grace_until_iso:
        try:
            raw = str(grace_until_iso).strip()
            if raw.endswith("Z"):
                raw = raw[:-1] + "+00:00"
            grace_dt = datetime.fromisoformat(raw)
            if grace_dt.tzinfo is None:
                grace_dt = grace_dt.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) <= grace_dt:
                return "warming"
        except ValueError:
            pass

    if lag_seconds <= 300:
        return "active"
    if lag_seconds <= 1800:
        return "degraded"
    return "stale"


# ──────────────────────────────────────────────────────────────────────────────
# Policy audit log
# ──────────────────────────────────────────────────────────────────────────────

def record_policy_audit_log(
    action: str,
    actor: str = "system",
    *,
    workspace_slug: str = "default",
    policy_id: str = "",
    target_type: str = "",
    target_value: str = "",
    detail: dict | None = None,
    outcome: str = "ok",
    ip_address: str = "",
) -> int:
    import json as _json
    now = utcnow()
    with connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO policy_audit_logs
              (workspace_slug, action, actor, policy_id, target_type, target_value,
               detail_json, outcome, ip_address, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                workspace_slug, action, actor, policy_id,
                target_type, target_value,
                _json.dumps(detail or {}), outcome, ip_address, now,
            ),
        )
        return cur.lastrowid or 0


def list_policy_audit_logs(
    workspace_slug: str = "default",
    *,
    action: str = "",
    actor: str = "",
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    wheres = ["workspace_slug=?"]
    params: list[Any] = [workspace_slug]
    if action:
        wheres.append("action=?")
        params.append(action)
    if actor:
        wheres.append("actor=?")
        params.append(actor)
    sql = f"""
        SELECT id, action, actor, policy_id, target_type, target_value,
               detail_json, outcome, ip_address, created_at
        FROM policy_audit_logs
        WHERE {' AND '.join(wheres)}
        ORDER BY created_at DESC, id DESC
        LIMIT ? OFFSET ?
    """
    params += [limit, offset]
    with connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


# ──────────────────────────────────────────────────────────────────────────────
# Incident fingerprinting helpers
# ──────────────────────────────────────────────────────────────────────────────

def incident_fingerprint(
    normalized_ip: str,
    signature: str,
    target: str = "generic",
    severity: str = "high",
) -> str:
    """Stable fingerprint for grouping incidents by attacker+technique+target."""
    parts = [
        str(normalized_ip or "").strip(),
        str(signature or "").strip().lower(),
        str(target or "generic").strip().lower(),
        str(severity or "high").strip().lower(),
    ]
    return "|".join(parts)
