from __future__ import annotations

import json
import os
import sqlite3
import ipaddress
import hashlib
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from .security import db_path


_TI_CACHE: dict[str, tuple[float, list[dict]]] = {}
_TI_CACHE_TTL_SEC = max(60, min(int(os.getenv("IPS_THREAT_INTEL_CACHE_SEC", "900") or 900), 24 * 3600))
_DASHBOARD_SUMMARY_CACHE: dict[str, object] = {"at": 0.0, "data": None}
_DASHBOARD_SUMMARY_CACHE_TTL_SEC = max(0.0, min(float(os.getenv("IPS_DASHBOARD_SUMMARY_CACHE_SEC", "2") or 2.0), 60.0))
_GEOASN_RULES_CACHE: tuple[str, list[dict]] | None = None
_POSTGRES_SCHEMA_SQL_CACHE: str | None = None
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_DELIVERY_CHAIN_MATCHER_CACHE: tuple[float, dict[str, object]] | None = None
_DELIVERY_CHAIN_MATCHER_CACHE_TTL_SEC = max(
    10.0,
    min(float(os.getenv("IPS_DELIVERY_CHAIN_MATCHER_CACHE_SEC", "120") or 120.0), 600.0),
)
_KEV_MATCHER_CACHE: tuple[float, dict[str, object]] | None = None
_KEV_MATCHER_CACHE_TTL_SEC = max(
    5.0,
    min(float(os.getenv("IPS_KEV_MATCHER_CACHE_SEC", "60") or 60.0), 600.0),
)
_ASSET_MATCHER_CACHE: dict[str, tuple[float, dict[str, object]]] = {}
_ASSET_MATCHER_CACHE_TTL_SEC = max(
    5.0,
    min(float(os.getenv("IPS_ASSET_MATCHER_CACHE_SEC", "30") or 30.0), 300.0),
)
_DELIVERY_CHAIN_KEYWORDS = (
    "infostealer",
    "stealer",
    "phishing",
    "malvert",
    "clickfix",
    "fakeupdate",
    "fake_update",
    "lure",
)
_DELIVERY_SHORTENER_HOSTS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "rb.gy",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "lnkd.in",
}
_DELIVERY_FILE_DISTRIBUTION_HOSTS = {
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "cdn.discordapp.com",
    "discordapp.com",
    "pastebin.com",
    "mega.nz",
    "dropbox.com",
    "drive.google.com",
    "storage.googleapis.com",
    "files.catbox.moe",
    "wetransfer.com",
}
_DELIVERY_SUSPICIOUS_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".iso",
    ".img",
    ".dmg",
    ".pkg",
    ".msi",
    ".exe",
    ".dll",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".wsf",
    ".hta",
    ".cmd",
    ".bat",
    ".ps1",
    ".lnk",
}
_TI_ALLOWED_INDICATOR_TYPES = {
    "ip",
    "cidr",
    "domain",
    "url",
    "sha256",
    "md5",
    "ja3",
    "ja4",
    "jarm",
    "cve",
    "attack_technique",
}
_TI_ALLOWED_STATUS = {"active", "disabled"}


def _db_dsn() -> str:
    return str(os.getenv("IPS_DB_DSN", "") or "").strip()


def _is_postgres_backend() -> bool:
    dsn = _db_dsn().lower()
    return dsn.startswith("postgresql://") or dsn.startswith("postgres://")


def _qmark_to_pyformat(sql: str) -> str:
    out: list[str] = []
    in_single = False
    i = 0
    while i < len(sql):
        ch = sql[i]
        if ch == "'":
            # Preserve escaped single quote ''.
            if in_single and i + 1 < len(sql) and sql[i + 1] == "'":
                out.append("''")
                i += 2
                continue
            in_single = not in_single
            out.append(ch)
            i += 1
            continue
        if ch == "?" and not in_single:
            out.append("%s")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _normalize_postgres_sql(sql: str) -> str:
    converted = _qmark_to_pyformat(sql)
    if re.match(r"(?is)^\s*INSERT\s+OR\s+IGNORE\s+INTO\s+", converted):
        converted = re.sub(r"(?is)^\s*INSERT\s+OR\s+IGNORE\s+INTO\s+", "INSERT INTO ", converted, count=1)
        if "ON CONFLICT" not in converted.upper():
            converted = converted.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
    return converted


class _PgCompatCursor:
    def __init__(self, conn, cursor, sql: str):
        self._conn = conn
        self._cursor = cursor
        self.rowcount = int(getattr(cursor, "rowcount", 0) or 0)
        self.lastrowid = None
        upper = sql.strip().upper()
        if upper.startswith("INSERT") and " RETURNING " not in upper:
            try:
                c2 = self._conn.cursor()
                c2.execute("SELECT LASTVAL()")
                row = c2.fetchone()
                if isinstance(row, (tuple, list)) and row:
                    self.lastrowid = int(row[0])
                elif isinstance(row, dict):
                    self.lastrowid = int(next(iter(row.values())))
            except Exception:
                self.lastrowid = None

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()


class _PgCompatConnection:
    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql: str, params=()):
        query = _normalize_postgres_sql(sql)
        cur = self._conn.cursor()
        cur.execute(query, tuple(params or ()))
        return _PgCompatCursor(self._conn, cur, query)

    def executemany(self, sql: str, seq_of_params):
        query = _normalize_postgres_sql(sql)
        cur = self._conn.cursor()
        cur.executemany(query, seq_of_params)
        return _PgCompatCursor(self._conn, cur, query)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


def _ingest_shard_count() -> int:
    raw = str(os.getenv("IPS_INGEST_SHARD_COUNT", "1") or "1").strip()
    try:
        return max(1, min(int(raw), 128))
    except ValueError:
        return 1


def _sensor_home_shard(workspace_slug: str, sensor_id: str, shard_count: int) -> int:
    if shard_count <= 1:
        return 0
    key = f"{workspace_slug}:{sensor_id}".encode("utf-8")
    digest = hashlib.sha256(key).hexdigest()[:8]
    return int(digest, 16) % shard_count


def _load_geoasn_rules() -> list[dict]:
    global _GEOASN_RULES_CACHE
    raw = str(os.getenv("IPS_GEOASN_RULES", "") or "").strip()
    if _GEOASN_RULES_CACHE and _GEOASN_RULES_CACHE[0] == raw:
        return _GEOASN_RULES_CACHE[1]
    rules: list[dict] = []
    if raw:
        for token in [x.strip() for x in raw.split(",") if x.strip()]:
            parts = [x.strip() for x in token.replace(":", "|").split("|")]
            if len(parts) < 3:
                continue
            cidr, country_code, asn = parts[0], parts[1], parts[2]
            if not cidr:
                continue
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            rules.append(
                {
                    "network": net,
                    "country_code": str(country_code or "").upper()[:8],
                    "asn": str(asn or "").upper()[:64],
                    "source": "static_rule",
                }
            )
    _GEOASN_RULES_CACHE = (raw, rules)
    return rules


def _geoasn_rule_count() -> int:
    return len(_load_geoasn_rules())


def _geoasn_enrich_ip(value: str) -> tuple[str, str, str]:
    raw = str(value or "").strip().lower()
    if not raw:
        return "", "", "none"
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return "", "", "invalid_ip"
    for rule in _load_geoasn_rules():
        net = rule.get("network")
        if not isinstance(net, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            continue
        if ip.version == net.version and ip in net:
            return str(rule.get("country_code") or ""), str(rule.get("asn") or ""), str(rule.get("source") or "static_rule")
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return "LOCAL", "AS-PRIVATE", "private_local"
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return "N/A", "AS-N/A", "special_range"
    return "", "", "unmapped"


SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS sensors (
  workspace_slug TEXT NOT NULL,
  sensor_id TEXT NOT NULL,
  name TEXT NOT NULL,
  sensor_type TEXT NOT NULL,
  policy_mode TEXT NOT NULL,
  shared_secret TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  meta_json TEXT NOT NULL DEFAULT '{}',
  last_seen_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_slug, sensor_id)
);
CREATE INDEX IF NOT EXISTS idx_sensors_ws_type_active ON sensors (workspace_slug, sensor_type, is_active);
CREATE INDEX IF NOT EXISTS idx_sensors_ws_last_seen ON sensors (workspace_slug, last_seen_at DESC);
CREATE TABLE IF NOT EXISTS block_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL,
  sensor_id TEXT,
  target_type TEXT NOT NULL,
  target_value TEXT NOT NULL,
  stage TEXT NOT NULL,
  ttl_seconds INTEGER NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  acknowledged_at TEXT,
  response_meta TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_block_actions_lookup ON block_actions (workspace_slug, status, stage, created_at);
CREATE INDEX IF NOT EXISTS idx_block_actions_expiry ON block_actions (workspace_slug, expires_at);
CREATE INDEX IF NOT EXISTS idx_block_actions_pending_queue ON block_actions (workspace_slug, status, created_at, id);
CREATE INDEX IF NOT EXISTS idx_block_actions_target_status ON block_actions (workspace_slug, target_type, target_value, status);
CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL,
  sensor_id TEXT NOT NULL,
  source_event_key TEXT NOT NULL DEFAULT '',
  detected_at TEXT NOT NULL,
  src_ip TEXT,
  dst_ip TEXT,
  src_port INTEGER,
  dst_port INTEGER,
  protocol TEXT NOT NULL DEFAULT '',
  signature TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL,
  score REAL,
  action TEXT NOT NULL,
  payload_excerpt TEXT NOT NULL DEFAULT '',
  raw_event TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_security_events_ts ON security_events (workspace_slug, detected_at);
CREATE INDEX IF NOT EXISTS idx_security_events_key ON security_events (workspace_slug, source_event_key);
CREATE INDEX IF NOT EXISTS idx_security_events_src_window ON security_events (workspace_slug, src_ip, detected_at, severity);
CREATE INDEX IF NOT EXISTS idx_security_events_ws_id ON security_events (workspace_slug, id DESC);
CREATE TABLE IF NOT EXISTS flow_findings (
  workspace_slug TEXT NOT NULL,
  bucket TEXT NOT NULL,
  signal TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_slug, bucket, signal)
);
CREATE INDEX IF NOT EXISTS idx_flow_findings_lookup ON flow_findings (workspace_slug, bucket, signal);
CREATE TABLE IF NOT EXISTS metric_buckets (
  bucket TEXT PRIMARY KEY,
  total INTEGER NOT NULL DEFAULT 0,
  s2xx INTEGER NOT NULL DEFAULT 0,
  s3xx INTEGER NOT NULL DEFAULT 0,
  s4xx INTEGER NOT NULL DEFAULT 0,
  s5xx INTEGER NOT NULL DEFAULT 0,
  blocked INTEGER NOT NULL DEFAULT 0,
  blocked_429 INTEGER NOT NULL DEFAULT 0,
  blocked_503 INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS metric_bucket_items (
  bucket TEXT NOT NULL,
  kind TEXT NOT NULL,
  label TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket, kind, label)
);
CREATE INDEX IF NOT EXISTS idx_metric_bucket_items_lookup ON metric_bucket_items (kind, bucket);
CREATE TABLE IF NOT EXISTS metric_bucket_rt (
  bucket TEXT PRIMARY KEY,
  avg REAL NOT NULL,
  p50 REAL NOT NULL,
  p95 REAL NOT NULL,
  p99 REAL NOT NULL,
  count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS metric_bucket_rt_daily (
  day TEXT PRIMARY KEY,
  avg REAL NOT NULL,
  p50 REAL NOT NULL,
  p95 REAL NOT NULL,
  p99 REAL NOT NULL,
  count INTEGER NOT NULL,
  source_buckets INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workspace_settings (
  workspace_slug TEXT PRIMARY KEY,
  waf_enabled INTEGER NOT NULL DEFAULT 1,
  waf_mode TEXT NOT NULL DEFAULT 'block',
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workspace_assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL,
  asset_key TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  host TEXT NOT NULL DEFAULT '',
  ip_cidr TEXT NOT NULL DEFAULT '',
  service_port INTEGER,
  exposure TEXT NOT NULL DEFAULT 'external',
  criticality INTEGER NOT NULL DEFAULT 3,
  status TEXT NOT NULL DEFAULT 'active',
  tags_json TEXT NOT NULL DEFAULT '[]',
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(workspace_slug, asset_key)
);
CREATE INDEX IF NOT EXISTS idx_workspace_assets_lookup ON workspace_assets (workspace_slug, status, updated_at, id);
CREATE INDEX IF NOT EXISTS idx_workspace_assets_host ON workspace_assets (workspace_slug, host, status);
CREATE INDEX IF NOT EXISTS idx_workspace_assets_cidr ON workspace_assets (workspace_slug, ip_cidr, status);
CREATE TABLE IF NOT EXISTS workspace_kpi_settings (
  workspace_slug TEXT PRIMARY KEY,
  exclude_test_ip_on_kpi INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS test_ip_allowlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL,
  ip_cidr TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  note TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT 'admin',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  expires_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_test_ip_allowlist ON test_ip_allowlist (workspace_slug, ip_cidr);
CREATE INDEX IF NOT EXISTS idx_test_ip_allowlist_lookup ON test_ip_allowlist (workspace_slug, status, expires_at, updated_at);
CREATE TABLE IF NOT EXISTS control_policy_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL,
  version_no INTEGER NOT NULL,
  title TEXT NOT NULL DEFAULT '',
  policy_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'draft',
  created_by TEXT NOT NULL DEFAULT 'system',
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  activated_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_control_policy_version_no ON control_policy_versions (workspace_slug, version_no);
CREATE INDEX IF NOT EXISTS idx_control_policy_status ON control_policy_versions (workspace_slug, status, created_at);
CREATE TABLE IF NOT EXISTS control_policy_distributions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL,
  policy_version_id INTEGER NOT NULL,
  version_no INTEGER NOT NULL,
  sensor_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  detail_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  acknowledged_at TEXT,
  FOREIGN KEY (policy_version_id) REFERENCES control_policy_versions(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_control_policy_dist ON control_policy_distributions (workspace_slug, version_no, sensor_id);
CREATE INDEX IF NOT EXISTS idx_control_policy_dist_lookup ON control_policy_distributions (workspace_slug, sensor_id, status, updated_at);
CREATE TABLE IF NOT EXISTS notification_channels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL,
  channel_type TEXT NOT NULL,
  webhook_url TEXT NOT NULL,
  is_enabled INTEGER NOT NULL DEFAULT 1,
  secret_token TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_notification_channel ON notification_channels (workspace_slug, channel_type, webhook_url);
CREATE TABLE IF NOT EXISTS notification_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL,
  channel_type TEXT NOT NULL,
  event_type TEXT NOT NULL,
  status TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notification_events_lookup ON notification_events (workspace_slug, created_at);
CREATE TABLE IF NOT EXISTS admin_audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  status TEXT NOT NULL,
  path TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_lookup ON admin_audit_logs (created_at, action, status);
CREATE TABLE IF NOT EXISTS e2e_eval_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL,
  profile TEXT NOT NULL DEFAULT 'default',
  total_events INTEGER NOT NULL DEFAULT 0,
  attack_events INTEGER NOT NULL DEFAULT 0,
  benign_events INTEGER NOT NULL DEFAULT 0,
  attack_mitigation_rate REAL NOT NULL DEFAULT 0,
  attack_block_rate REAL NOT NULL DEFAULT 0,
  benign_mitigation_rate REAL NOT NULL DEFAULT 0,
  benign_block_rate REAL NOT NULL DEFAULT 0,
  p95_ms REAL NOT NULL DEFAULT 0,
  p99_ms REAL NOT NULL DEFAULT 0,
  passed INTEGER NOT NULL DEFAULT 0,
  thresholds_json TEXT NOT NULL DEFAULT '{}',
  summary_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_e2e_eval_runs_lookup ON e2e_eval_runs (workspace_slug, created_at);
CREATE INDEX IF NOT EXISTS idx_e2e_eval_runs_ws_id ON e2e_eval_runs (workspace_slug, id DESC);
CREATE TABLE IF NOT EXISTS e2e_eval_scenarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL,
  scenario TEXT NOT NULL,
  total INTEGER NOT NULL DEFAULT 0,
  attack INTEGER NOT NULL DEFAULT 0,
  benign INTEGER NOT NULL DEFAULT 0,
  mitigated INTEGER NOT NULL DEFAULT 0,
  blocked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  FOREIGN KEY (run_id) REFERENCES e2e_eval_runs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_e2e_eval_scenarios_run ON e2e_eval_scenarios (run_id, scenario);
CREATE TABLE IF NOT EXISTS metric_action_latency (
  workspace_slug TEXT NOT NULL,
  bucket TEXT NOT NULL,
  action TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  avg_ms REAL NOT NULL DEFAULT 0,
  p95_ms REAL NOT NULL DEFAULT 0,
  p99_ms REAL NOT NULL DEFAULT 0,
  min_ms REAL NOT NULL DEFAULT 0,
  max_ms REAL NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_slug, bucket, action)
);
CREATE INDEX IF NOT EXISTS idx_metric_action_latency_lookup ON metric_action_latency (workspace_slug, bucket, action);
CREATE TABLE IF NOT EXISTS action_latency_alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL,
  bucket TEXT NOT NULL,
  action TEXT NOT NULL,
  p95_ms REAL NOT NULL DEFAULT 0,
  p99_ms REAL NOT NULL DEFAULT 0,
  threshold_p95_ms REAL NOT NULL DEFAULT 0,
  threshold_p99_ms REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_action_latency_alerts ON action_latency_alerts (workspace_slug, bucket, action);
CREATE INDEX IF NOT EXISTS idx_action_latency_alerts_workspace_action_created ON action_latency_alerts (workspace_slug, action, id DESC);
CREATE TABLE IF NOT EXISTS soc_incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL,
  sensor_id TEXT NOT NULL,
  correlation_key TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'high',
  status TEXT NOT NULL DEFAULT 'open',
  event_count INTEGER NOT NULL DEFAULT 0,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  meta_json TEXT NOT NULL DEFAULT '{}'
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_soc_incidents_key ON soc_incidents (workspace_slug, correlation_key);
CREATE INDEX IF NOT EXISTS idx_soc_incidents_lookup ON soc_incidents (workspace_slug, status, updated_at);
CREATE INDEX IF NOT EXISTS idx_soc_incidents_recent ON soc_incidents (workspace_slug, updated_at DESC, id DESC);
CREATE TABLE IF NOT EXISTS soc_triage_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL,
  incident_id INTEGER NOT NULL,
  action TEXT NOT NULL,
  actor TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  FOREIGN KEY (incident_id) REFERENCES soc_incidents(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_soc_triage_lookup ON soc_triage_logs (workspace_slug, created_at, action);
CREATE TABLE IF NOT EXISTS remote_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL,
  xdr_action_id INTEGER,
  incident_id INTEGER,
  case_id INTEGER,
  action_type TEXT NOT NULL,
  target_json TEXT NOT NULL DEFAULT '{}',
  requested_by TEXT NOT NULL DEFAULT '',
  requested_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'received',
  result_summary TEXT NOT NULL DEFAULT '',
  result_meta_json TEXT NOT NULL DEFAULT '{}',
  executed_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_remote_actions_xdr ON remote_actions (workspace_slug, xdr_action_id);
CREATE INDEX IF NOT EXISTS idx_remote_actions_lookup ON remote_actions (workspace_slug, status, updated_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_remote_actions_ws_id ON remote_actions (workspace_slug, id DESC);
CREATE TABLE IF NOT EXISTS xdr_event_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL,
  sensor_id TEXT NOT NULL,
  source_event_key TEXT NOT NULL,
  local_incident_id INTEGER,
  local_correlation_key TEXT NOT NULL DEFAULT '',
  xdr_source_key TEXT NOT NULL DEFAULT '',
  xdr_event_id TEXT NOT NULL DEFAULT '',
  export_status TEXT NOT NULL DEFAULT 'exported',
  detail_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_xdr_event_links_event ON xdr_event_links (workspace_slug, source_event_key);
CREATE INDEX IF NOT EXISTS idx_xdr_event_links_recent ON xdr_event_links (workspace_slug, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_xdr_event_links_ws_id ON xdr_event_links (workspace_slug, id DESC);
CREATE INDEX IF NOT EXISTS idx_xdr_event_links_status_recent ON xdr_event_links (workspace_slug, export_status, created_at DESC, id DESC);
CREATE TABLE IF NOT EXISTS rule_feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL,
  rule_key TEXT NOT NULL,
  verdict TEXT NOT NULL,
  actor TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  source_event_key TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rule_feedback_lookup ON rule_feedback (workspace_slug, rule_key, created_at);
CREATE TABLE IF NOT EXISTS rule_overrides (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL,
  rule_key TEXT NOT NULL,
  action TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  actor TEXT NOT NULL DEFAULT 'system',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  expires_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_rule_overrides_active ON rule_overrides (workspace_slug, rule_key, action, status);
CREATE INDEX IF NOT EXISTS idx_rule_overrides_lookup ON rule_overrides (workspace_slug, status, updated_at);
CREATE TABLE IF NOT EXISTS threat_intel_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  indicator_type TEXT NOT NULL DEFAULT 'ip',
  indicator_value TEXT NOT NULL,
  source TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT 'medium',
  confidence REAL NOT NULL DEFAULT 0.5,
  status TEXT NOT NULL DEFAULT 'active',
  note TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL,
  expires_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_intel_indicator ON threat_intel_entries (indicator_type, indicator_value, source);
CREATE INDEX IF NOT EXISTS idx_threat_intel_lookup ON threat_intel_entries (status, indicator_type, indicator_value, updated_at);
CREATE TABLE IF NOT EXISTS threat_intel_sync_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  feed_source TEXT NOT NULL DEFAULT '',
  feed_name TEXT NOT NULL DEFAULT '',
  feed_version TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'ok',
  entry_count INTEGER NOT NULL DEFAULT 0,
  accepted_count INTEGER NOT NULL DEFAULT 0,
  rejected_count INTEGER NOT NULL DEFAULT 0,
  checksum_sha256 TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_threat_intel_sync_runs_recent ON threat_intel_sync_runs (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_sync_runs_source_recent ON threat_intel_sync_runs (feed_source, created_at DESC, id DESC);
"""


@contextmanager
def connect():
    if _is_postgres_backend():
        try:
            import psycopg
            from psycopg.rows import dict_row
        except Exception as exc:
            raise RuntimeError("PostgreSQL backend requires 'psycopg' package") from exc
        raw = psycopg.connect(_db_dsn(), autocommit=False, row_factory=dict_row)
        conn = _PgCompatConnection(raw)
    else:
        raw = sqlite3.connect(db_path())
        raw.row_factory = sqlite3.Row
        conn = raw
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _postgres_schema_sql() -> str:
    global _POSTGRES_SCHEMA_SQL_CACHE
    if _POSTGRES_SCHEMA_SQL_CACHE is not None:
        return _POSTGRES_SCHEMA_SQL_CACHE
    out_lines: list[str] = []
    for line in SCHEMA_SQL.splitlines():
        if line.strip().upper().startswith("PRAGMA "):
            continue
        out_lines.append(line)
    sql = "\n".join(out_lines)
    sql = re.sub(r"\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b", "BIGSERIAL PRIMARY KEY", sql, flags=re.IGNORECASE)
    _POSTGRES_SCHEMA_SQL_CACHE = sql
    return sql


def init_db() -> None:
    with connect() as conn:
        if _is_postgres_backend():
            schema_sql = _postgres_schema_sql()
            for stmt in [x.strip() for x in schema_sql.split(";") if x.strip()]:
                conn.execute(stmt)
        else:
            conn.executescript(SCHEMA_SQL)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def _bucket_5m_from_iso(ts: str | None) -> str:
    dt = None
    if ts:
        raw = str(ts).strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError:
            dt = None
    if dt is None:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    dt = dt.replace(minute=(dt.minute // 5) * 5, second=0, microsecond=0)
    return dt.strftime("%Y%m%d_%H%M")


def _bucket_day(bucket: str | None) -> str:
    raw = str(bucket or "").strip()
    if len(raw) >= 8 and raw[:8].isdigit():
        return raw[:8]
    return datetime.now(timezone.utc).strftime("%Y%m%d")


def _retention_days(env_name: str, default: int, min_days: int, max_days: int) -> int:
    raw = str(os.getenv(env_name, str(default)) or str(default)).strip()
    try:
        days = int(raw)
    except ValueError:
        days = default
    return max(min_days, min(days, max_days))


def _rollup_metric_rt_daily(conn: sqlite3.Connection, buckets: set[str]) -> None:
    if not buckets:
        return
    now = utcnow()
    days = sorted({_bucket_day(bucket) for bucket in buckets})
    for day in days:
        start = f"{day}_0000"
        end = f"{day}_2359"
        row = conn.execute(
            """
            SELECT
              COALESCE(SUM(avg * count), 0) AS avg_weighted,
              COALESCE(SUM(p50 * count), 0) AS p50_weighted,
              COALESCE(SUM(p95 * count), 0) AS p95_weighted,
              COALESCE(SUM(p99 * count), 0) AS p99_weighted,
              COALESCE(SUM(count), 0) AS total_count,
              COALESCE(COUNT(*), 0) AS source_buckets
            FROM metric_bucket_rt
            WHERE bucket >= ? AND bucket <= ?
            """,
            (start, end),
        ).fetchone()
        total_count = int(row["total_count"] or 0)
        source_buckets = int(row["source_buckets"] or 0)
        if total_count <= 0:
            conn.execute("DELETE FROM metric_bucket_rt_daily WHERE day = ?", (day,))
            continue
        avg = float(row["avg_weighted"] or 0.0) / total_count
        p50 = float(row["p50_weighted"] or 0.0) / total_count
        p95 = float(row["p95_weighted"] or 0.0) / total_count
        p99 = float(row["p99_weighted"] or 0.0) / total_count
        conn.execute(
            """
            INSERT INTO metric_bucket_rt_daily (day, avg, p50, p95, p99, count, source_buckets, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(day) DO UPDATE SET
              avg = excluded.avg,
              p50 = excluded.p50,
              p95 = excluded.p95,
              p99 = excluded.p99,
              count = excluded.count,
              source_buckets = excluded.source_buckets,
              updated_at = excluded.updated_at
            """,
            (day, avg, p50, p95, p99, total_count, source_buckets, now),
        )


def _prune_metric_rt_retention(conn: sqlite3.Connection) -> dict:
    short_days = _retention_days("IPS_RT_SHORT_RETENTION_DAYS", 14, 1, 366)
    long_days = _retention_days("IPS_RT_LONG_RETENTION_DAYS", 180, 7, 3650)
    now = datetime.now(timezone.utc)
    short_cutoff = (now - timedelta(days=short_days)).strftime("%Y%m%d_%H%M")
    long_cutoff = (now - timedelta(days=long_days)).strftime("%Y%m%d")
    cur_short = conn.execute("DELETE FROM metric_bucket_rt WHERE bucket < ?", (short_cutoff,))
    cur_long = conn.execute("DELETE FROM metric_bucket_rt_daily WHERE day < ?", (long_cutoff,))
    return {
        "short_days": short_days,
        "long_days": long_days,
        "pruned_5m": int(cur_short.rowcount or 0),
        "pruned_daily": int(cur_long.rowcount or 0),
    }


def _ensure_metric_rt_daily_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS metric_bucket_rt_daily (
          day TEXT PRIMARY KEY,
          avg REAL NOT NULL,
          p50 REAL NOT NULL,
          p95 REAL NOT NULL,
          p99 REAL NOT NULL,
          count INTEGER NOT NULL,
          source_buckets INTEGER NOT NULL DEFAULT 0,
          updated_at TEXT NOT NULL
        )
        """
    )


def _extract_latency_ms(event: dict) -> float | None:
    for key in ("processing_ms", "latency_ms", "response_ms", "rt_ms"):
        value = event.get(key)
        v = _to_float(value, -1.0)
        if v >= 0:
            return v
    rt = _to_float(event.get("rt"), -1.0)
    if rt >= 0:
        return rt * 1000.0
    return None


def upsert_action_latency_metrics(workspace_slug: str, events: list[dict]) -> int:
    action_bucket_samples: dict[tuple[str, str], list[float]] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        latency_ms = _extract_latency_ms(event)
        if latency_ms is None:
            continue
        action = str(event.get("action") or "alert").strip().lower() or "alert"
        bucket = _bucket_5m_from_iso(event.get("detected_at"))
        key = (bucket, action)
        action_bucket_samples.setdefault(key, []).append(latency_ms)

    if not action_bucket_samples:
        return 0

    now = utcnow()
    with connect() as conn:
        for (bucket, action), values in action_bucket_samples.items():
            if not values:
                continue
            count = len(values)
            avg_ms = sum(values) / count
            p95_ms = _percentile(values, 0.95)
            p99_ms = _percentile(values, 0.99)
            min_ms = min(values)
            max_ms = max(values)
            row = conn.execute(
                """
                SELECT count, avg_ms, p95_ms, p99_ms, min_ms, max_ms
                FROM metric_action_latency
                WHERE workspace_slug = ? AND bucket = ? AND action = ?
                """,
                (workspace_slug, bucket, action),
            ).fetchone()
            if row:
                old_count = int(row["count"] or 0)
                old_avg = _to_float(row["avg_ms"], 0.0)
                total_count = old_count + count
                merged_avg = ((old_avg * old_count) + (avg_ms * count)) / total_count if total_count else 0.0
                merged_p95 = max(_to_float(row["p95_ms"], 0.0), p95_ms)
                merged_p99 = max(_to_float(row["p99_ms"], 0.0), p99_ms)
                merged_min = min(_to_float(row["min_ms"], min_ms), min_ms)
                merged_max = max(_to_float(row["max_ms"], max_ms), max_ms)
                conn.execute(
                    """
                    UPDATE metric_action_latency
                    SET count = ?, avg_ms = ?, p95_ms = ?, p99_ms = ?, min_ms = ?, max_ms = ?, updated_at = ?
                    WHERE workspace_slug = ? AND bucket = ? AND action = ?
                    """,
                    (
                        total_count,
                        merged_avg,
                        merged_p95,
                        merged_p99,
                        merged_min,
                        merged_max,
                        now,
                        workspace_slug,
                        bucket,
                        action,
                    ),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO metric_action_latency (
                      workspace_slug, bucket, action, count, avg_ms, p95_ms, p99_ms, min_ms, max_ms, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (workspace_slug, bucket, action, count, avg_ms, p95_ms, p99_ms, min_ms, max_ms, now),
                )
    return len(action_bucket_samples)


def list_action_latency_summary(workspace_slug: str, hours: int = 24, limit: int = 20) -> list[dict]:
    now = datetime.now(timezone.utc)
    now = now.replace(minute=(now.minute // 5) * 5, second=0, microsecond=0)
    bucket_count = max(1, min(int(hours * 60 / 5), 2016))
    buckets = {(now - timedelta(minutes=i * 5)).strftime("%Y%m%d_%H%M") for i in range(bucket_count)}
    if not buckets:
        return []
    placeholders = ",".join("?" for _ in buckets)
    safe_limit = max(1, min(int(limit), 50))
    with connect() as conn:
        rows = conn.execute(
            f"""
            SELECT
              action,
              COALESCE(SUM(count), 0) AS sample_count,
              COALESCE(SUM(avg_ms * count), 0) AS weighted_sum,
              COALESCE(MAX(p95_ms), 0) AS worst_p95_ms,
              COALESCE(MAX(p99_ms), 0) AS worst_p99_ms,
              COALESCE(MAX(max_ms), 0) AS max_ms
            FROM metric_action_latency
            WHERE workspace_slug = ? AND bucket IN ({placeholders})
            GROUP BY action
            ORDER BY sample_count DESC, action ASC
            LIMIT ?
            """,
            (workspace_slug, *tuple(sorted(buckets)), safe_limit),
        ).fetchall()
    out = []
    for row in rows:
        sample_count = int(row["sample_count"] or 0)
        weighted_sum = _to_float(row["weighted_sum"], 0.0)
        avg_ms = (weighted_sum / sample_count) if sample_count else 0.0
        out.append(
            {
                "action": row["action"],
                "sample_count": sample_count,
                "avg_ms": round(avg_ms, 3),
                "worst_p95_ms": round(_to_float(row["worst_p95_ms"], 0.0), 3),
                "worst_p99_ms": round(_to_float(row["worst_p99_ms"], 0.0), 3),
                "max_ms": round(_to_float(row["max_ms"], 0.0), 3),
            }
        )
    return out


def record_action_latency_alert(
    workspace_slug: str,
    bucket: str,
    action: str,
    p95_ms: float,
    p99_ms: float,
    threshold_p95_ms: float,
    threshold_p99_ms: float,
) -> bool:
    cooldown_min = max(0, min(int(os.getenv("IPS_ACTION_SLO_ALERT_COOLDOWN_MIN", "30") or 30), 24 * 60))
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    with connect() as conn:
        if cooldown_min > 0:
            row = conn.execute(
                """
                SELECT created_at
                FROM action_latency_alerts
                WHERE workspace_slug = ? AND action = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (workspace_slug, action),
            ).fetchone()
            if row and str(row["created_at"] or "").strip():
                last_dt = _parse_iso_datetime(str(row["created_at"]))
                if (now_dt - last_dt).total_seconds() < cooldown_min * 60:
                    return False
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO action_latency_alerts (
              workspace_slug, bucket, action, p95_ms, p99_ms, threshold_p95_ms, threshold_p99_ms, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (workspace_slug, bucket, action, p95_ms, p99_ms, threshold_p95_ms, threshold_p99_ms, now),
        )
        return bool(cur.rowcount)


def list_action_latency_alerts(workspace_slug: str, limit: int = 30) -> list[dict]:
    safe_limit = max(1, min(int(limit), 200))
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT workspace_slug, bucket, action, p95_ms, p99_ms, threshold_p95_ms, threshold_p99_ms, created_at
            FROM action_latency_alerts
            WHERE workspace_slug = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (workspace_slug, safe_limit),
        ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["p95_ms"] = round(_to_float(item.get("p95_ms"), 0.0), 3)
        item["p99_ms"] = round(_to_float(item.get("p99_ms"), 0.0), 3)
        item["threshold_p95_ms"] = round(_to_float(item.get("threshold_p95_ms"), 0.0), 3)
        item["threshold_p99_ms"] = round(_to_float(item.get("threshold_p99_ms"), 0.0), 3)
        out.append(item)
    return out


def _severity_rank(value: str) -> int:
    s = str(value or "").strip().lower()
    if s == "critical":
        return 4
    if s == "high":
        return 3
    if s == "medium":
        return 2
    if s == "low":
        return 1
    return 0


def _normalize_severity(value: str) -> str:
    s = str(value or "").strip().lower()
    if s in {"critical", "high", "medium", "low"}:
        return s
    return "high"


def _parse_iso_datetime(value: str | None) -> datetime:
    raw = str(value or "").strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw) if raw else datetime.now(timezone.utc)
    except ValueError:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _signature_family(signature: str) -> str:
    s = str(signature or "").strip().lower()
    if not s:
        return "generic"
    if s.startswith("scan-") or "scan" in s:
        return "scan"
    if s.startswith("rl-") or "rate_limit" in s:
        return "rate_limit"
    if s.startswith("waf-") or "waf" in s:
        return "waf"
    if s.startswith("bot-") or "bot" in s:
        return "bot"
    token = s.replace(":", "-").split("-", 1)[0]
    return token[:32] if token else "generic"


def _is_high_risk_signature(signature: str) -> bool:
    s = str(signature or "").strip().lower()
    if not s:
        return False
    keywords = (
        "scan",
        "auth",
        "stuff",
        "credential",
        "api",
        "bola",
        "ssrf",
        "path",
        "traversal",
        "rce",
        "cve",
        "scrape",
        "ddos",
    )
    return any(k in s for k in keywords)


_ACTION_SCORE = {
    "allow": 0,
    "observe": 1,
    "alert": 1,
    "challenge": 2,
    "captcha": 2,
    "limit": 3,
    "throttle": 3,
    "block": 4,
    "deny": 4,
    "drop": 4,
    "reject": 4,
    "waf_block": 4,
    "403": 4,
    "429": 3,
}


def _enforce_min_action(action: str, min_action: str) -> str:
    cur = str(action or "observe").strip().lower() or "observe"
    mn = str(min_action or "challenge").strip().lower() or "challenge"
    if _ACTION_SCORE.get(cur, 1) >= _ACTION_SCORE.get(mn, 2):
        return cur
    return mn


def _to_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int, min_v: int, max_v: int) -> int:
    value = _to_int(os.getenv(name, str(default)), default)
    return max(min_v, min(value, max_v))


def _recent_5m_buckets(hours: int) -> list[str]:
    now = datetime.now(timezone.utc)
    now = now.replace(minute=(now.minute // 5) * 5, second=0, microsecond=0)
    bucket_count = max(1, min(int(hours * 60 / 5), 2016))
    return [(now - timedelta(minutes=i * 5)).strftime("%Y%m%d_%H%M") for i in range(bucket_count)]


def _analyze_flow_signals(events: list[dict]) -> dict:
    if not events:
        return {"event_hits": 0, "signal_counts": {}}
    port_sweep_threshold = _env_int("IPS_FLOW_PORT_SWEEP_THRESHOLD", 12, 4, 256)
    host_sweep_threshold = _env_int("IPS_FLOW_HOST_SWEEP_THRESHOLD", 10, 3, 256)
    burst_threshold = _env_int("IPS_FLOW_BURST_PER_5MIN", 45, 10, 10000)
    protocol_mix_threshold = _env_int("IPS_FLOW_PROTOCOL_MIX_THRESHOLD", 3, 2, 10)
    min_signals = _env_int("IPS_FLOW_MIN_SIGNALS", 2, 1, 4)
    strong_factor = max(2, _env_int("IPS_FLOW_STRONG_FACTOR", 2, 2, 5))
    min_events_per_src = _env_int("IPS_FLOW_MIN_EVENTS_PER_SRC", 16, 2, 1000)
    score_floor = float(_env_int("IPS_FLOW_SCORE_FLOOR", 72, 40, 100))
    min_action = str(os.getenv("IPS_FLOW_MIN_ACTION", "challenge") or "challenge").strip().lower()
    if min_action not in {"observe", "challenge", "limit", "block"}:
        min_action = "challenge"
    excluded_prefixes_raw = str(
        os.getenv(
            "IPS_FLOW_EXCLUDE_URI_PREFIXES",
            os.getenv("IPS_EXCLUDE_URI_PREFIXES", "/secops/api/,/api/v1/dashboard/summary/,/healthz"),
        )
        or ""
    ).strip()
    excluded_prefixes = tuple(x.strip() for x in excluded_prefixes_raw.split(",") if x.strip())
    sig_port_sweep = 1
    sig_host_sweep = 2
    sig_protocol_mix = 4
    sig_burst = 8

    src_event_counts: dict[str, int] = {}
    filtered_events: list[dict] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        uri = str(event.get("uri") or event.get("path") or event.get("request_path") or "").strip()
        if uri and excluded_prefixes and uri.startswith(excluded_prefixes):
            continue
        src_ip = str(event.get("src_ip") or "").strip().lower()
        if not src_ip:
            continue
        filtered_events.append(event)
        src_event_counts[src_ip] = src_event_counts.get(src_ip, 0) + 1
    if not filtered_events:
        return {"event_hits": 0, "signal_counts": {}}

    qualified_src_ips = {src for src, count in src_event_counts.items() if count >= min_events_per_src}
    if not qualified_src_ips:
        return {"event_hits": 0, "signal_counts": {}}

    src_stats: dict[str, dict] = {}
    src_bucket_counts: dict[tuple[str, str], int] = {}
    for event in filtered_events:
        src_ip = str(event.get("src_ip") or "").strip().lower()
        if src_ip not in qualified_src_ips:
            continue
        bucket = _bucket_5m_from_iso(event.get("detected_at"))
        stat = src_stats.setdefault(src_ip, {"dst_ports": set(), "dst_ips": set(), "protocols": set()})
        dst_port = event.get("dst_port")
        if dst_port not in (None, ""):
            stat["dst_ports"].add(str(dst_port))
        dst_ip = str(event.get("dst_ip") or "").strip().lower()
        if dst_ip:
            stat["dst_ips"].add(dst_ip)
        proto = str(event.get("protocol") or "").strip().lower()
        if proto:
            stat["protocols"].add(proto)
        src_bucket_counts[(src_ip, bucket)] = src_bucket_counts.get((src_ip, bucket), 0) + 1

    src_meta: dict[str, dict] = {}
    for src_ip, stat in src_stats.items():
        dst_port_count = len(stat["dst_ports"])
        dst_ip_count = len(stat["dst_ips"])
        protocol_count = len(stat["protocols"])
        static_mask = 0
        if dst_port_count >= port_sweep_threshold:
            static_mask |= sig_port_sweep
        if dst_ip_count >= host_sweep_threshold:
            static_mask |= sig_host_sweep
        if protocol_count >= protocol_mix_threshold:
            static_mask |= sig_protocol_mix
        src_meta[src_ip] = {
            "dst_port_count": dst_port_count,
            "dst_ip_count": dst_ip_count,
            "protocols": tuple(sorted(stat["protocols"])),
            "static_mask": static_mask,
            "strong_static": (
                dst_port_count >= port_sweep_threshold * strong_factor
                or dst_ip_count >= host_sweep_threshold * strong_factor
                or protocol_count >= protocol_mix_threshold * strong_factor
            ),
        }

    event_hits = 0
    signal_counts: dict[str, int] = {}
    for event in filtered_events:
        src_ip = str(event.get("src_ip") or "").strip().lower()
        if not src_ip:
            continue
        meta = src_meta.get(src_ip)
        if not meta:
            continue
        bucket = _bucket_5m_from_iso(event.get("detected_at"))
        bucket_hits = int(src_bucket_counts.get((src_ip, bucket), 0))
        signal_mask = int(meta["static_mask"])
        if bucket_hits >= burst_threshold:
            signal_mask |= sig_burst
        if not signal_mask:
            continue
        signal_count = (
            (1 if signal_mask & sig_port_sweep else 0)
            + (1 if signal_mask & sig_host_sweep else 0)
            + (1 if signal_mask & sig_protocol_mix else 0)
            + (1 if signal_mask & sig_burst else 0)
        )
        strong_signal = bool(meta["strong_static"]) or bucket_hits >= burst_threshold * strong_factor
        if signal_count < min_signals and not strong_signal:
            continue

        signals: list[str] = []
        if signal_mask & sig_port_sweep:
            signal_counts["flow_port_sweep"] = signal_counts.get("flow_port_sweep", 0) + 1
            signals.append("flow_port_sweep")
        if signal_mask & sig_host_sweep:
            signal_counts["flow_host_sweep"] = signal_counts.get("flow_host_sweep", 0) + 1
            signals.append("flow_host_sweep")
        if signal_mask & sig_protocol_mix:
            signal_counts["flow_protocol_mix"] = signal_counts.get("flow_protocol_mix", 0) + 1
            signals.append("flow_protocol_mix")
        if signal_mask & sig_burst:
            signal_counts["flow_burst"] = signal_counts.get("flow_burst", 0) + 1
            signals.append("flow_burst")

        event_hits += 1
        sev = str(event.get("severity") or "medium").strip().lower()
        if _severity_rank(sev) < _severity_rank("high"):
            event["severity"] = "high"
        event["score"] = max(_to_float(event.get("score"), 0.0), score_floor)
        event["action"] = _enforce_min_action(str(event.get("action") or "observe"), min_action)
        tags = event.get("tags")
        if isinstance(tags, list):
            if "flow_anomaly" not in tags:
                tags.append("flow_anomaly")
        else:
            event["tags"] = ["flow_anomaly"]
        event["flow_analysis"] = {
            "signals": signals,
            "src_unique_dst_ports": int(meta["dst_port_count"]),
            "src_unique_dst_ips": int(meta["dst_ip_count"]),
            "src_protocols": list(meta["protocols"]),
            "src_bucket_hits_5m": bucket_hits,
        }
    return {"event_hits": event_hits, "signal_counts": signal_counts}


def upsert_flow_findings(workspace_slug: str, events: list[dict]) -> int:
    by_bucket_signal: dict[tuple[str, str], int] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        flow = event.get("flow_analysis")
        if not isinstance(flow, dict):
            continue
        signals = flow.get("signals")
        if not isinstance(signals, list):
            continue
        bucket = _bucket_5m_from_iso(event.get("detected_at"))
        for signal in {str(s).strip().lower() for s in signals if str(s).strip()}:
            by_bucket_signal[(bucket, signal)] = by_bucket_signal.get((bucket, signal), 0) + 1
    if not by_bucket_signal:
        return 0
    now = utcnow()
    with connect() as conn:
        for (bucket, signal), count in by_bucket_signal.items():
            conn.execute(
                """
                INSERT INTO flow_findings (workspace_slug, bucket, signal, count, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(workspace_slug, bucket, signal) DO UPDATE SET
                  count = count + excluded.count,
                  updated_at = excluded.updated_at
                """,
                (workspace_slug, bucket, signal, int(count), now),
            )
    return len(by_bucket_signal)


def list_flow_findings_summary(workspace_slug: str, hours: int = 24, limit: int = 20) -> list[dict]:
    buckets = _recent_5m_buckets(hours)
    if not buckets:
        return []
    placeholders = ",".join("?" for _ in buckets)
    safe_limit = max(1, min(int(limit), 100))
    with connect() as conn:
        rows = conn.execute(
            f"""
            SELECT signal, COALESCE(SUM(count), 0) AS hits
            FROM flow_findings
            WHERE workspace_slug = ? AND bucket IN ({placeholders})
            GROUP BY signal
            ORDER BY hits DESC, signal ASC
            LIMIT ?
            """,
            (workspace_slug, *tuple(sorted(buckets)), safe_limit),
        ).fetchall()
    return [{"signal": str(row["signal"]), "hits": int(row["hits"] or 0)} for row in rows]


def _incident_window_slot(detected_at: str | None) -> str:
    dt = _parse_iso_datetime(detected_at)
    win_min = max(5, min(int(os.getenv("IPS_SOC_AGG_WINDOW_MIN", "15") or 15), 60))
    minute = (dt.minute // win_min) * win_min
    slot = dt.replace(minute=minute, second=0, microsecond=0)
    return slot.strftime("%Y%m%d_%H%M")


def _window_slot_bounds(slot: str) -> tuple[datetime, datetime]:
    dt = datetime.strptime(slot, "%Y%m%d_%H%M").replace(tzinfo=timezone.utc)
    win_min = max(5, min(int(os.getenv("IPS_SOC_AGG_WINDOW_MIN", "15") or 15), 60))
    return dt, dt + timedelta(minutes=win_min)


def _sensor_type_for_id(conn: sqlite3.Connection, workspace_slug: str, sensor_id: str) -> str:
    row = conn.execute(
        """
        SELECT sensor_type
        FROM sensors
        WHERE workspace_slug = ? AND sensor_id = ?
        LIMIT 1
        """,
        (workspace_slug, sensor_id),
    ).fetchone()
    return str((row["sensor_type"] if row else "") or "unknown").strip().lower() or "unknown"


def _related_sensor_types(
    conn: sqlite3.Connection,
    workspace_slug: str,
    src_ip: str,
    window_slot: str,
    current_sensor_type: str,
) -> list[str]:
    src = str(src_ip or "").strip().lower()
    if not src or src == "unknown":
        return [current_sensor_type]
    start_dt, end_dt = _window_slot_bounds(window_slot)
    rows = conn.execute(
        """
        SELECT DISTINCT COALESCE(NULLIF(LOWER(s.sensor_type), ''), 'unknown') AS sensor_type
        FROM security_events se
        LEFT JOIN sensors s
          ON s.workspace_slug = se.workspace_slug
         AND s.sensor_id = se.sensor_id
        WHERE se.workspace_slug = ?
          AND se.src_ip = ?
          AND se.severity IN ('high', 'critical')
          AND se.detected_at >= ?
          AND se.detected_at < ?
        """,
        (workspace_slug, src, start_dt.isoformat(), end_dt.isoformat()),
    ).fetchall()
    types = {current_sensor_type}
    for row in rows:
        types.add(str(row["sensor_type"] or "unknown").strip().lower() or "unknown")
    return sorted(types)


def _pick_primary_key(
    event: dict,
    sensor_id: str,
    *,
    sensor_type: str,
    sensor_types_seen: list[str] | None = None,
) -> tuple[str, str, dict]:
    signature = str(event.get("signature") or event.get("rule") or "generic").strip().lower()[:120]
    src_ip = str(event.get("src_ip") or "unknown").strip().lower()[:64]
    family = _signature_family(signature)
    window_slot = _incident_window_slot(event.get("detected_at"))
    seen_types = [str(x).strip().lower() for x in (sensor_types_seen or []) if str(x).strip()]
    if not seen_types:
        seen_types = [sensor_type]
    min_multi_types = max(2, min(int(os.getenv("IPS_SOC_MULTI_SENSOR_MIN_TYPES", "2") or 2), 10))
    is_multi_sensor = len(set(seen_types)) >= min_multi_types and src_ip not in {"", "unknown"}
    is_global = family == "scan"
    src_key = "global" if is_global else src_ip
    key = f"{family}:{src_key}:{window_slot}"
    if is_global:
        correlation_key = f"global:{key}"
        title = f"{family} incident [{window_slot}] src={src_key}"
    elif is_multi_sensor:
        correlation_key = f"multi:{key}"
        title = f"multi-sensor {family} incident [{window_slot}] src={src_key}"
    else:
        correlation_key = f"{sensor_id}:{key}"
        title = f"{family} incident [{window_slot}] src={src_key}"
    meta = {
        "family": family,
        "src_key": src_key,
        "window_slot": window_slot,
        "signature": signature,
        "sensor_type": sensor_type,
        "sensor_types_seen": sorted(set(seen_types)),
        "multi_sensor": bool(is_multi_sensor),
    }
    return correlation_key, title[:180], meta


def upsert_soc_incidents_from_events(workspace_slug: str, sensor_id: str, events: list[dict]) -> dict:
    grouped: dict[str, dict] = {}
    with connect() as conn:
        sensor_type = _sensor_type_for_id(conn, workspace_slug, sensor_id)
        type_cache: dict[tuple[str, str], list[str]] = {}
        for event in events:
            if not isinstance(event, dict):
                continue
            sev = str(event.get("severity") or "").strip().lower()
            if sev not in {"high", "critical"}:
                continue
            src_ip = str(event.get("src_ip") or "unknown").strip().lower()
            window_slot = _incident_window_slot(event.get("detected_at"))
            cache_key = (src_ip, window_slot)
            if cache_key not in type_cache:
                type_cache[cache_key] = _related_sensor_types(conn, workspace_slug, src_ip, window_slot, sensor_type)
            correlation_key, title, key_meta = _pick_primary_key(
                event,
                sensor_id,
                sensor_type=sensor_type,
                sensor_types_seen=type_cache.get(cache_key) or [sensor_type],
            )
            detected_at = str(event.get("detected_at") or utcnow())
            item = grouped.setdefault(
                correlation_key,
                {
                    "correlation_key": correlation_key,
                    "title": title,
                    "severity": _normalize_severity(sev),
                    "event_count": 0,
                    "first_seen_at": detected_at,
                    "last_seen_at": detected_at,
                    "meta_json": key_meta,
                },
            )
            item["event_count"] += 1
            if _severity_rank(sev) > _severity_rank(item["severity"]):
                item["severity"] = _normalize_severity(sev)
            if detected_at < item["first_seen_at"]:
                item["first_seen_at"] = detected_at
            if detected_at > item["last_seen_at"]:
                item["last_seen_at"] = detected_at

    created = 0
    updated = 0
    if not grouped:
        return {"created": 0, "updated": 0}

    now = utcnow()
    with connect() as conn:
        for row in grouped.values():
            existing = conn.execute(
                """
                SELECT id, severity, event_count, meta_json
                FROM soc_incidents
                WHERE workspace_slug = ? AND correlation_key = ?
                """,
                (workspace_slug, row["correlation_key"]),
            ).fetchone()
            if existing:
                new_count = int(existing["event_count"] or 0) + int(row["event_count"] or 0)
                current_sev = str(existing["severity"] or "high")
                new_sev = row["severity"] if _severity_rank(row["severity"]) >= _severity_rank(current_sev) else current_sev
                existing_meta = {}
                try:
                    existing_meta = json.loads(existing["meta_json"] or "{}")
                except (TypeError, json.JSONDecodeError):
                    existing_meta = {}
                merged_types = set(str(x).strip().lower() for x in (existing_meta.get("sensor_types_seen") or []) if str(x).strip())
                merged_types.update(str(x).strip().lower() for x in (row.get("meta_json", {}).get("sensor_types_seen") or []) if str(x).strip())
                if merged_types:
                    row["meta_json"]["sensor_types_seen"] = sorted(merged_types)
                    row["meta_json"]["multi_sensor"] = len(merged_types) >= max(
                        2, min(int(os.getenv("IPS_SOC_MULTI_SENSOR_MIN_TYPES", "2") or 2), 10)
                    )
                conn.execute(
                    """
                    UPDATE soc_incidents
                    SET title = ?, severity = ?, status = CASE WHEN status = 'closed' THEN 'open' ELSE status END,
                        event_count = ?, last_seen_at = ?, updated_at = ?, meta_json = ?
                    WHERE id = ?
                    """,
                    (
                        row["title"],
                        new_sev,
                        new_count,
                        row["last_seen_at"],
                        now,
                        json.dumps(row.get("meta_json") or {}, ensure_ascii=False),
                        int(existing["id"]),
                    ),
                )
                updated += 1
            else:
                conn.execute(
                    """
                    INSERT INTO soc_incidents (
                      workspace_slug, sensor_id, correlation_key, title, severity, status,
                      event_count, first_seen_at, last_seen_at, created_at, updated_at, meta_json
                    ) VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        workspace_slug,
                        sensor_id,
                        row["correlation_key"],
                        row["title"],
                        row["severity"],
                        int(row["event_count"]),
                        row["first_seen_at"],
                        row["last_seen_at"],
                        now,
                        now,
                        json.dumps(row.get("meta_json") or {}, ensure_ascii=False),
                    ),
                )
                created += 1
    return {"created": created, "updated": updated}


def list_soc_incidents(workspace_slug: str, limit: int = 50) -> list[dict]:
    safe_limit = max(1, min(int(limit), 200))
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT id, workspace_slug, sensor_id, correlation_key, title, severity, status, event_count,
                   first_seen_at, last_seen_at, created_at, updated_at
            FROM soc_incidents
            WHERE workspace_slug = ?
            ORDER BY updated_at DESC, id DESC
            LIMIT ?
            """,
            (workspace_slug, safe_limit),
        ).fetchall()
    return [dict(row) for row in rows]


def resolve_event_incident_links(workspace_slug: str, sensor_id: str, events: list[dict]) -> list[dict]:
    links: list[dict] = []
    if not events:
        return links
    with connect() as conn:
        sensor_type = _sensor_type_for_id(conn, workspace_slug, sensor_id)
        type_cache: dict[tuple[str, str], list[str]] = {}
        for event in events:
            if not isinstance(event, dict):
                continue
            source_event_key = str(event.get("source_event_key") or event.get("event_id") or "").strip()
            if not source_event_key:
                continue
            src_ip = str(event.get("src_ip") or "unknown").strip().lower()
            window_slot = _incident_window_slot(event.get("detected_at"))
            cache_key = (src_ip, window_slot)
            if cache_key not in type_cache:
                type_cache[cache_key] = _related_sensor_types(conn, workspace_slug, src_ip, window_slot, sensor_type)
            correlation_key, _, _ = _pick_primary_key(
                event,
                sensor_id,
                sensor_type=sensor_type,
                sensor_types_seen=type_cache.get(cache_key) or [sensor_type],
            )
            row = conn.execute(
                """
                SELECT id
                FROM soc_incidents
                WHERE workspace_slug = ? AND correlation_key = ?
                LIMIT 1
                """,
                (workspace_slug, correlation_key),
            ).fetchone()
            links.append(
                {
                    "source_event_key": source_event_key,
                    "local_incident_id": int(row["id"]) if row else None,
                    "local_correlation_key": correlation_key,
                }
            )
    return links


def upsert_xdr_event_links(
    workspace_slug: str,
    sensor_id: str,
    xdr_source_key: str,
    links: list[dict],
) -> int:
    if not links:
        return 0
    now = utcnow()
    saved = 0
    with connect() as conn:
        for item in links:
            source_event_key = str(item.get("source_event_key") or "").strip()
            if not source_event_key:
                continue
            conn.execute(
                """
                INSERT INTO xdr_event_links (
                  workspace_slug, sensor_id, source_event_key, local_incident_id, local_correlation_key,
                  xdr_source_key, xdr_event_id, export_status, detail_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(workspace_slug, source_event_key) DO UPDATE SET
                  sensor_id = excluded.sensor_id,
                  local_incident_id = excluded.local_incident_id,
                  local_correlation_key = excluded.local_correlation_key,
                  xdr_source_key = excluded.xdr_source_key,
                  xdr_event_id = excluded.xdr_event_id,
                  export_status = excluded.export_status,
                  detail_json = excluded.detail_json,
                  created_at = excluded.created_at
                """,
                (
                    workspace_slug,
                    sensor_id,
                    source_event_key,
                    item.get("local_incident_id"),
                    str(item.get("local_correlation_key") or ""),
                    str(xdr_source_key or ""),
                    str(item.get("xdr_event_id") or source_event_key),
                    str(item.get("export_status") or "exported"),
                    json.dumps(item.get("detail") or {}, ensure_ascii=False),
                    now,
                ),
            )
            saved += 1
    return saved


def list_xdr_event_links(workspace_slug: str, limit: int = 100) -> list[dict]:
    safe_limit = max(1, min(int(limit), 1000))
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT id, workspace_slug, sensor_id, source_event_key, local_incident_id, local_correlation_key,
                   xdr_source_key, xdr_event_id, export_status, detail_json, created_at
            FROM xdr_event_links
            WHERE workspace_slug = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (workspace_slug, safe_limit),
        ).fetchall()
    out: list[dict] = []
    for row in rows:
        item = dict(row)
        try:
            item["detail"] = json.loads(item.pop("detail_json") or "{}")
        except (TypeError, json.JSONDecodeError):
            item["detail"] = {}
        out.append(item)
    return out


def triage_soc_incident(workspace_slug: str, incident_id: int, actor: str, action: str, note: str = "") -> dict | None:
    act = str(action or "triage").strip().lower()
    if act not in {"triage", "close", "reopen"}:
        act = "triage"
    new_status = {"triage": "triaged", "close": "closed", "reopen": "open"}[act]
    now = utcnow()
    with connect() as conn:
        conn.execute(
            """
            UPDATE soc_incidents
            SET status = ?, updated_at = ?
            WHERE id = ? AND workspace_slug = ?
            """,
            (new_status, now, int(incident_id), workspace_slug),
        )
        row = conn.execute(
            """
            SELECT id, workspace_slug, sensor_id, correlation_key, title, severity, status, event_count,
                   first_seen_at, last_seen_at, created_at, updated_at
            FROM soc_incidents
            WHERE id = ? AND workspace_slug = ?
            """,
            (int(incident_id), workspace_slug),
        ).fetchone()
        if not row:
            return None
        conn.execute(
            """
            INSERT INTO soc_triage_logs (workspace_slug, incident_id, action, actor, note, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (workspace_slug, int(incident_id), act, str(actor or "admin")[:120], str(note or "")[:1000], now),
        )
    return dict(row)


def soc_chain_summary(workspace_slug: str, hours: int = 24) -> dict:
    since = datetime.now(timezone.utc) - timedelta(hours=max(1, min(int(hours), 168)))
    since_iso = since.isoformat()
    with connect() as conn:
        rule_hits = int(
            conn.execute(
                """
                SELECT COUNT(1) AS c
                FROM security_events
                WHERE workspace_slug = ? AND detected_at >= ? AND TRIM(COALESCE(signature, '')) != ''
                """,
                (workspace_slug, since_iso),
            ).fetchone()["c"]
            or 0
        )
        events = int(
            conn.execute(
                """
                SELECT COUNT(1) AS c
                FROM security_events
                WHERE workspace_slug = ? AND detected_at >= ?
                """,
                (workspace_slug, since_iso),
            ).fetchone()["c"]
            or 0
        )
        incidents = int(
            conn.execute(
                """
                SELECT COUNT(1) AS c
                FROM soc_incidents
                WHERE workspace_slug = ? AND created_at >= ?
                """,
                (workspace_slug, since_iso),
            ).fetchone()["c"]
            or 0
        )
        triages = int(
            conn.execute(
                """
                SELECT COUNT(DISTINCT incident_id) AS c
                FROM soc_triage_logs
                WHERE workspace_slug = ? AND created_at >= ? AND action IN ('triage', 'close')
                """,
                (workspace_slug, since_iso),
            ).fetchone()["c"]
            or 0
        )
        open_incidents = int(
            conn.execute(
                """
                SELECT COUNT(1) AS c
                FROM soc_incidents
                WHERE workspace_slug = ? AND status IN ('open', 'triaged')
                """,
                (workspace_slug,),
            ).fetchone()["c"]
            or 0
        )
    return {
        "hours": hours,
        "rule_hits": rule_hits,
        "events": events,
        "incidents": incidents,
        "triaged_incidents": triages,
        "open_incidents": open_incidents,
        "rule_to_event_rate": round((events / rule_hits), 4) if rule_hits else 0.0,
        "event_to_incident_rate": round((incidents / events), 4) if events else 0.0,
        "incident_to_triage_rate": round((triages / incidents), 4) if incidents else 0.0,
    }


def soc_multi_sensor_summary(workspace_slug: str, hours: int = 24) -> dict:
    since = datetime.now(timezone.utc) - timedelta(hours=max(1, min(int(hours), 168)))
    since_iso = since.isoformat()
    with connect() as conn:
        recent_multi = int(
            conn.execute(
                """
                SELECT COUNT(1) AS c
                FROM soc_incidents
                WHERE workspace_slug = ? AND created_at >= ? AND correlation_key LIKE 'multi:%'
                """,
                (workspace_slug, since_iso),
            ).fetchone()["c"]
            or 0
        )
        open_multi = int(
            conn.execute(
                """
                SELECT COUNT(1) AS c
                FROM soc_incidents
                WHERE workspace_slug = ? AND status IN ('open', 'triaged') AND correlation_key LIKE 'multi:%'
                """,
                (workspace_slug,),
            ).fetchone()["c"]
            or 0
        )
        total_recent = int(
            conn.execute(
                """
                SELECT COUNT(1) AS c
                FROM soc_incidents
                WHERE workspace_slug = ? AND created_at >= ?
                """,
                (workspace_slug, since_iso),
            ).fetchone()["c"]
            or 0
        )
    return {
        "hours": hours,
        "recent_multi_sensor_incidents": recent_multi,
        "open_multi_sensor_incidents": open_multi,
        "recent_multi_sensor_rate": round((recent_multi / total_recent), 4) if total_recent else 0.0,
    }


def _normalize_rule_key(value: str) -> str:
    return str(value or "").strip().lower()[:180]


def _normalize_ti_indicator(indicator_type: str, indicator_value: str) -> tuple[str, str] | None:
    itype = str(indicator_type or "ip").strip().lower()
    raw_value = str(indicator_value or "").strip()
    if itype not in _TI_ALLOWED_INDICATOR_TYPES or not raw_value:
        return None
    if itype == "ip":
        try:
            return itype, str(ipaddress.ip_address(raw_value.lower()))
        except ValueError:
            return None
    if itype == "cidr":
        try:
            return itype, str(ipaddress.ip_network(raw_value.lower(), strict=False))
        except ValueError:
            return None
    if itype == "domain":
        value = raw_value.lower().rstrip(".")
        if len(value) > 253 or "." not in value:
            return None
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", value):
            return None
        return itype, value
    if itype == "url":
        parsed = urllib.parse.urlparse(raw_value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            return None
        cleaned = parsed._replace(fragment="")
        return itype, urllib.parse.urlunparse(cleaned)[:1000]
    if itype == "sha256":
        value = raw_value.lower()
        if re.fullmatch(r"[0-9a-f]{64}", value):
            return itype, value
        return None
    if itype == "md5":
        value = raw_value.lower()
        if re.fullmatch(r"[0-9a-f]{32}", value):
            return itype, value
        return None
    if itype in {"ja3", "ja4", "jarm"}:
        value = raw_value.lower()
        if 4 <= len(value) <= 200 and re.fullmatch(r"[0-9a-z:,_\.-]+", value):
            return itype, value
        return None
    if itype == "cve":
        value = raw_value.upper()
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", value):
            return itype, value
        return None
    if itype == "attack_technique":
        value = raw_value.upper()
        if re.fullmatch(r"T\d{4}(?:\.\d{3})?", value):
            return itype, value
        return None
    return None


def record_threat_intel_sync_run(
    feed_source: str,
    feed_name: str,
    feed_version: str,
    *,
    status: str,
    entry_count: int,
    accepted_count: int,
    rejected_count: int,
    checksum_sha256: str,
    note: str = "",
) -> dict:
    now = utcnow()
    with connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO threat_intel_sync_runs (
              feed_source, feed_name, feed_version, status,
              entry_count, accepted_count, rejected_count,
              checksum_sha256, note, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(feed_source or "")[:120],
                str(feed_name or "")[:200],
                str(feed_version or "")[:120],
                str(status or "ok")[:20],
                max(0, int(entry_count)),
                max(0, int(accepted_count)),
                max(0, int(rejected_count)),
                str(checksum_sha256 or "")[:128],
                str(note or "")[:2000],
                now,
            ),
        )
        row = conn.execute(
            """
            SELECT id, feed_source, feed_name, feed_version, status,
                   entry_count, accepted_count, rejected_count, checksum_sha256, note, created_at
            FROM threat_intel_sync_runs
            WHERE id = ?
            """,
            (cur.lastrowid,),
        ).fetchone()
    return dict(row) if row else {}


def list_threat_intel_sync_runs(limit: int = 50) -> list[dict]:
    safe_limit = max(1, min(int(limit), 500))
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT id, feed_source, feed_name, feed_version, status,
                   entry_count, accepted_count, rejected_count, checksum_sha256, note, created_at
            FROM threat_intel_sync_runs
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def upsert_threat_intel_entry(
    indicator_type: str,
    indicator_value: str,
    source: str,
    category: str = "",
    severity: str = "medium",
    confidence: float = 0.5,
    status: str = "active",
    note: str = "",
    ttl_hours: int | None = None,
) -> dict | None:
    normalized = _normalize_ti_indicator(indicator_type, indicator_value)
    if normalized is None:
        return None
    itype, ivalue = normalized
    src = str(source or "").strip()
    if not src:
        return None
    sev = str(severity or "medium").strip().lower()
    if sev not in {"low", "medium", "high", "critical"}:
        sev = "medium"
    st = str(status or "active").strip().lower()
    if st not in _TI_ALLOWED_STATUS:
        st = "active"
    conf = max(0.0, min(float(confidence or 0.5), 1.0))
    now = utcnow()
    expires_at = None
    if ttl_hours is not None:
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=max(1, min(int(ttl_hours), 24 * 365)))).isoformat()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO threat_intel_entries (
              indicator_type, indicator_value, source, category, severity, confidence, status, note, updated_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(indicator_type, indicator_value, source) DO UPDATE SET
              category = excluded.category,
              severity = excluded.severity,
              confidence = excluded.confidence,
              status = excluded.status,
              note = excluded.note,
              updated_at = excluded.updated_at,
              expires_at = excluded.expires_at
            """,
            (itype, ivalue, src[:120], str(category or "")[:120], sev, conf, st, str(note or "")[:1000], now, expires_at),
        )
        row = conn.execute(
            """
            SELECT id, indicator_type, indicator_value, source, category, severity, confidence, status, note, updated_at, expires_at
            FROM threat_intel_entries
            WHERE indicator_type = ? AND indicator_value = ? AND source = ?
            """,
            (itype, ivalue, src[:120]),
        ).fetchone()
    return dict(row) if row else None


def upsert_threat_intel_entries_bulk(
    entries: list[dict[str, object]],
    *,
    feed_source: str = "",
    feed_name: str = "",
    feed_version: str = "",
    default_ttl_hours: int | None = None,
) -> dict:
    items = entries if isinstance(entries, list) else []
    now = utcnow()
    checksum = hashlib.sha256()
    accepted = 0
    rejected = 0
    errors: list[dict[str, object]] = []
    max_errors = 100
    with connect() as conn:
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                rejected += 1
                if len(errors) < max_errors:
                    errors.append({"index": idx, "error": "item_must_be_object"})
                continue
            normalized = _normalize_ti_indicator(
                str(item.get("indicator_type") or "ip"),
                str(item.get("indicator_value") or ""),
            )
            source = str(item.get("source") or feed_source or "").strip()
            if normalized is None or not source:
                rejected += 1
                if len(errors) < max_errors:
                    errors.append({"index": idx, "error": "invalid_indicator_or_source"})
                continue
            itype, ivalue = normalized
            sev = str(item.get("severity") or "medium").strip().lower()
            if sev not in {"low", "medium", "high", "critical"}:
                sev = "medium"
            st = str(item.get("status") or "active").strip().lower()
            if st not in _TI_ALLOWED_STATUS:
                st = "active"
            confidence = max(0.0, min(_to_float(item.get("confidence"), 0.5), 1.0))
            ttl_hours = item.get("ttl_hours")
            if ttl_hours is None:
                ttl_hours = default_ttl_hours
            expires_at = None
            if ttl_hours is not None:
                try:
                    ttl_h = max(1, min(int(ttl_hours), 24 * 365))
                    expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_h)).isoformat()
                except (TypeError, ValueError):
                    expires_at = None
            category = str(item.get("category") or "")[:120]
            note = str(item.get("note") or "")[:1000]
            conn.execute(
                """
                INSERT INTO threat_intel_entries (
                  indicator_type, indicator_value, source, category, severity, confidence, status, note, updated_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(indicator_type, indicator_value, source) DO UPDATE SET
                  category = excluded.category,
                  severity = excluded.severity,
                  confidence = excluded.confidence,
                  status = excluded.status,
                  note = excluded.note,
                  updated_at = excluded.updated_at,
                  expires_at = excluded.expires_at
                """,
                (itype, ivalue, source[:120], category, sev, confidence, st, note, now, expires_at),
            )
            checksum.update(f"{itype}|{ivalue}|{source[:120]}|{sev}|{confidence:.4f}|{st}\n".encode("utf-8"))
            accepted += 1
    run = record_threat_intel_sync_run(
        feed_source=feed_source,
        feed_name=feed_name,
        feed_version=feed_version,
        status="ok" if rejected == 0 else ("partial" if accepted > 0 else "failed"),
        entry_count=len(items),
        accepted_count=accepted,
        rejected_count=rejected,
        checksum_sha256=checksum.hexdigest(),
        note=f"errors={len(errors)}",
    )
    return {
        "entry_count": len(items),
        "accepted_count": accepted,
        "rejected_count": rejected,
        "errors": errors,
        "sync_run": run,
    }


def list_threat_intel_entries(active_only: bool = True, limit: int = 200) -> list[dict]:
    safe_limit = max(1, min(int(limit), 2000))
    now = utcnow()
    with connect() as conn:
        if active_only:
            rows = conn.execute(
                """
                SELECT id, indicator_type, indicator_value, source, category, severity, confidence, status, note, updated_at, expires_at
                FROM threat_intel_entries
                WHERE status = 'active' AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY updated_at DESC, id DESC
                LIMIT ?
                """,
                (now, safe_limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, indicator_type, indicator_value, source, category, severity, confidence, status, note, updated_at, expires_at
                FROM threat_intel_entries
                ORDER BY updated_at DESC, id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
    return [dict(row) for row in rows]


def count_threat_intel_entries(active_only: bool = True) -> int:
    now = utcnow()
    with connect() as conn:
        if active_only:
            row = conn.execute(
                """
                SELECT COUNT(1) AS c
                FROM threat_intel_entries
                WHERE status = 'active' AND (expires_at IS NULL OR expires_at > ?)
                """,
                (now,),
            ).fetchone()
        else:
            row = conn.execute("SELECT COUNT(1) AS c FROM threat_intel_entries").fetchone()
    return int((row["c"] if row else 0) or 0)


def lookup_threat_intel_ip(ip: str) -> list[dict]:
    raw = str(ip or "").strip().lower()
    if not raw:
        return []
    try:
        target_ip = ipaddress.ip_address(raw)
    except ValueError:
        return []
    now = utcnow()
    with connect() as conn:
        ip_rows = conn.execute(
            """
            SELECT indicator_type, indicator_value, source, category, severity, confidence
            FROM threat_intel_entries
            WHERE status = 'active'
              AND indicator_type = 'ip'
              AND indicator_value = ?
              AND (expires_at IS NULL OR expires_at > ?)
            """,
            (str(target_ip), now),
        ).fetchall()
        cidr_rows = conn.execute(
            """
            SELECT indicator_type, indicator_value, source, category, severity, confidence
            FROM threat_intel_entries
            WHERE status = 'active'
              AND indicator_type = 'cidr'
              AND (expires_at IS NULL OR expires_at > ?)
            """,
            (now,),
        ).fetchall()
    rows = list(ip_rows) + list(cidr_rows)
    out = []
    for row in rows:
        itype = str(row["indicator_type"] or "ip")
        ivalue = str(row["indicator_value"] or "").strip().lower()
        try:
            if itype == "ip":
                if target_ip != ipaddress.ip_address(ivalue):
                    continue
            elif itype == "cidr":
                net = ipaddress.ip_network(ivalue, strict=False)
                if target_ip.version != net.version or target_ip not in net:
                    continue
            else:
                continue
        except ValueError:
            continue
        out.append(dict(row))
    out.sort(key=lambda r: (_severity_rank(str(r.get("severity") or "")), float(r.get("confidence") or 0.0)), reverse=True)
    return out


def _ti_live_enabled() -> bool:
    return str(os.getenv("IPS_THREAT_INTEL_LIVE_ENABLED", "0")).strip().lower() in {"1", "true", "on", "yes"}


def _http_json(url: str, headers: dict[str, str] | None = None, timeout_sec: int = 4) -> dict | None:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            if int(getattr(resp, "status", 200)) >= 400:
                return None
            payload = resp.read()
    except (urllib.error.URLError, TimeoutError, ValueError):
        return None
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if isinstance(data, dict):
        return data
    return None


def _lookup_abuseipdb_live(ip: str) -> dict | None:
    api_key = str(os.getenv("ABUSEIPDB_API_KEY", "")).strip()
    if not api_key:
        return None
    query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90"})
    url = f"https://api.abuseipdb.com/api/v2/check?{query}"
    data = _http_json(
        url,
        headers={"Key": api_key, "Accept": "application/json"},
        timeout_sec=5,
    )
    if not data:
        return None
    info = data.get("data") if isinstance(data.get("data"), dict) else {}
    score = int(info.get("abuseConfidenceScore") or 0)
    confidence = max(0.0, min(score / 100.0, 1.0))
    if score >= 80:
        sev = "critical"
    elif score >= 50:
        sev = "high"
    elif score >= 20:
        sev = "medium"
    else:
        sev = "low"
    return {
        "indicator_type": "ip",
        "indicator_value": ip,
        "source": "abuseipdb_live",
        "category": "reputation",
        "severity": sev,
        "confidence": round(confidence, 3),
        "provider": "abuseipdb",
        "abuse_score": score,
        "total_reports": int(info.get("totalReports") or 0),
    }


def _lookup_greynoise_live(ip: str) -> dict | None:
    api_key = str(os.getenv("GREYNOISE_API_KEY", "")).strip()
    if not api_key:
        return None
    url = f"https://api.greynoise.io/v3/community/{urllib.parse.quote(ip)}"
    data = _http_json(
        url,
        headers={"Accept": "application/json", "key": api_key},
        timeout_sec=5,
    )
    if not data:
        return None
    noise = bool(data.get("noise"))
    riot = bool(data.get("riot"))
    classification = str(data.get("classification") or "").strip().lower()
    if noise and classification == "malicious":
        sev, conf = "high", 0.85
    elif noise:
        sev, conf = "medium", 0.65
    elif riot:
        sev, conf = "low", 0.15
    else:
        sev, conf = "low", 0.3
    return {
        "indicator_type": "ip",
        "indicator_value": ip,
        "source": "greynoise_live",
        "category": f"classification:{classification or 'unknown'}",
        "severity": sev,
        "confidence": conf,
        "provider": "greynoise",
        "classification": classification or "unknown",
        "noise": noise,
        "riot": riot,
    }


def lookup_threat_intel_ip_live(ip: str) -> list[dict]:
    raw = str(ip or "").strip().lower()
    if not raw:
        return []
    try:
        target_ip = str(ipaddress.ip_address(raw))
    except ValueError:
        return []
    if not _ti_live_enabled():
        return []
    key = f"ti_live:{target_ip}"
    now_mono = time.monotonic()
    cached = _TI_CACHE.get(key)
    if cached and cached[0] > now_mono:
        return list(cached[1])
    out = []
    abuse = _lookup_abuseipdb_live(target_ip)
    if abuse:
        out.append(abuse)
    gn = _lookup_greynoise_live(target_ip)
    if gn:
        out.append(gn)
    out.sort(key=lambda r: (_severity_rank(str(r.get("severity") or "")), float(r.get("confidence") or 0.0)), reverse=True)
    _TI_CACHE[key] = (now_mono + float(_TI_CACHE_TTL_SEC), list(out))
    return out


def lookup_threat_intel_ip_all(ip: str) -> list[dict]:
    local_rows = lookup_threat_intel_ip(ip)
    live_rows = lookup_threat_intel_ip_live(ip)
    merged: list[dict] = []
    seen = set()
    for row in local_rows + live_rows:
        source = str(row.get("source") or "unknown")
        iv = str(row.get("indicator_value") or ip)
        key = f"{source}:{iv}"
        if key in seen:
            continue
        seen.add(key)
        merged.append(row)
    merged.sort(key=lambda r: (_severity_rank(str(r.get("severity") or "")), float(r.get("confidence") or 0.0)), reverse=True)
    return merged


def lookup_threat_intel_ip_mode(ip: str, mode: str = "local") -> list[dict]:
    m = str(mode or "local").strip().lower()
    if m not in {"local", "live", "all", "off"}:
        m = "local"
    if m == "off":
        return []
    if m == "local":
        return lookup_threat_intel_ip(ip)
    if m == "live":
        return lookup_threat_intel_ip_live(ip)
    return lookup_threat_intel_ip_all(ip)


def list_recent_threat_intel_matches(workspace_slug: str, limit: int = 30) -> list[dict]:
    safe_limit = max(1, min(int(limit), 200))
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT id, detected_at, src_ip, signature, severity, score, action, raw_event
            FROM security_events
            WHERE workspace_slug = ?
            ORDER BY detected_at DESC, id DESC
            LIMIT 1000
            """,
            (workspace_slug,),
        ).fetchall()
    out: list[dict] = []
    for row in rows:
        raw = {}
        try:
            raw = json.loads(str(row["raw_event"] or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            raw = {}
        ti = raw.get("threat_intel") if isinstance(raw.get("threat_intel"), list) else []
        if not ti:
            continue
        top = ti[0] if isinstance(ti[0], dict) else {}
        country_code = str(raw.get("country_code") or "")
        asn = str(raw.get("asn") or "")
        detail = ", ".join(
            f"{str(x.get('source') or x.get('provider') or 'unknown')}:{str(x.get('severity') or 'n/a')}/{float(x.get('confidence') or 0.0):.2f}"
            for x in ti[:3]
            if isinstance(x, dict)
        )
        if country_code or asn:
            detail = f"geo={country_code or 'N/A'} asn={asn or 'N/A'} | {detail}"
        out.append(
            {
                "event_id": int(row["id"]),
                "detected_at": row["detected_at"],
                "src_ip": str(row["src_ip"] or ""),
                "country_code": country_code,
                "asn": asn,
                "rule": str(row["signature"] or ""),
                "severity": str(row["severity"] or ""),
                "score": float(row["score"] or 0.0),
                "action": str(row["action"] or ""),
                "provider": str(top.get("source") or top.get("provider") or "unknown"),
                "confidence": float(top.get("confidence") or 0.0),
                "detail": detail[:300],
            }
        )
        if len(out) >= safe_limit:
            break
    return out


def list_rule_overrides(workspace_slug: str, active_only: bool = True, limit: int = 100) -> list[dict]:
    safe_limit = max(1, min(int(limit), 500))
    now = utcnow()
    with connect() as conn:
        if active_only:
            rows = conn.execute(
                """
                SELECT id, workspace_slug, rule_key, action, reason, actor, status, created_at, updated_at, expires_at
                FROM rule_overrides
                WHERE workspace_slug = ?
                  AND status = 'active'
                  AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY updated_at DESC, id DESC
                LIMIT ?
                """,
                (workspace_slug, now, safe_limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, workspace_slug, rule_key, action, reason, actor, status, created_at, updated_at, expires_at
                FROM rule_overrides
                WHERE workspace_slug = ?
                ORDER BY updated_at DESC, id DESC
                LIMIT ?
                """,
                (workspace_slug, safe_limit),
            ).fetchall()
    return [dict(row) for row in rows]


def upsert_rule_override(
    workspace_slug: str,
    rule_key: str,
    action: str,
    reason: str,
    actor: str,
    ttl_hours: int = 24,
) -> dict | None:
    rk = _normalize_rule_key(rule_key)
    act = str(action or "observe").strip().lower()
    if not rk or act not in {"allow", "observe", "limit", "challenge", "block"}:
        return None
    now = utcnow()
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=max(1, min(int(ttl_hours), 24 * 30)))).isoformat()
    with connect() as conn:
        row = conn.execute(
            """
            SELECT id
            FROM rule_overrides
            WHERE workspace_slug = ? AND rule_key = ? AND action = ? AND status = 'active'
            LIMIT 1
            """,
            (workspace_slug, rk, act),
        ).fetchone()
        if row:
            conn.execute(
                """
                UPDATE rule_overrides
                SET reason = ?, actor = ?, updated_at = ?, expires_at = ?
                WHERE id = ?
                """,
                (str(reason or "")[:300], str(actor or "system")[:120], now, expires_at, int(row["id"])),
            )
            out = conn.execute("SELECT * FROM rule_overrides WHERE id = ?", (int(row["id"]),)).fetchone()
        else:
            cur = conn.execute(
                """
                INSERT INTO rule_overrides (workspace_slug, rule_key, action, reason, actor, status, created_at, updated_at, expires_at)
                VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)
                """,
                (workspace_slug, rk, act, str(reason or "")[:300], str(actor or "system")[:120], now, now, expires_at),
            )
            out = conn.execute("SELECT * FROM rule_overrides WHERE id = ?", (int(cur.lastrowid),)).fetchone()
    return dict(out) if out else None


def list_rule_feedback_stats(workspace_slug: str, limit: int = 50) -> list[dict]:
    safe_limit = max(1, min(int(limit), 200))
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT
              rule_key,
              COUNT(1) AS total_feedback,
              SUM(CASE WHEN verdict = 'false_positive' THEN 1 ELSE 0 END) AS false_positive_count,
              SUM(CASE WHEN verdict = 'true_positive' THEN 1 ELSE 0 END) AS true_positive_count,
              MAX(created_at) AS last_feedback_at
            FROM rule_feedback
            WHERE workspace_slug = ?
            GROUP BY rule_key
            ORDER BY total_feedback DESC, false_positive_count DESC, rule_key ASC
            LIMIT ?
            """,
            (workspace_slug, safe_limit),
        ).fetchall()
    out = []
    for row in rows:
        total = int(row["total_feedback"] or 0)
        fp = int(row["false_positive_count"] or 0)
        out.append(
            {
                "rule_key": row["rule_key"],
                "total_feedback": total,
                "false_positive_count": fp,
                "true_positive_count": int(row["true_positive_count"] or 0),
                "false_positive_rate": round((fp / total), 4) if total else 0.0,
                "last_feedback_at": row["last_feedback_at"],
            }
        )
    return out


def record_rule_feedback(
    workspace_slug: str,
    rule_key: str,
    verdict: str,
    actor: str,
    note: str = "",
    source_event_key: str = "",
) -> dict:
    rk = _normalize_rule_key(rule_key)
    vd = str(verdict or "").strip().lower()
    if vd not in {"false_positive", "true_positive"}:
        vd = "false_positive"
    now = utcnow()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO rule_feedback (workspace_slug, rule_key, verdict, actor, note, source_event_key, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (workspace_slug, rk, vd, str(actor or "admin")[:120], str(note or "")[:1000], str(source_event_key or "")[:220], now),
        )

    recent_window = max(5, min(int(os.getenv("IPS_RULE_FEEDBACK_WINDOW", "20")), 200))
    min_samples = max(3, min(int(os.getenv("IPS_RULE_AUTO_MIN_SAMPLES", "5")), 100))
    fp_rate_threshold = max(0.5, min(_to_float(os.getenv("IPS_RULE_AUTO_FP_RATE", "0.8"), 0.8), 1.0))
    tp_rate_threshold = max(0.5, min(_to_float(os.getenv("IPS_RULE_AUTO_TP_RATE", "0.7"), 0.7), 1.0))
    auto_ttl_hours = max(1, min(int(os.getenv("IPS_RULE_AUTO_TTL_HOURS", "24")), 24 * 30))
    auto_override = None
    auto_recovered = False

    with connect() as conn:
        rows = conn.execute(
            """
            SELECT verdict
            FROM rule_feedback
            WHERE workspace_slug = ? AND rule_key = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (workspace_slug, rk, recent_window),
        ).fetchall()
    total = len(rows)
    fp = sum(1 for r in rows if str(r["verdict"]) == "false_positive")
    tp = sum(1 for r in rows if str(r["verdict"]) == "true_positive")
    fp_rate = (fp / total) if total else 0.0
    tp_rate = (tp / total) if total else 0.0
    if total >= min_samples and fp_rate >= fp_rate_threshold:
        auto_override = upsert_rule_override(
            workspace_slug=workspace_slug,
            rule_key=rk,
            action="observe",
            reason=f"auto_adjust false_positive_rate={fp_rate:.2f} ({fp}/{total})",
            actor="auto_feedback",
            ttl_hours=auto_ttl_hours,
        )
    elif total >= min_samples and tp_rate >= tp_rate_threshold:
        now = utcnow()
        with connect() as conn:
            cur = conn.execute(
                """
                UPDATE rule_overrides
                SET status = 'inactive', updated_at = ?, expires_at = COALESCE(expires_at, ?)
                WHERE workspace_slug = ? AND rule_key = ? AND action = 'observe' AND status = 'active'
                """,
                (now, now, workspace_slug, rk),
            )
            auto_recovered = bool(cur.rowcount)
    return {
        "workspace_slug": workspace_slug,
        "rule_key": rk,
        "verdict": vd,
        "recent_total": total,
        "recent_false_positive": fp,
        "recent_false_positive_rate": round(fp_rate, 4),
        "recent_true_positive": tp,
        "recent_true_positive_rate": round(tp_rate, 4),
        "auto_override": auto_override,
        "auto_recovered": auto_recovered,
    }


def register_sensor(payload: dict) -> dict:
    now = utcnow()
    shard_count = _ingest_shard_count()
    meta = payload.get("meta_json") if isinstance(payload.get("meta_json"), dict) else {}
    meta = dict(meta)
    if "ingest_shard" not in meta:
        meta["ingest_shard"] = int(_sensor_home_shard(str(payload["workspace_slug"]), str(payload["sensor_id"]), shard_count))
    if "ingest_shard_count" not in meta:
        meta["ingest_shard_count"] = int(shard_count)
    meta_json = json.dumps(meta, ensure_ascii=False)
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO sensors (workspace_slug, sensor_id, name, sensor_type, policy_mode, shared_secret, is_active, meta_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
            ON CONFLICT(workspace_slug, sensor_id) DO UPDATE SET
              name=excluded.name,
              sensor_type=excluded.sensor_type,
              policy_mode=excluded.policy_mode,
              shared_secret=excluded.shared_secret,
              is_active=1,
              meta_json=excluded.meta_json,
              updated_at=excluded.updated_at
            """,
            (
                payload["workspace_slug"],
                payload["sensor_id"],
                payload["name"],
                payload["sensor_type"],
                payload["policy_mode"],
                payload["shared_secret"],
                meta_json,
                now,
                now,
            ),
        )
    return get_sensor(payload["workspace_slug"], payload["sensor_id"])


def get_workspace_setting(workspace_slug: str) -> dict:
    with connect() as conn:
        row = conn.execute(
            "SELECT workspace_slug, waf_enabled, waf_mode, updated_at FROM workspace_settings WHERE workspace_slug = ?",
            (workspace_slug,),
        ).fetchone()
        if not row:
            now = utcnow()
            conn.execute(
                "INSERT INTO workspace_settings (workspace_slug, waf_enabled, waf_mode, updated_at) VALUES (?, 1, 'block', ?)",
                (workspace_slug, now),
            )
            row = conn.execute(
                "SELECT workspace_slug, waf_enabled, waf_mode, updated_at FROM workspace_settings WHERE workspace_slug = ?",
                (workspace_slug,),
            ).fetchone()
    data = dict(row)
    data["waf_enabled"] = bool(data.get("waf_enabled"))
    return data


def set_workspace_waf(workspace_slug: str, waf_enabled: bool, waf_mode: str) -> dict:
    now = utcnow()
    mode = (waf_mode or "block").strip().lower()
    if mode not in {"block", "monitor"}:
        mode = "block"
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO workspace_settings (workspace_slug, waf_enabled, waf_mode, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(workspace_slug) DO UPDATE SET
              waf_enabled = excluded.waf_enabled,
              waf_mode = excluded.waf_mode,
              updated_at = excluded.updated_at
            """,
            (workspace_slug, 1 if waf_enabled else 0, mode, now),
        )
    return get_workspace_setting(workspace_slug)


def _normalize_ip_cidr(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("ip_cidr is required")
    net = ipaddress.ip_network(raw, strict=False)
    if net.num_addresses == 1:
        return str(net.network_address)
    return str(net)


def _is_expired(expires_at: str | None) -> bool:
    if not expires_at:
        return False
    return _parse_iso_datetime(expires_at) <= datetime.now(timezone.utc)


def _normalize_asset_host(value: str) -> str:
    host = str(value or "").strip().lower().rstrip(".")
    if not host:
        return ""
    if len(host) > 253:
        raise ValueError("host is too long")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", host):
        raise ValueError("invalid host")
    return host


def upsert_workspace_asset(
    workspace_slug: str,
    *,
    asset_key: str,
    display_name: str = "",
    host: str = "",
    ip_cidr: str = "",
    service_port: int | None = None,
    exposure: str = "external",
    criticality: int = 3,
    status: str = "active",
    tags: list[str] | None = None,
    note: str = "",
) -> dict:
    ws = str(workspace_slug or "").strip()
    key = str(asset_key or "").strip().lower()
    if not ws:
        raise ValueError("workspace_slug is required")
    if not key:
        raise ValueError("asset_key is required")
    host_norm = _normalize_asset_host(host) if str(host or "").strip() else ""
    cidr_norm = _normalize_ip_cidr(ip_cidr) if str(ip_cidr or "").strip() else ""
    if not host_norm and not cidr_norm:
        raise ValueError("host or ip_cidr is required")
    if service_port is not None:
        try:
            port = int(service_port)
        except (TypeError, ValueError):
            raise ValueError("invalid service_port")
        if port < 1 or port > 65535:
            raise ValueError("invalid service_port")
        service_port = port
    exp = str(exposure or "external").strip().lower()
    if exp not in {"external", "internal", "dmz"}:
        exp = "external"
    st = str(status or "active").strip().lower()
    if st not in {"active", "inactive"}:
        st = "active"
    try:
        crit = int(criticality)
    except (TypeError, ValueError):
        crit = 3
    crit = max(1, min(crit, 5))
    tags_clean = []
    for raw in tags or []:
        t = str(raw or "").strip().lower()
        if not t:
            continue
        if len(t) > 40:
            t = t[:40]
        tags_clean.append(t)
    tags_json = json.dumps(sorted(set(tags_clean)), ensure_ascii=False)
    now = utcnow()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO workspace_assets (
              workspace_slug, asset_key, display_name, host, ip_cidr, service_port, exposure, criticality, status,
              tags_json, note, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace_slug, asset_key) DO UPDATE SET
              display_name = excluded.display_name,
              host = excluded.host,
              ip_cidr = excluded.ip_cidr,
              service_port = excluded.service_port,
              exposure = excluded.exposure,
              criticality = excluded.criticality,
              status = excluded.status,
              tags_json = excluded.tags_json,
              note = excluded.note,
              updated_at = excluded.updated_at
            """,
            (
                ws,
                key[:80],
                str(display_name or "")[:120],
                host_norm,
                cidr_norm,
                service_port,
                exp,
                crit,
                st,
                tags_json,
                str(note or "")[:500],
                now,
                now,
            ),
        )
        row = conn.execute(
            """
            SELECT id, workspace_slug, asset_key, display_name, host, ip_cidr, service_port, exposure, criticality, status,
                   tags_json, note, created_at, updated_at
            FROM workspace_assets
            WHERE workspace_slug = ? AND asset_key = ?
            """,
            (ws, key[:80]),
        ).fetchone()
    out = dict(row)
    try:
        out["tags"] = json.loads(out.pop("tags_json") or "[]")
    except Exception:
        out["tags"] = []
    return out


def list_workspace_assets(workspace_slug: str, *, active_only: bool = True, limit: int = 300) -> list[dict]:
    ws = str(workspace_slug or "").strip()
    safe_limit = max(1, min(int(limit), 5000))
    with connect() as conn:
        if active_only:
            rows = conn.execute(
                """
                SELECT id, workspace_slug, asset_key, display_name, host, ip_cidr, service_port, exposure, criticality, status,
                       tags_json, note, created_at, updated_at
                FROM workspace_assets
                WHERE workspace_slug = ? AND status = 'active'
                ORDER BY updated_at DESC, id DESC
                LIMIT ?
                """,
                (ws, safe_limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, workspace_slug, asset_key, display_name, host, ip_cidr, service_port, exposure, criticality, status,
                       tags_json, note, created_at, updated_at
                FROM workspace_assets
                WHERE workspace_slug = ?
                ORDER BY updated_at DESC, id DESC
                LIMIT ?
                """,
                (ws, safe_limit),
            ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        try:
            item["tags"] = json.loads(item.pop("tags_json") or "[]")
        except Exception:
            item["tags"] = []
        out.append(item)
    return out


def get_workspace_kpi_setting(workspace_slug: str) -> dict:
    with connect() as conn:
        row = conn.execute(
            "SELECT workspace_slug, exclude_test_ip_on_kpi, updated_at FROM workspace_kpi_settings WHERE workspace_slug = ?",
            (workspace_slug,),
        ).fetchone()
        if not row:
            now = utcnow()
            conn.execute(
                """
                INSERT INTO workspace_kpi_settings (workspace_slug, exclude_test_ip_on_kpi, updated_at)
                VALUES (?, 1, ?)
                """,
                (workspace_slug, now),
            )
            row = conn.execute(
                "SELECT workspace_slug, exclude_test_ip_on_kpi, updated_at FROM workspace_kpi_settings WHERE workspace_slug = ?",
                (workspace_slug,),
            ).fetchone()
    data = dict(row)
    data["exclude_test_ip_on_kpi"] = bool(data.get("exclude_test_ip_on_kpi"))
    return data


def set_workspace_kpi_setting(workspace_slug: str, *, exclude_test_ip_on_kpi: bool) -> dict:
    now = utcnow()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO workspace_kpi_settings (workspace_slug, exclude_test_ip_on_kpi, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(workspace_slug) DO UPDATE SET
              exclude_test_ip_on_kpi = excluded.exclude_test_ip_on_kpi,
              updated_at = excluded.updated_at
            """,
            (workspace_slug, 1 if exclude_test_ip_on_kpi else 0, now),
        )
    return get_workspace_kpi_setting(workspace_slug)


def upsert_test_ip_allowlist_entry(
    workspace_slug: str,
    ip_cidr: str,
    *,
    note: str = "",
    actor: str = "admin",
    expires_at: str | None = None,
) -> dict:
    now = utcnow()
    ip_rule = _normalize_ip_cidr(ip_cidr)
    expiry = None
    if str(expires_at or "").strip():
        expiry_dt = _parse_iso_datetime(expires_at)
        if expiry_dt <= datetime.now(timezone.utc):
            raise ValueError("expires_at must be in the future")
        expiry = expiry_dt.isoformat()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO test_ip_allowlist (workspace_slug, ip_cidr, status, note, created_by, created_at, updated_at, expires_at)
            VALUES (?, ?, 'active', ?, ?, ?, ?, ?)
            ON CONFLICT(workspace_slug, ip_cidr) DO UPDATE SET
              status = 'active',
              note = excluded.note,
              created_by = excluded.created_by,
              updated_at = excluded.updated_at,
              expires_at = excluded.expires_at
            """,
            (
                workspace_slug,
                ip_rule,
                str(note or "")[:600],
                str(actor or "admin")[:120],
                now,
                now,
                expiry,
            ),
        )
        row = conn.execute(
            """
            SELECT id, workspace_slug, ip_cidr, status, note, created_by, created_at, updated_at, expires_at
            FROM test_ip_allowlist
            WHERE workspace_slug = ? AND ip_cidr = ?
            """,
            (workspace_slug, ip_rule),
        ).fetchone()
    return dict(row) if row else {}


def set_test_ip_allowlist_status(
    workspace_slug: str,
    entry_id: int,
    *,
    status: str = "inactive",
) -> dict | None:
    st = str(status or "").strip().lower()
    if st not in {"active", "inactive"}:
        st = "inactive"
    now = utcnow()
    with connect() as conn:
        conn.execute(
            """
            UPDATE test_ip_allowlist
            SET status = ?, updated_at = ?
            WHERE id = ? AND workspace_slug = ?
            """,
            (st, now, int(entry_id), workspace_slug),
        )
        row = conn.execute(
            """
            SELECT id, workspace_slug, ip_cidr, status, note, created_by, created_at, updated_at, expires_at
            FROM test_ip_allowlist
            WHERE id = ? AND workspace_slug = ?
            """,
            (int(entry_id), workspace_slug),
        ).fetchone()
    return dict(row) if row else None


def list_test_ip_allowlist(
    workspace_slug: str,
    *,
    active_only: bool = False,
    include_expired: bool = True,
    limit: int = 200,
) -> list[dict]:
    safe_limit = max(1, min(int(limit), 1000))
    where = ["workspace_slug = ?"]
    params: list[object] = [workspace_slug]
    if active_only:
        where.append("status = 'active'")
    query = f"""
        SELECT id, workspace_slug, ip_cidr, status, note, created_by, created_at, updated_at, expires_at
        FROM test_ip_allowlist
        WHERE {' AND '.join(where)}
        ORDER BY updated_at DESC, id DESC
        LIMIT ?
    """
    params.append(safe_limit)
    with connect() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["is_expired"] = _is_expired(item.get("expires_at"))
        if not include_expired and item["is_expired"]:
            continue
        out.append(item)
    return out


def _parse_test_ips(workspace_slug: str) -> list[str]:
    active = list_test_ip_allowlist(workspace_slug, active_only=True, include_expired=False, limit=1000)
    db_rules = [str(row.get("ip_cidr") or "").strip() for row in active if str(row.get("ip_cidr") or "").strip()]
    env_raw = str(os.getenv("IPS_TEST_IP_LIST", "")).strip()
    env_rules = [part.strip() for part in env_raw.split(",") if part.strip()]
    merged: list[str] = []
    for ip_rule in db_rules + env_rules:
        try:
            normalized = _normalize_ip_cidr(ip_rule)
        except ValueError:
            continue
        if normalized not in merged:
            merged.append(normalized)
    return merged


def _next_policy_version_no(workspace_slug: str) -> int:
    with connect() as conn:
        row = conn.execute(
            "SELECT COALESCE(MAX(version_no), 0) AS mx FROM control_policy_versions WHERE workspace_slug = ?",
            (workspace_slug,),
        ).fetchone()
    return int(row["mx"] or 0) + 1


def create_control_policy_version(
    workspace_slug: str,
    policy: dict,
    *,
    title: str = "",
    actor: str = "system",
    note: str = "",
    activate: bool = False,
) -> dict:
    now = utcnow()
    version_no = _next_policy_version_no(workspace_slug)
    policy_json = json.dumps(policy if isinstance(policy, dict) else {}, ensure_ascii=False)
    status = "active" if activate else "draft"
    with connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO control_policy_versions (
              workspace_slug, version_no, title, policy_json, status, created_by, note, created_at, activated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                workspace_slug,
                version_no,
                str(title or "")[:160],
                policy_json,
                status,
                str(actor or "system")[:120],
                str(note or "")[:600],
                now,
                now if activate else None,
            ),
        )
        version_id = int(cur.lastrowid)
        if activate:
            conn.execute(
                "UPDATE control_policy_versions SET status = 'archived' WHERE workspace_slug = ? AND id <> ? AND status = 'active'",
                (workspace_slug, version_id),
            )
            # Keep legacy setting table aligned with control plane active policy.
            wf = bool((policy or {}).get("waf_enabled", True))
            wm = str((policy or {}).get("waf_mode", "block")).strip().lower()
            if wm not in {"block", "monitor"}:
                wm = "block"
            conn.execute(
                """
                INSERT INTO workspace_settings (workspace_slug, waf_enabled, waf_mode, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(workspace_slug) DO UPDATE SET
                  waf_enabled = excluded.waf_enabled,
                  waf_mode = excluded.waf_mode,
                  updated_at = excluded.updated_at
                """,
                (workspace_slug, 1 if wf else 0, wm, now),
            )
        row = conn.execute(
            "SELECT * FROM control_policy_versions WHERE id = ?",
            (version_id,),
        ).fetchone()
    out = dict(row)
    out["policy_json"] = json.loads(out.get("policy_json") or "{}")
    return out


def get_active_control_policy(workspace_slug: str) -> dict:
    with connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM control_policy_versions
            WHERE workspace_slug = ? AND status = 'active'
            ORDER BY version_no DESC, id DESC
            LIMIT 1
            """,
            (workspace_slug,),
        ).fetchone()
    if row:
        out = dict(row)
        out["policy_json"] = json.loads(out.get("policy_json") or "{}")
        return out
    # Bootstrap active policy from legacy workspace settings.
    setting = get_workspace_setting(workspace_slug)
    boot = create_control_policy_version(
        workspace_slug,
        {
            "waf_enabled": bool(setting.get("waf_enabled")),
            "waf_mode": str(setting.get("waf_mode") or "block"),
            "short_ttl_sec": 300,
            "long_ttl_sec": 3600,
            "rate_threshold_pps": 2000,
            "whitelist_cidr": [],
        },
        title="bootstrap-active",
        actor="system",
        note="bootstrap from workspace_settings",
        activate=True,
    )
    return boot


def list_control_policy_versions(workspace_slug: str, limit: int = 20) -> list[dict]:
    safe_limit = max(1, min(int(limit), 200))
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT id, workspace_slug, version_no, title, status, created_by, note, created_at, activated_at
            FROM control_policy_versions
            WHERE workspace_slug = ?
            ORDER BY version_no DESC, id DESC
            LIMIT ?
            """,
            (workspace_slug, safe_limit),
        ).fetchall()
    return [dict(r) for r in rows]


def publish_control_policy_version(workspace_slug: str, version_id: int, actor: str = "system") -> dict | None:
    now = utcnow()
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM control_policy_versions WHERE id = ? AND workspace_slug = ?",
            (int(version_id), workspace_slug),
        ).fetchone()
        if not row:
            return None
        policy = dict(row)
        policy_obj = json.loads(policy.get("policy_json") or "{}")
        conn.execute(
            "UPDATE control_policy_versions SET status = 'archived' WHERE workspace_slug = ? AND status = 'active'",
            (workspace_slug,),
        )
        conn.execute(
            """
            UPDATE control_policy_versions
            SET status = 'active', activated_at = ?, created_by = CASE WHEN created_by = '' THEN ? ELSE created_by END
            WHERE id = ? AND workspace_slug = ?
            """,
            (now, str(actor or "system")[:120], int(version_id), workspace_slug),
        )
        sensors = conn.execute(
            "SELECT sensor_id FROM sensors WHERE workspace_slug = ? AND is_active = 1 ORDER BY sensor_id ASC",
            (workspace_slug,),
        ).fetchall()
        for s in sensors:
            sensor_id = str(s["sensor_id"])
            conn.execute(
                """
                INSERT INTO control_policy_distributions (
                  workspace_slug, policy_version_id, version_no, sensor_id, status, detail_json, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, 'pending', '{}', ?, ?)
                ON CONFLICT(workspace_slug, version_no, sensor_id) DO UPDATE SET
                  status = 'pending',
                  detail_json = '{}',
                  updated_at = excluded.updated_at,
                  acknowledged_at = NULL
                """,
                (workspace_slug, int(version_id), int(policy["version_no"]), sensor_id, now, now),
            )
        wf = bool(policy_obj.get("waf_enabled", True))
        wm = str(policy_obj.get("waf_mode", "block")).strip().lower()
        if wm not in {"block", "monitor"}:
            wm = "block"
        conn.execute(
            """
            INSERT INTO workspace_settings (workspace_slug, waf_enabled, waf_mode, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(workspace_slug) DO UPDATE SET
              waf_enabled = excluded.waf_enabled,
              waf_mode = excluded.waf_mode,
              updated_at = excluded.updated_at
            """,
            (workspace_slug, 1 if wf else 0, wm, now),
        )
        out = conn.execute("SELECT * FROM control_policy_versions WHERE id = ?", (int(version_id),)).fetchone()
    result = dict(out)
    result["policy_json"] = json.loads(result.get("policy_json") or "{}")
    return result


def list_control_policy_distributions(workspace_slug: str, sensor_id: str = "", limit: int = 50) -> list[dict]:
    safe_limit = max(1, min(int(limit), 500))
    with connect() as conn:
        if sensor_id:
            rows = conn.execute(
                """
                SELECT id, workspace_slug, policy_version_id, version_no, sensor_id, status, detail_json, created_at, updated_at, acknowledged_at
                FROM control_policy_distributions
                WHERE workspace_slug = ? AND sensor_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (workspace_slug, sensor_id, safe_limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, workspace_slug, policy_version_id, version_no, sensor_id, status, detail_json, created_at, updated_at, acknowledged_at
                FROM control_policy_distributions
                WHERE workspace_slug = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (workspace_slug, safe_limit),
            ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["detail_json"] = json.loads(item.get("detail_json") or "{}")
        out.append(item)
    return out


def control_plane_overview(workspace_slug: str) -> dict:
    waf = get_workspace_setting(workspace_slug)
    active_policy = get_active_control_policy(workspace_slug)
    with connect() as conn:
        dist_rows = conn.execute(
            """
            SELECT status, COUNT(*) AS cnt
            FROM control_policy_distributions
            WHERE workspace_slug = ?
            GROUP BY status
            ORDER BY status ASC
            """,
            (workspace_slug,),
        ).fetchall()
        latest_dist_rows = conn.execute(
            """
            SELECT id, version_no, sensor_id, status, updated_at, acknowledged_at
            FROM control_policy_distributions
            WHERE workspace_slug = ?
            ORDER BY id DESC
            LIMIT 10
            """,
            (workspace_slug,),
        ).fetchall()
    dist_counts = {str(r["status"]): int(r["cnt"] or 0) for r in dist_rows}
    return {
        "workspace_slug": workspace_slug,
        "waf": waf,
        "active_policy": {
            "id": active_policy.get("id"),
            "version_no": active_policy.get("version_no"),
            "title": active_policy.get("title"),
            "status": active_policy.get("status"),
            "activated_at": active_policy.get("activated_at"),
        },
        "distribution_counts": dist_counts,
        "recent_distributions": [dict(x) for x in latest_dist_rows],
        "sensors": list_sensors_summary(workspace_slug),
    }


def get_pending_policy_distribution(workspace_slug: str, sensor_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM control_policy_distributions
            WHERE workspace_slug = ? AND sensor_id = ? AND status = 'pending'
            ORDER BY id ASC
            LIMIT 1
            """,
            (workspace_slug, sensor_id),
        ).fetchone()
    if not row:
        return None
    out = dict(row)
    out["detail_json"] = json.loads(out.get("detail_json") or "{}")
    return out


def ack_policy_distribution(workspace_slug: str, sensor_id: str, distribution_id: int, status: str, detail: dict | None = None) -> dict | None:
    st = str(status or "").strip().lower()
    if st not in {"applied", "failed", "ignored"}:
        return None
    now = utcnow()
    detail_json = json.dumps(detail if isinstance(detail, dict) else {}, ensure_ascii=False)
    with connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM control_policy_distributions
            WHERE id = ? AND workspace_slug = ? AND sensor_id = ?
            """,
            (int(distribution_id), workspace_slug, sensor_id),
        ).fetchone()
        if not row:
            return None
        conn.execute(
            """
            UPDATE control_policy_distributions
            SET status = ?, detail_json = ?, updated_at = ?, acknowledged_at = ?
            WHERE id = ? AND workspace_slug = ? AND sensor_id = ?
            """,
            (st, detail_json, now, now, int(distribution_id), workspace_slug, sensor_id),
        )
        out = conn.execute("SELECT * FROM control_policy_distributions WHERE id = ?", (int(distribution_id),)).fetchone()
    result = dict(out)
    result["detail_json"] = json.loads(result.get("detail_json") or "{}")
    return result


def get_sensor(workspace_slug: str, sensor_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM sensors WHERE workspace_slug = ? AND sensor_id = ? AND is_active = 1",
            (workspace_slug, sensor_id),
        ).fetchone()
    if not row:
        return None
    data = dict(row)
    data["meta_json"] = json.loads(data["meta_json"] or "{}")
    return data


def list_sensors_summary(workspace_slug: str | None = None) -> dict:
    shard_count = _ingest_shard_count()
    with connect() as conn:
        if workspace_slug:
            rows = conn.execute(
                """
                SELECT sensor_type, COUNT(*) AS total, SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) AS active
                FROM sensors
                WHERE workspace_slug = ?
                GROUP BY sensor_type
                ORDER BY total DESC, sensor_type ASC
                """,
                (workspace_slug,),
            ).fetchall()
            total = conn.execute("SELECT COUNT(*) AS c FROM sensors WHERE workspace_slug = ?", (workspace_slug,)).fetchone()["c"]
            active = conn.execute("SELECT COUNT(*) AS c FROM sensors WHERE workspace_slug = ? AND is_active = 1", (workspace_slug,)).fetchone()["c"]
            shard_rows = conn.execute(
                """
                SELECT sensor_id, is_active, meta_json
                FROM sensors
                WHERE workspace_slug = ?
                """,
                (workspace_slug,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT sensor_type, COUNT(*) AS total, SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) AS active
                FROM sensors
                GROUP BY sensor_type
                ORDER BY total DESC, sensor_type ASC
                """
            ).fetchall()
            total = conn.execute("SELECT COUNT(*) AS c FROM sensors").fetchone()["c"]
            active = conn.execute("SELECT COUNT(*) AS c FROM sensors WHERE is_active = 1").fetchone()["c"]
            shard_rows = conn.execute("SELECT workspace_slug, sensor_id, is_active, meta_json FROM sensors").fetchall()
    shard_dist: dict[int, dict[str, int]] = {i: {"total": 0, "active": 0} for i in range(shard_count)}
    for row in shard_rows:
        sid = str(row["sensor_id"] or "")
        ws = str(row["workspace_slug"] if "workspace_slug" in row.keys() else workspace_slug or "")
        is_active = int(row["is_active"] or 0) == 1
        meta_raw = str(row["meta_json"] or "{}")
        shard_id = None
        try:
            meta = json.loads(meta_raw) if meta_raw else {}
            shard_id = int(meta.get("ingest_shard"))
        except (TypeError, ValueError, json.JSONDecodeError):
            shard_id = None
        if shard_id is None:
            shard_id = _sensor_home_shard(ws, sid, shard_count)
        shard_id = max(0, min(int(shard_id), max(0, shard_count - 1)))
        shard_dist[shard_id]["total"] += 1
        if is_active:
            shard_dist[shard_id]["active"] += 1
    return {
        "workspace_slug": workspace_slug,
        "total_sensors": int(total or 0),
        "active_sensors": int(active or 0),
        "by_type": [{"sensor_type": r["sensor_type"], "total": int(r["total"] or 0), "active": int(r["active"] or 0)} for r in rows],
        "ingest_shard_count": shard_count,
        "ingest_shard_distribution": [
            {"shard_id": sid, "total": int(vals["total"]), "active": int(vals["active"])}
            for sid, vals in sorted(shard_dist.items(), key=lambda x: x[0])
        ],
    }


def touch_sensor(workspace_slug: str, sensor_id: str) -> None:
    now = utcnow()
    with connect() as conn:
        conn.execute(
            "UPDATE sensors SET last_seen_at = ?, updated_at = ? WHERE workspace_slug = ? AND sensor_id = ?",
            (now, now, workspace_slug, sensor_id),
        )


def create_block_action(payload: dict) -> dict:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=int(payload["ttl_seconds"]))
    setting = get_workspace_setting(payload["workspace_slug"])
    is_waf_enabled = bool(setting.get("waf_enabled"))
    status = "pending" if is_waf_enabled else "canceled"
    acknowledged_at = None if is_waf_enabled else now.isoformat()
    response_meta = {}
    if not is_waf_enabled:
        response_meta = {"reason": "waf_disabled"}
    with connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO block_actions (
              workspace_slug, sensor_id, target_type, target_value, stage, ttl_seconds, reason, status,
              created_at, expires_at, acknowledged_at, response_meta
            )
            VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload["workspace_slug"],
                payload["target_type"],
                payload["target_value"],
                payload["stage"],
                int(payload["ttl_seconds"]),
                payload.get("reason", ""),
                status,
                now.isoformat(),
                expires_at.isoformat(),
                acknowledged_at,
                json.dumps(response_meta, ensure_ascii=False),
            ),
        )
        action_id = cur.lastrowid
        row = conn.execute("SELECT * FROM block_actions WHERE id = ?", (action_id,)).fetchone()
    return dict(row)


def fetch_pending_actions(workspace_slug: str, sensor_id: str, limit: int) -> list[dict]:
    setting = get_workspace_setting(workspace_slug)
    if not bool(setting.get("waf_enabled")):
        return []
    now = datetime.now(timezone.utc).isoformat()
    with connect() as conn:
        conn.execute(
            "UPDATE block_actions SET status = 'expired' WHERE workspace_slug = ? AND status = 'pending' AND expires_at < ?",
            (workspace_slug, now),
        )
        rows = conn.execute(
            """
            SELECT * FROM block_actions
            WHERE workspace_slug = ? AND status = 'pending'
            ORDER BY created_at ASC, id ASC
            LIMIT ?
            """,
            (workspace_slug, limit),
        ).fetchall()
        ids = [row["id"] for row in rows]
        if ids:
            conn.executemany(
                "UPDATE block_actions SET status = 'sent', sensor_id = ? WHERE id = ?",
                [(sensor_id, action_id) for action_id in ids],
            )
    return [dict(row) for row in rows]


def ack_action(workspace_slug: str, action_id: int, sensor_id: str, status: str, meta: dict) -> dict | None:
    now = utcnow()
    with connect() as conn:
        conn.execute(
            """
            UPDATE block_actions
            SET status = ?, sensor_id = ?, acknowledged_at = ?, response_meta = ?
            WHERE id = ? AND workspace_slug = ?
            """,
            (status, sensor_id, now, json.dumps(meta, ensure_ascii=False), action_id, workspace_slug),
        )
        row = conn.execute("SELECT * FROM block_actions WHERE id = ? AND workspace_slug = ?", (action_id, workspace_slug)).fetchone()
    return dict(row) if row else None


def upsert_remote_action(payload: dict) -> dict:
    now = utcnow()
    workspace_slug = str(payload.get("workspace_slug") or "lab").strip() or "lab"
    xdr_action_id_raw = payload.get("xdr_action_id")
    try:
        xdr_action_id = int(xdr_action_id_raw)
    except (TypeError, ValueError):
        xdr_action_id = None
    if xdr_action_id is not None and xdr_action_id <= 0:
        xdr_action_id = None
    requested_at = str(payload.get("requested_at") or now)
    target = payload.get("target")
    if not isinstance(target, dict):
        target = {}
    with connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO remote_actions (
              workspace_slug, xdr_action_id, incident_id, case_id, action_type,
              target_json, requested_by, requested_at, status, result_summary,
              result_meta_json, executed_at, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
            ON CONFLICT(workspace_slug, xdr_action_id) DO UPDATE SET
              incident_id = excluded.incident_id,
              case_id = excluded.case_id,
              action_type = excluded.action_type,
              target_json = excluded.target_json,
              requested_by = excluded.requested_by,
              requested_at = excluded.requested_at,
              updated_at = excluded.updated_at
            """,
            (
                workspace_slug,
                xdr_action_id,
                payload.get("incident_id"),
                payload.get("case_id"),
                str(payload.get("action_type") or ""),
                json.dumps(target, ensure_ascii=False),
                str(payload.get("requested_by") or ""),
                requested_at,
                str(payload.get("status") or "received"),
                str(payload.get("result_summary") or ""),
                json.dumps(payload.get("result_meta") or {}, ensure_ascii=False),
                now,
                now,
            ),
        )
        if cur.lastrowid:
            row = conn.execute("SELECT * FROM remote_actions WHERE id = ?", (cur.lastrowid,)).fetchone()
        elif xdr_action_id is not None:
            row = conn.execute(
                "SELECT * FROM remote_actions WHERE workspace_slug = ? AND xdr_action_id = ?",
                (workspace_slug, xdr_action_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM remote_actions WHERE workspace_slug = ? ORDER BY id DESC LIMIT 1",
                (workspace_slug,),
            ).fetchone()
    data = dict(row)
    data["target"] = json.loads(data.get("target_json") or "{}")
    data["result_meta"] = json.loads(data.get("result_meta_json") or "{}")
    return data


def set_remote_action_result(
    workspace_slug: str,
    remote_action_id: int,
    status: str,
    result_summary: str,
    result_meta: dict | None = None,
) -> dict | None:
    now = utcnow()
    with connect() as conn:
        conn.execute(
            """
            UPDATE remote_actions
            SET status = ?, result_summary = ?, result_meta_json = ?, executed_at = ?, updated_at = ?
            WHERE workspace_slug = ? AND id = ?
            """,
            (
                status,
                result_summary,
                json.dumps(result_meta or {}, ensure_ascii=False),
                now,
                now,
                workspace_slug,
                remote_action_id,
            ),
        )
        row = conn.execute(
            "SELECT * FROM remote_actions WHERE workspace_slug = ? AND id = ?",
            (workspace_slug, remote_action_id),
        ).fetchone()
    if not row:
        return None
    data = dict(row)
    data["target"] = json.loads(data.get("target_json") or "{}")
    data["result_meta"] = json.loads(data.get("result_meta_json") or "{}")
    return data


def list_remote_actions(workspace_slug: str, limit: int = 100) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT * FROM remote_actions
            WHERE workspace_slug = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (workspace_slug, max(1, limit)),
        ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["target"] = json.loads(item.get("target_json") or "{}")
        item["result_meta"] = json.loads(item.get("result_meta_json") or "{}")
        out.append(item)
    return out


def cancel_block_actions_for_target(workspace_slug: str, target_type: str, target_value: str, reason: str = "") -> int:
    now = utcnow()
    reason_json = json.dumps({"reason": reason or "xdr_remote_unblock"}, ensure_ascii=False)
    with connect() as conn:
        cur = conn.execute(
            """
            UPDATE block_actions
            SET status = 'canceled',
                acknowledged_at = ?,
                response_meta = ?
            WHERE workspace_slug = ?
              AND target_type = ?
              AND target_value = ?
              AND status IN ('pending', 'sent', 'applied')
            """,
            (now, reason_json, workspace_slug, target_type, target_value),
        )
    return int(cur.rowcount or 0)


def get_source_heartbeat_snapshot(workspace_slug: str, sensor_id: str | None = None) -> dict:
    with connect() as conn:
        totals = conn.execute(
            """
            SELECT
              COUNT(*) AS total_sensors,
              SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) AS active_sensors,
              MAX(last_seen_at) AS last_seen_at
            FROM sensors
            WHERE workspace_slug = ?
            """,
            (workspace_slug,),
        ).fetchone()
        if sensor_id:
            selected_sensor = conn.execute(
                """
                SELECT sensor_id, sensor_type, is_active, last_seen_at, updated_at
                FROM sensors
                WHERE workspace_slug = ? AND sensor_id = ?
                """,
                (workspace_slug, sensor_id),
            ).fetchone()
        else:
            selected_sensor = None
        latest_event = conn.execute(
            "SELECT MAX(detected_at) AS latest_event_at FROM security_events WHERE workspace_slug = ?",
            (workspace_slug,),
        ).fetchone()
    setting = get_workspace_setting(workspace_slug)
    return {
        "workspace_slug": workspace_slug,
        "sensor_id": sensor_id or "",
        "total_sensors": int((totals["total_sensors"] if totals else 0) or 0),
        "active_sensors": int((totals["active_sensors"] if totals else 0) or 0),
        "last_seen_at": (totals["last_seen_at"] if totals else None),
        "latest_event_at": (latest_event["latest_event_at"] if latest_event else None),
        "waf_enabled": bool(setting.get("waf_enabled")),
        "waf_mode": str(setting.get("waf_mode") or "block"),
        "selected_sensor": dict(selected_sensor) if selected_sensor else None,
        "generated_at": utcnow(),
    }


def upsert_notification_channel(payload: dict) -> dict:
    now = utcnow()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO notification_channels (workspace_slug, channel_type, webhook_url, is_enabled, secret_token, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace_slug, channel_type, webhook_url) DO UPDATE SET
              is_enabled = excluded.is_enabled,
              secret_token = excluded.secret_token,
              updated_at = excluded.updated_at
            """,
            (
                payload["workspace_slug"],
                payload["channel_type"],
                payload["webhook_url"],
                1 if payload.get("is_enabled", True) else 0,
                payload.get("secret_token", ""),
                now,
                now,
            ),
        )
        row = conn.execute(
            """
            SELECT id, workspace_slug, channel_type, webhook_url, is_enabled, updated_at
            FROM notification_channels
            WHERE workspace_slug = ? AND channel_type = ? AND webhook_url = ?
            """,
            (payload["workspace_slug"], payload["channel_type"], payload["webhook_url"]),
        ).fetchone()
    data = dict(row)
    data["is_enabled"] = bool(data.get("is_enabled"))
    return data


def list_notification_channels(workspace_slug: str | None = None) -> list[dict]:
    with connect() as conn:
        if workspace_slug:
            rows = conn.execute(
                """
                SELECT id, workspace_slug, channel_type, webhook_url, is_enabled, updated_at
                FROM notification_channels
                WHERE workspace_slug = ?
                ORDER BY channel_type ASC, id ASC
                """,
                (workspace_slug,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, workspace_slug, channel_type, webhook_url, is_enabled, updated_at
                FROM notification_channels
                ORDER BY workspace_slug ASC, channel_type ASC, id ASC
                """
            ).fetchall()
    out = []
    for row in rows:
        data = dict(row)
        data["is_enabled"] = bool(data.get("is_enabled"))
        out.append(data)
    return out


def get_enabled_notification_channels(workspace_slug: str) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT workspace_slug, channel_type, webhook_url, secret_token
            FROM notification_channels
            WHERE workspace_slug = ? AND is_enabled = 1
            ORDER BY channel_type ASC, id ASC
            """,
            (workspace_slug,),
        ).fetchall()
    return [dict(row) for row in rows]


def record_notification_event(workspace_slug: str, channel_type: str, event_type: str, status: str, detail: str = "") -> None:
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO notification_events (workspace_slug, channel_type, event_type, status, detail, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (workspace_slug, channel_type, event_type, status, detail[:500], utcnow()),
        )


def list_notification_events(workspace_slug: str | None = None, limit: int = 50) -> list[dict]:
    safe_limit = max(1, min(int(limit), 500))
    with connect() as conn:
        if workspace_slug:
            rows = conn.execute(
                """
                SELECT workspace_slug, channel_type, event_type, status, detail, created_at
                FROM notification_events
                WHERE workspace_slug = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (workspace_slug, safe_limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT workspace_slug, channel_type, event_type, status, detail, created_at
                FROM notification_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
    return [dict(row) for row in rows]


def record_admin_audit_log(actor: str, action: str, status: str, path: str, detail: str = "") -> None:
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO admin_audit_logs (actor, action, status, path, detail, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (str(actor or "unknown")[:120], str(action or "")[:120], str(status or "")[:30], str(path or "")[:220], str(detail or "")[:1000], utcnow()),
        )


def list_admin_audit_logs(limit: int = 100) -> list[dict]:
    safe_limit = max(1, min(int(limit), 1000))
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT id, actor, action, status, path, detail, created_at
            FROM admin_audit_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def prune_admin_audit_logs(retention_days: int = 30) -> int:
    days = max(1, min(int(retention_days), 3650))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with connect() as conn:
        cur = conn.execute("DELETE FROM admin_audit_logs WHERE created_at < ?", (cutoff,))
        return int(cur.rowcount or 0)


def list_security_events_for_eval(workspace_slug: str, since_iso: str | None = None, limit: int = 50000) -> list[dict]:
    safe_limit = max(1, min(int(limit), 200000))
    with connect() as conn:
        if since_iso:
            rows = conn.execute(
                """
                SELECT source_event_key, detected_at, severity, action, raw_event
                FROM security_events
                WHERE workspace_slug = ? AND detected_at >= ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (workspace_slug, since_iso, safe_limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT source_event_key, detected_at, severity, action, raw_event
                FROM security_events
                WHERE workspace_slug = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (workspace_slug, safe_limit),
            ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        try:
            item["raw_event"] = json.loads(item.get("raw_event") or "{}")
        except Exception:
            item["raw_event"] = {}
        out.append(item)
    return out


def save_e2e_eval_run(
    workspace_slug: str,
    profile: str,
    thresholds: dict,
    summary: dict,
    scenarios: list[dict],
) -> dict:
    now = utcnow()
    with connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO e2e_eval_runs (
              workspace_slug, profile, total_events, attack_events, benign_events,
              attack_mitigation_rate, attack_block_rate, benign_mitigation_rate, benign_block_rate,
              p95_ms, p99_ms, passed, thresholds_json, summary_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                workspace_slug,
                str(profile or "default")[:60],
                int(summary.get("total_events") or 0),
                int(summary.get("attack_events") or 0),
                int(summary.get("benign_events") or 0),
                float(summary.get("attack_mitigation_rate") or 0.0),
                float(summary.get("attack_block_rate") or 0.0),
                float(summary.get("benign_mitigation_rate") or 0.0),
                float(summary.get("benign_block_rate") or 0.0),
                float(summary.get("p95_ms") or 0.0),
                float(summary.get("p99_ms") or 0.0),
                1 if bool(summary.get("passed")) else 0,
                json.dumps(thresholds or {}, ensure_ascii=False),
                json.dumps(summary or {}, ensure_ascii=False),
                now,
            ),
        )
        run_id = int(cur.lastrowid)
        for row in scenarios:
            conn.execute(
                """
                INSERT INTO e2e_eval_scenarios (run_id, scenario, total, attack, benign, mitigated, blocked, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    str(row.get("scenario") or "unknown")[:120],
                    int(row.get("total") or 0),
                    int(row.get("attack") or 0),
                    int(row.get("benign") or 0),
                    int(row.get("mitigated") or 0),
                    int(row.get("blocked") or 0),
                    now,
                ),
            )
        run = conn.execute("SELECT * FROM e2e_eval_runs WHERE id = ?", (run_id,)).fetchone()
    data = dict(run)
    data["thresholds"] = json.loads(data.pop("thresholds_json") or "{}")
    data["summary"] = json.loads(data.pop("summary_json") or "{}")
    data["passed"] = bool(data.get("passed"))
    return data


def list_e2e_eval_runs(workspace_slug: str, limit: int = 20) -> list[dict]:
    safe_limit = max(1, min(int(limit), 200))
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT * FROM e2e_eval_runs
            WHERE workspace_slug = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (workspace_slug, safe_limit),
        ).fetchall()
        out = []
        run_ids = [int(r["id"]) for r in rows]
        scenarios_by_run: dict[int, list[dict]] = {rid: [] for rid in run_ids}
        if run_ids:
            placeholders = ",".join("?" for _ in run_ids)
            scenario_rows = conn.execute(
                f"""
                SELECT run_id, scenario, total, attack, benign, mitigated, blocked
                FROM e2e_eval_scenarios
                WHERE run_id IN ({placeholders})
                ORDER BY run_id DESC, scenario ASC
                """,
                tuple(run_ids),
            ).fetchall()
            for srow in scenario_rows:
                rid = int(srow["run_id"])
                scenarios_by_run.setdefault(rid, []).append(
                    {
                        "scenario": srow["scenario"],
                        "total": int(srow["total"] or 0),
                        "attack": int(srow["attack"] or 0),
                        "benign": int(srow["benign"] or 0),
                        "mitigated": int(srow["mitigated"] or 0),
                        "blocked": int(srow["blocked"] or 0),
                    }
                )
        for row in rows:
            item = dict(row)
            item["thresholds"] = json.loads(item.pop("thresholds_json") or "{}")
            item["summary"] = json.loads(item.pop("summary_json") or "{}")
            item["passed"] = bool(item.get("passed"))
            item["scenarios"] = scenarios_by_run.get(int(item["id"]), [])
            out.append(item)
    return out


def _append_event_tag(event: dict, tag: str) -> None:
    if not isinstance(event, dict):
        return
    tags = event.get("tags")
    if not isinstance(tags, list):
        tags = []
        event["tags"] = tags
    if tag not in tags:
        tags.append(tag)


def _event_host_candidates(event: dict) -> set[str]:
    out: set[str] = set()
    for key in ("host", "dst_host", "server_name", "http_host", "authority"):
        value = str(event.get(key) or "").strip().lower().rstrip(".")
        if value:
            out.add(value)
    url_value = str(event.get("url") or event.get("request_url") or "").strip()
    if url_value:
        parsed = urllib.parse.urlparse(url_value)
        host = str(parsed.hostname or "").strip().lower().rstrip(".")
        if host:
            out.add(host)
    return out


def _event_request_path(event: dict) -> str:
    for key in ("uri", "path", "request_path"):
        value = str(event.get(key) or "").strip()
        if value:
            if not value.startswith("/"):
                return "/" + value
            return value
    url_value = str(event.get("url") or event.get("request_url") or "").strip()
    if not url_value:
        return ""
    parsed = urllib.parse.urlparse(url_value)
    path = str(parsed.path or "").strip()
    if not path:
        return ""
    if not path.startswith("/"):
        return "/" + path
    return path


def _event_referrer_host(event: dict) -> str:
    ref = str(event.get("referrer") or event.get("referer") or event.get("http_referrer") or "").strip()
    if not ref:
        return ""
    parsed = urllib.parse.urlparse(ref)
    return str(parsed.hostname or "").strip().lower().rstrip(".")


def _event_hashes(event: dict) -> tuple[str, str]:
    sha256 = str(event.get("sha256") or event.get("file_sha256") or "").strip().lower()
    md5 = str(event.get("md5") or event.get("file_md5") or "").strip().lower()
    if sha256 and not re.fullmatch(r"[0-9a-f]{64}", sha256):
        sha256 = ""
    if md5 and not re.fullmatch(r"[0-9a-f]{32}", md5):
        md5 = ""
    return sha256, md5


def _path_has_suspicious_extension(path: str) -> str:
    p = str(path or "").strip().lower()
    if not p:
        return ""
    for ext in _DELIVERY_SUSPICIOUS_EXTENSIONS:
        if p.endswith(ext):
            return ext
        if f"{ext}?" in p:
            return ext
    return ""


def _load_delivery_chain_matcher() -> dict[str, object]:
    global _DELIVERY_CHAIN_MATCHER_CACHE
    now_mono = time.monotonic()
    cached = _DELIVERY_CHAIN_MATCHER_CACHE
    if cached and (now_mono - cached[0]) < _DELIVERY_CHAIN_MATCHER_CACHE_TTL_SEC:
        return cached[1]
    now = utcnow()
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT indicator_type, indicator_value, source, category, note
            FROM threat_intel_entries
            WHERE status = 'active'
              AND (expires_at IS NULL OR expires_at > ?)
              AND indicator_type IN ('domain', 'url', 'sha256', 'md5')
            ORDER BY updated_at DESC, id DESC
            LIMIT 100000
            """,
            (now,),
        ).fetchall()
    domains: set[str] = set()
    url_paths_by_host: dict[str, list[str]] = {}
    sha256_values: set[str] = set()
    md5_values: set[str] = set()
    sources: set[str] = set()
    for row in rows:
        source = str(row["source"] or "").strip()
        category = str(row["category"] or "").strip()
        note = str(row["note"] or "").strip()
        keyword_blob = f"{source} {category} {note}".lower()
        if not any(k in keyword_blob for k in _DELIVERY_CHAIN_KEYWORDS):
            continue
        itype = str(row["indicator_type"] or "").strip().lower()
        ivalue = str(row["indicator_value"] or "").strip()
        if not ivalue:
            continue
        if source:
            sources.add(source)
        if itype == "domain":
            host = ivalue.lower().rstrip(".")
            if host:
                domains.add(host)
        elif itype == "url":
            parsed = urllib.parse.urlparse(ivalue)
            host = str(parsed.hostname or "").strip().lower().rstrip(".")
            if not host:
                continue
            path = str(parsed.path or "").strip() or "/"
            url_paths_by_host.setdefault(host, []).append(path)
        elif itype == "sha256":
            val = ivalue.lower()
            if re.fullmatch(r"[0-9a-f]{64}", val):
                sha256_values.add(val)
        elif itype == "md5":
            val = ivalue.lower()
            if re.fullmatch(r"[0-9a-f]{32}", val):
                md5_values.add(val)
    for host, paths in list(url_paths_by_host.items()):
        uniq = sorted({p for p in paths if p}, key=lambda v: len(v), reverse=True)
        url_paths_by_host[host] = uniq[:300]
    matcher = {
        "domains": domains,
        "url_paths_by_host": url_paths_by_host,
        "sha256": sha256_values,
        "md5": md5_values,
        "sources": sorted(sources)[:30],
    }
    _DELIVERY_CHAIN_MATCHER_CACHE = (now_mono, matcher)
    return matcher


def _detect_delivery_chain(
    event: dict,
    matcher: dict[str, object],
    *,
    host_candidates: set[str] | None = None,
    req_path: str | None = None,
) -> dict | None:
    domains = matcher.get("domains") if isinstance(matcher, dict) else set()
    url_paths_by_host = matcher.get("url_paths_by_host") if isinstance(matcher, dict) else {}
    hash_sha256 = matcher.get("sha256") if isinstance(matcher, dict) else set()
    hash_md5 = matcher.get("md5") if isinstance(matcher, dict) else set()
    sources = matcher.get("sources") if isinstance(matcher, dict) else []
    domains = domains if isinstance(domains, set) else set()
    url_paths_by_host = url_paths_by_host if isinstance(url_paths_by_host, dict) else {}
    hash_sha256 = hash_sha256 if isinstance(hash_sha256, set) else set()
    hash_md5 = hash_md5 if isinstance(hash_md5, set) else set()
    sources = sources if isinstance(sources, list) else []

    if host_candidates is None:
        host_candidates = _event_host_candidates(event)
    if req_path is None:
        req_path = _event_request_path(event)
    ref_host = _event_referrer_host(event)
    sha256, md5 = _event_hashes(event)
    reasons: list[dict[str, str]] = []
    score = 0
    chain_type = "delivery_chain"

    for host in host_candidates:
        if host in domains:
            reasons.append({"kind": "domain", "value": host})
            score += 48
        for prefix in url_paths_by_host.get(host, []):
            if req_path and (req_path == prefix or req_path.startswith(prefix.rstrip("*"))):
                reasons.append({"kind": "url_path", "value": f"{host}{prefix}"})
                score += 45
                break

    if sha256 and sha256 in hash_sha256:
        reasons.append({"kind": "sha256", "value": sha256})
        score += 50
    if md5 and md5 in hash_md5:
        reasons.append({"kind": "md5", "value": md5})
        score += 35

    suspicious_ext = _path_has_suspicious_extension(req_path)
    if suspicious_ext:
        reasons.append({"kind": "suspicious_ext", "value": suspicious_ext})
        score += 20

    if ref_host and ref_host not in host_candidates:
        if ref_host in _DELIVERY_SHORTENER_HOSTS:
            reasons.append({"kind": "shortener_referrer", "value": ref_host})
            score += 16
            chain_type = "malvertising_chain"
        if any(ref_host.endswith(h) for h in _DELIVERY_FILE_DISTRIBUTION_HOSTS):
            reasons.append({"kind": "file_hosting_referrer", "value": ref_host})
            score += 14
        if suspicious_ext:
            reasons.append({"kind": "cross_host_redirect", "value": f"{ref_host}->{','.join(sorted(host_candidates)[:2])}"})
            score += 12

    for host in host_candidates:
        if any(host.endswith(h) for h in _DELIVERY_FILE_DISTRIBUTION_HOSTS):
            reasons.append({"kind": "file_hosting_dst", "value": host})
            score += 10

    signature_blob = f"{str(event.get('signature') or '')} {str(event.get('event_type') or '')}".lower()
    if "phish" in signature_blob or "clickfix" in signature_blob:
        reasons.append({"kind": "signature_hint", "value": "phishing_like"})
        score += 12
        chain_type = "phishing_chain"

    if score < 45:
        return None
    unique_reasons = []
    seen = set()
    for item in reasons:
        key = f"{item.get('kind')}::{item.get('value')}"
        if key in seen:
            continue
        seen.add(key)
        unique_reasons.append(item)
    if not unique_reasons:
        return None
    confidence = min(0.99, max(0.45, score / 100.0))
    return {
        "matched": True,
        "chain_type": chain_type,
        "score": score,
        "confidence": round(confidence, 3),
        "reasons": unique_reasons[:8],
        "sources": sources[:8],
    }


def _extract_event_cves(event: dict) -> list[str]:
    found: set[str] = set()
    for key in ("cve", "cve_id"):
        value = str(event.get(key) or "").strip().upper()
        if value:
            for m in _CVE_RE.findall(value):
                found.add(m.upper())
    cves_obj = event.get("cves")
    if isinstance(cves_obj, list):
        for raw in cves_obj:
            for m in _CVE_RE.findall(str(raw or "").strip().upper()):
                found.add(m.upper())
    blob = " ".join(
        [
            str(event.get("signature") or ""),
            str(event.get("rule") or ""),
            str(event.get("payload_excerpt") or ""),
            str(event.get("message") or ""),
            str(event.get("uri") or ""),
            str(event.get("path") or ""),
        ]
    )
    for m in _CVE_RE.findall(blob):
        found.add(m.upper())
    return sorted(found)


def _load_kev_matcher() -> dict[str, object]:
    global _KEV_MATCHER_CACHE
    now_mono = time.monotonic()
    cached = _KEV_MATCHER_CACHE
    if cached and (now_mono - float(cached[0])) < _KEV_MATCHER_CACHE_TTL_SEC:
        return cached[1]
    now = utcnow()
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT indicator_type, indicator_value, source
            FROM threat_intel_entries
            WHERE status = 'active'
              AND (expires_at IS NULL OR expires_at > ?)
              AND lower(source) LIKE '%kev%'
              AND indicator_type IN ('cve', 'domain', 'url')
            ORDER BY updated_at DESC, id DESC
            LIMIT 50000
            """,
            (now,),
        ).fetchall()
    cves: set[str] = set()
    domains: set[str] = set()
    url_paths_by_host: dict[str, list[str]] = {}
    sources: set[str] = set()
    for row in rows:
        itype = str(row["indicator_type"] or "").strip().lower()
        ivalue = str(row["indicator_value"] or "").strip()
        source = str(row["source"] or "").strip()
        if source:
            sources.add(source)
        if not ivalue:
            continue
        if itype == "cve":
            for m in _CVE_RE.findall(ivalue.upper()):
                cves.add(m.upper())
        elif itype == "domain":
            host = ivalue.lower().rstrip(".")
            if host:
                domains.add(host)
        elif itype == "url":
            parsed = urllib.parse.urlparse(ivalue)
            host = str(parsed.hostname or "").strip().lower().rstrip(".")
            if not host:
                continue
            path = str(parsed.path or "").strip() or "/"
            bucket = url_paths_by_host.setdefault(host, [])
            bucket.append(path)
    for host, paths in list(url_paths_by_host.items()):
        uniq = sorted({p for p in paths if p}, key=lambda v: len(v), reverse=True)
        url_paths_by_host[host] = uniq[:300]
    matcher = {
        "cves": cves,
        "domains": domains,
        "url_paths_by_host": url_paths_by_host,
        "sources": sorted(sources)[:20],
    }
    _KEV_MATCHER_CACHE = (now_mono, matcher)
    return matcher


def _load_workspace_asset_matcher(workspace_slug: str) -> dict[str, object]:
    now_mono = time.monotonic()
    cached = _ASSET_MATCHER_CACHE.get(workspace_slug)
    if cached and (now_mono - float(cached[0])) < _ASSET_MATCHER_CACHE_TTL_SEC:
        return cached[1]
    assets = list_workspace_assets(workspace_slug, active_only=True, limit=2000)
    host_map: dict[str, list[dict]] = {}
    nets: list[tuple[ipaddress._BaseNetwork, dict]] = []
    port_map: dict[int, list[dict]] = {}
    for asset in assets:
        host = str(asset.get("host") or "").strip().lower().rstrip(".")
        if host:
            host_map.setdefault(host, []).append(asset)
        cidr = str(asset.get("ip_cidr") or "").strip()
        if cidr:
            try:
                nets.append((ipaddress.ip_network(cidr, strict=False), asset))
            except ValueError:
                pass
        port_value = asset.get("service_port")
        if port_value is not None:
            try:
                port = int(port_value)
            except (TypeError, ValueError):
                port = 0
            if 1 <= port <= 65535:
                port_map.setdefault(port, []).append(asset)
    matcher = {"host_map": host_map, "nets": nets, "port_map": port_map}
    _ASSET_MATCHER_CACHE[workspace_slug] = (now_mono, matcher)
    return matcher


def _match_workspace_asset(
    event: dict,
    matcher: dict[str, object],
    *,
    host_candidates: set[str] | None = None,
    dst_ip: ipaddress._BaseAddress | None = None,
    dst_port: int | None = None,
) -> dict | None:
    host_map = matcher.get("host_map") if isinstance(matcher, dict) else {}
    nets = matcher.get("nets") if isinstance(matcher, dict) else []
    port_map = matcher.get("port_map") if isinstance(matcher, dict) else {}
    host_map = host_map if isinstance(host_map, dict) else {}
    nets = nets if isinstance(nets, list) else []
    port_map = port_map if isinstance(port_map, dict) else {}
    if host_candidates is None:
        host_candidates = _event_host_candidates(event)
    if dst_ip is None:
        dst_ip_raw = str(event.get("dst_ip") or "").strip()
        if dst_ip_raw:
            try:
                dst_ip = ipaddress.ip_address(dst_ip_raw)
            except ValueError:
                dst_ip = None
    if dst_port is None:
        try:
            if event.get("dst_port") is not None:
                dst_port = int(event.get("dst_port"))
        except (TypeError, ValueError):
            dst_port = None

    scores: dict[str, dict] = {}

    def bump(asset: dict, points: int, reason: str) -> None:
        key = str(asset.get("asset_key") or asset.get("id") or "")
        if not key:
            return
        item = scores.get(key)
        if item is None:
            item = {
                "asset_key": str(asset.get("asset_key") or ""),
                "display_name": str(asset.get("display_name") or ""),
                "exposure": str(asset.get("exposure") or "external"),
                "criticality": int(asset.get("criticality") or 3),
                "host": str(asset.get("host") or ""),
                "ip_cidr": str(asset.get("ip_cidr") or ""),
                "service_port": asset.get("service_port"),
                "score": 0,
                "reasons": [],
            }
            scores[key] = item
        item["score"] += int(points)
        if reason not in item["reasons"]:
            item["reasons"].append(reason)

    for host in host_candidates:
        for asset in host_map.get(host, []):
            crit = max(1, min(int(asset.get("criticality") or 3), 5))
            bump(asset, 55 + crit * 2, "host_match")

    if dst_ip is not None:
        for net, asset in nets:
            if dst_ip.version != net.version:
                continue
            if dst_ip in net:
                crit = max(1, min(int(asset.get("criticality") or 3), 5))
                bump(asset, 65 + crit * 2, "dst_ip_match")

    if dst_port is not None:
        for asset in port_map.get(dst_port, []):
            crit = max(1, min(int(asset.get("criticality") or 3), 5))
            bump(asset, 18 + crit, "service_port_match")

    if not scores:
        return None
    best = max(scores.values(), key=lambda item: (int(item.get("score") or 0), int(item.get("criticality") or 1)))
    if int(best.get("score") or 0) < 20:
        return None
    return best


def insert_security_events(workspace_slug: str, sensor_id: str, events: list[dict]) -> dict:
    accepted = 0
    skipped = 0
    threat_intel_hits = 0
    accepted_events: list[dict] = []
    ti_mode = str(os.getenv("IPS_THREAT_INTEL_INLINE_MODE", "local")).strip().lower()
    if ti_mode not in {"local", "live", "all", "off"}:
        ti_mode = "local"
    live_budget = max(0, min(int(os.getenv("IPS_THREAT_INTEL_INLINE_LIVE_MAX_IPS", "20") or 20), 2000))
    live_lookups = 0
    ti_cache: dict[str, list[dict]] = {}
    kev_matcher = _load_kev_matcher()
    delivery_matcher = _load_delivery_chain_matcher()
    asset_matcher = _load_workspace_asset_matcher(workspace_slug)
    kev_cves = kev_matcher.get("cves") if isinstance(kev_matcher, dict) else set()
    kev_domains = kev_matcher.get("domains") if isinstance(kev_matcher, dict) else set()
    kev_url_paths_by_host = kev_matcher.get("url_paths_by_host") if isinstance(kev_matcher, dict) else {}
    kev_sources = kev_matcher.get("sources") if isinstance(kev_matcher, dict) else []
    kev_cves = kev_cves if isinstance(kev_cves, set) else set()
    kev_domains = kev_domains if isinstance(kev_domains, set) else set()
    kev_url_paths_by_host = kev_url_paths_by_host if isinstance(kev_url_paths_by_host, dict) else {}
    kev_sources = kev_sources if isinstance(kev_sources, list) else []
    kev_has_cve = bool(kev_cves)
    kev_has_domain = bool(kev_domains)
    kev_has_url_path = bool(kev_url_paths_by_host)
    asset_host_map = asset_matcher.get("host_map") if isinstance(asset_matcher, dict) else {}
    asset_nets = asset_matcher.get("nets") if isinstance(asset_matcher, dict) else []
    asset_port_map = asset_matcher.get("port_map") if isinstance(asset_matcher, dict) else {}
    asset_matcher_has_any = bool(asset_host_map or asset_nets or asset_port_map)
    min_action_high = str(os.getenv("IPS_FORCE_MIN_ACTION_FOR_HIGH_RISK", "challenge")).strip().lower()
    if min_action_high not in {"challenge", "limit", "block"}:
        min_action_high = "challenge"
    prepared: list[dict] = []
    for raw_event in events:
        if not isinstance(raw_event, dict):
            continue
        event = raw_event
        action = str(event.get("action") or "alert").strip().lower()
        severity = str(event.get("severity") or "medium").strip().lower()
        src_ip = str(event.get("src_ip") or "").strip()
        geo_country, geo_asn, geo_source = _geoasn_enrich_ip(src_ip)
        if geo_country and not str(event.get("country_code") or "").strip():
            event["country_code"] = geo_country
        if geo_asn and not str(event.get("asn") or "").strip():
            event["asn"] = geo_asn
        event["geoasn_source"] = geo_source
        ti_matches: list[dict] = []
        if src_ip:
            cached = ti_cache.get(src_ip)
            if cached is not None:
                ti_matches = cached
            else:
                mode_for_ip = ti_mode
                if mode_for_ip in {"live", "all"}:
                    if live_lookups >= live_budget:
                        mode_for_ip = "local" if mode_for_ip == "all" else "off"
                    else:
                        live_lookups += 1
                ti_matches = lookup_threat_intel_ip_mode(src_ip, mode_for_ip)
                ti_cache[src_ip] = ti_matches
        ti_hit_counted = False
        if ti_matches:
            threat_intel_hits += 1
            ti_hit_counted = True
            event["threat_intel"] = ti_matches[:5]
            _append_event_tag(event, "threat_intel_match")
            sev = str(event.get("severity") or "medium").strip().lower()
            if _severity_rank(sev) < _severity_rank("high"):
                event["severity"] = "high"
            event["score"] = max(_to_float(event.get("score"), 0.0), 80.0)
        kev_reasons: list[dict] = []
        host_candidates: set[str] | None = None
        req_path: str | None = None
        if kev_has_cve:
            for cve in _extract_event_cves(event):
                if cve in kev_cves:
                    kev_reasons.append({"kind": "cve", "value": cve})
        if kev_has_domain or kev_has_url_path:
            host_candidates = _event_host_candidates(event)
            if kev_has_domain:
                for host in host_candidates:
                    if host in kev_domains:
                        kev_reasons.append({"kind": "domain", "value": host})
            if kev_has_url_path:
                req_path = _event_request_path(event)
                if req_path:
                    for host in host_candidates:
                        for prefix in kev_url_paths_by_host.get(host, []):
                            if req_path == prefix or req_path.startswith(prefix.rstrip("*")):
                                kev_reasons.append({"kind": "url_path", "value": f"{host}{prefix}"})
                                break
        if kev_reasons:
            event["kev_match"] = {
                "matched": True,
                "reasons": kev_reasons[:5],
                "sources": kev_sources[:5],
            }
            _append_event_tag(event, "kev_exploit_match")
            if not ti_hit_counted:
                threat_intel_hits += 1
                ti_hit_counted = True
            synthetic_ti = {
                "indicator_type": "kev",
                "indicator_value": kev_reasons[0]["value"],
                "source": "cisa_kev",
                "category": "known_exploited",
                "severity": "high",
                "confidence": 0.95,
            }
            existing_ti = event.get("threat_intel")
            if not isinstance(existing_ti, list):
                existing_ti = []
            existing_ti.append(synthetic_ti)
            event["threat_intel"] = existing_ti[:5]
            if _severity_rank(str(event.get("severity") or "medium")) < _severity_rank("high"):
                event["severity"] = "high"
            event["score"] = max(_to_float(event.get("score"), 0.0), 85.0)
        dst_ip_obj: ipaddress._BaseAddress | None = None
        dst_ip_raw = str(event.get("dst_ip") or "").strip()
        if dst_ip_raw:
            try:
                dst_ip_obj = ipaddress.ip_address(dst_ip_raw)
            except ValueError:
                dst_ip_obj = None
        dst_port_int: int | None = None
        try:
            if event.get("dst_port") is not None:
                dst_port_int = int(event.get("dst_port"))
        except (TypeError, ValueError):
            dst_port_int = None
        asset_match = None
        if asset_matcher_has_any:
            if host_candidates is None:
                host_candidates = _event_host_candidates(event)
            asset_match = _match_workspace_asset(
                event,
                asset_matcher,
                host_candidates=host_candidates,
                dst_ip=dst_ip_obj,
                dst_port=dst_port_int,
            )
        if asset_match:
            event["asset_match"] = asset_match
            _append_event_tag(event, "asset_target_match")
        if kev_reasons and asset_match:
            _append_event_tag(event, "kev_asset_relevant")
            exposure = str(asset_match.get("exposure") or "external").strip().lower()
            crit = max(1, min(int(asset_match.get("criticality") or 3), 5))
            floor = 88.0
            if exposure in {"external", "dmz"}:
                floor = 92.0
                if crit >= 4:
                    action = _enforce_min_action(str(event.get("action") or action), "block")
                else:
                    action = _enforce_min_action(str(event.get("action") or action), "limit")
                event["severity"] = "critical" if crit >= 3 else "high"
            else:
                action = _enforce_min_action(str(event.get("action") or action), "challenge")
                if _severity_rank(str(event.get("severity") or "medium")) < _severity_rank("high"):
                    event["severity"] = "high"
            event["action"] = action
            event["score"] = max(_to_float(event.get("score"), 0.0), floor + float(max(0, crit - 3)))
        delivery_fast_path_possible = False
        if host_candidates is not None and host_candidates:
            delivery_fast_path_possible = True
        if not delivery_fast_path_possible and str(event.get("url") or event.get("request_url") or "").strip():
            delivery_fast_path_possible = True
        if not delivery_fast_path_possible and str(event.get("uri") or event.get("path") or event.get("request_path") or "").strip():
            delivery_fast_path_possible = True
        if not delivery_fast_path_possible and str(event.get("referrer") or event.get("referer") or event.get("http_referrer") or "").strip():
            delivery_fast_path_possible = True
        if not delivery_fast_path_possible and str(event.get("sha256") or event.get("file_sha256") or "").strip():
            delivery_fast_path_possible = True
        if not delivery_fast_path_possible and str(event.get("md5") or event.get("file_md5") or "").strip():
            delivery_fast_path_possible = True
        if req_path is None and delivery_fast_path_possible:
            req_path = _event_request_path(event)
        if host_candidates is None and delivery_fast_path_possible:
            host_candidates = _event_host_candidates(event)
        delivery_match = (
            _detect_delivery_chain(
                event,
                delivery_matcher,
                host_candidates=host_candidates,
                req_path=req_path,
            )
            if delivery_fast_path_possible
            else None
        )
        if delivery_match:
            event["delivery_chain_match"] = delivery_match
            chain_type = str(delivery_match.get("chain_type") or "delivery_chain")
            _append_event_tag(event, "infostealer_delivery_chain")
            _append_event_tag(event, chain_type)
            match_score = int(delivery_match.get("score") or 0)
            if not ti_hit_counted:
                threat_intel_hits += 1
                ti_hit_counted = True
            existing_ti = event.get("threat_intel")
            if not isinstance(existing_ti, list):
                existing_ti = []
            existing_ti.append(
                {
                    "indicator_type": "delivery_chain",
                    "indicator_value": chain_type,
                    "source": "threat_delivery_intel",
                    "category": chain_type,
                    "severity": "high" if match_score < 90 else "critical",
                    "confidence": float(delivery_match.get("confidence") or 0.5),
                }
            )
            event["threat_intel"] = existing_ti[:5]
            if _severity_rank(str(event.get("severity") or "medium")) < _severity_rank("high"):
                event["severity"] = "high"
            score_floor = 82.0 if match_score < 90 else 90.0
            event["score"] = max(_to_float(event.get("score"), 0.0), score_floor)
            if match_score >= 90:
                event["action"] = _enforce_min_action(str(event.get("action") or action), "limit")
            elif match_score >= 75:
                event["action"] = _enforce_min_action(str(event.get("action") or action), "challenge")
        severity = str(event.get("severity") or severity).strip().lower()
        action = str(event.get("action") or action).strip().lower()
        # Defensive default: high-risk high-severity detections should not remain allow/observe.
        signature = str(event.get("signature") or event.get("rule") or "").strip()
        if severity in {"high", "critical"} and _is_high_risk_signature(signature):
            event["action"] = _enforce_min_action(str(event.get("action") or action), min_action_high)
        # Reduce false positives: low-severity events should not aggressively mitigate unless TI matched.
        if not ti_matches and severity == "low" and action in {"challenge", "limit", "block", "deny", "drop", "reject", "waf_block", "429", "403"}:
            event["action"] = "observe"
            event.setdefault("auto_adjust_reason", "low_severity_fp_guard")
        prepared.append(event)
    flow_result = _analyze_flow_signals(prepared)
    source_keys = sorted(
        {
            str(event.get("event_id") or event.get("source_event_key") or "").strip()
            for event in prepared
            if str(event.get("event_id") or event.get("source_event_key") or "").strip()
        }
    )
    existing_source_keys: set[str] = set()
    rows_to_insert: list[tuple] = []
    with connect() as conn:
        if source_keys:
            chunk_size = 400
            for i in range(0, len(source_keys), chunk_size):
                chunk = source_keys[i : i + chunk_size]
                placeholders = ",".join("?" for _ in chunk)
                rows = conn.execute(
                    f"""
                    SELECT source_event_key
                    FROM security_events
                    WHERE workspace_slug = ?
                      AND source_event_key IN ({placeholders})
                    """,
                    (workspace_slug, *chunk),
                ).fetchall()
                for row in rows:
                    key = str(row["source_event_key"] or "").strip()
                    if key:
                        existing_source_keys.add(key)
        for event in prepared:
            source_key = str(event.get("event_id") or event.get("source_event_key") or "").strip()
            if source_key and source_key in existing_source_keys:
                skipped += 1
                continue
            rows_to_insert.append(
                (
                    workspace_slug,
                    sensor_id,
                    source_key,
                    event.get("detected_at") or utcnow(),
                    str(event.get("src_ip") or "").strip().lower() or None,
                    event.get("dst_ip"),
                    event.get("src_port"),
                    event.get("dst_port"),
                    str(event.get("protocol") or "")[:20],
                    str(event.get("signature") or event.get("rule") or "")[:180],
                    str(event.get("severity") or "medium"),
                    event.get("score"),
                    str(event.get("action") or "alert"),
                    str(event.get("payload_excerpt") or event.get("excerpt") or "")[:3000],
                    json.dumps(event, ensure_ascii=False),
                )
            )
            if source_key:
                existing_source_keys.add(source_key)
            accepted += 1
            accepted_events.append(event)
        if rows_to_insert:
            conn.executemany(
                """
                INSERT INTO security_events (
                  workspace_slug, sensor_id, source_event_key, detected_at, src_ip, dst_ip, src_port, dst_port,
                  protocol, signature, severity, score, action, payload_excerpt, raw_event
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows_to_insert,
            )
    latency_rows = upsert_action_latency_metrics(workspace_slug, accepted_events)
    flow_rows = upsert_flow_findings(workspace_slug, accepted_events)
    incident_result = upsert_soc_incidents_from_events(workspace_slug, sensor_id, accepted_events)
    return {
        "accepted": accepted,
        "skipped": skipped,
        "threat_intel_hits": threat_intel_hits,
        "threat_intel_inline_mode": ti_mode,
        "threat_intel_live_lookups": live_lookups,
        "flow_anomaly_hits": int(flow_result.get("event_hits") or 0),
        "flow_signal_counts": flow_result.get("signal_counts") or {},
        "flow_rows": flow_rows,
        "latency_rows": latency_rows,
        "incident_result": incident_result,
    }


def upsert_metrics(aggregated: dict) -> None:
    with connect() as conn:
        _ensure_metric_rt_daily_table(conn)
        rt_buckets_touched: set[str] = set()
        for bucket, counts in aggregated["bucket_counts"].items():
            conn.execute(
                """
                INSERT INTO metric_buckets (bucket, total, s2xx, s3xx, s4xx, s5xx, blocked, blocked_429, blocked_503)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(bucket) DO UPDATE SET
                  total = total + excluded.total,
                  s2xx = s2xx + excluded.s2xx,
                  s3xx = s3xx + excluded.s3xx,
                  s4xx = s4xx + excluded.s4xx,
                  s5xx = s5xx + excluded.s5xx,
                  blocked = blocked + excluded.blocked,
                  blocked_429 = blocked_429 + excluded.blocked_429,
                  blocked_503 = blocked_503 + excluded.blocked_503
                """,
                (
                    bucket,
                    counts.get("total", 0),
                    counts.get("s2xx", 0),
                    counts.get("s3xx", 0),
                    counts.get("s4xx", 0),
                    counts.get("s5xx", 0),
                    counts.get("blocked", 0),
                    counts.get("blocked_429", 0),
                    counts.get("blocked_503", 0),
                ),
            )
        for kind_name, items in (
            ("bucket_ip", aggregated["bucket_ip"]),
            ("bucket_uri", aggregated["bucket_uri"]),
            ("bucket_ua", aggregated["bucket_ua"]),
            ("bucket_ua_class", aggregated.get("bucket_ua_class", {})),
            ("bucket_uri_all", aggregated["bucket_uri_all"]),
            ("bucket_ua_all", aggregated["bucket_ua_all"]),
            ("bucket_reason", aggregated["bucket_reason"]),
        ):
            for bucket, labels in items.items():
                for label, count in labels.items():
                    conn.execute(
                        """
                        INSERT INTO metric_bucket_items (bucket, kind, label, count)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(bucket, kind, label) DO UPDATE SET count = count + excluded.count
                        """,
                        (bucket, kind_name, label, count),
                    )
        for bucket, rt in aggregated["rt_summary"].items():
            rt_buckets_touched.add(str(bucket))
            row = conn.execute(
                "SELECT avg, p50, p95, p99, count FROM metric_bucket_rt WHERE bucket = ?",
                (bucket,),
            ).fetchone()
            if row:
                old_count = int(row["count"] or 0)
                new_count = int(rt["count"] or 0)
                total_count = old_count + new_count
                if total_count <= 0:
                    continue
                merged_avg = ((float(row["avg"]) * old_count) + (float(rt["avg"]) * new_count)) / total_count
                # Percentile merge is approximate; weighted average keeps values stable across incremental ingests.
                merged_p50 = ((float(row["p50"]) * old_count) + (float(rt["p50"]) * new_count)) / total_count
                merged_p95 = ((float(row["p95"]) * old_count) + (float(rt["p95"]) * new_count)) / total_count
                merged_p99 = ((float(row["p99"]) * old_count) + (float(rt["p99"]) * new_count)) / total_count
                conn.execute(
                    """
                    UPDATE metric_bucket_rt
                    SET avg = ?, p50 = ?, p95 = ?, p99 = ?, count = ?
                    WHERE bucket = ?
                    """,
                    (merged_avg, merged_p50, merged_p95, merged_p99, total_count, bucket),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO metric_bucket_rt (bucket, avg, p50, p95, p99, count)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (bucket, rt["avg"], rt["p50"], rt["p95"], rt["p99"], rt["count"]),
                )
        _rollup_metric_rt_daily(conn, rt_buckets_touched)
        _prune_metric_rt_retention(conn)


def dashboard_summary() -> dict:
    now_mono = time.monotonic()
    cached = _DASHBOARD_SUMMARY_CACHE.get("data")
    cached_at = float(_DASHBOARD_SUMMARY_CACHE.get("at") or 0.0)
    if _DASHBOARD_SUMMARY_CACHE_TTL_SEC > 0 and isinstance(cached, dict) and (now_mono - cached_at) < _DASHBOARD_SUMMARY_CACHE_TTL_SEC:
        return dict(cached)
    now = datetime.now(timezone.utc)
    now = now.replace(minute=(now.minute // 5) * 5, second=0, microsecond=0)
    short_retention_days = _retention_days("IPS_RT_SHORT_RETENTION_DAYS", 14, 1, 366)
    long_retention_days = _retention_days("IPS_RT_LONG_RETENTION_DAYS", 180, 7, 3650)
    buckets_24 = {(now - timedelta(minutes=i * 5)).strftime("%Y%m%d_%H%M") for i in range(288)}
    buckets_48 = {(now - timedelta(minutes=i * 5)).strftime("%Y%m%d_%H%M") for i in range(576)}
    long_start_day = (now - timedelta(days=long_retention_days - 1)).strftime("%Y%m%d")
    long_end_day = now.strftime("%Y%m%d")
    default_workspace = os.getenv("IPS_DEFAULT_WORKSPACE", "lab").strip() or "lab"
    kpi_setting = get_workspace_kpi_setting(default_workspace)
    should_exclude_test_ip = bool(kpi_setting.get("exclude_test_ip_on_kpi"))
    test_ips = _parse_test_ips(default_workspace)
    with connect() as conn:
        _ensure_metric_rt_daily_table(conn)
        if not buckets_48:
            return {}
        placeholders_24 = ",".join("?" for _ in buckets_24)
        placeholders_48 = ",".join("?" for _ in buckets_48)
        totals = conn.execute(
            f"""
            SELECT
              COALESCE(SUM(total), 0) AS total,
              COALESCE(SUM(blocked_429), 0) AS blocked_429,
              COALESCE(SUM(s2xx), 0) AS s2xx,
              COALESCE(SUM(s3xx), 0) AS s3xx,
              COALESCE(SUM(s4xx), 0) AS s4xx,
              COALESCE(SUM(s5xx), 0) AS s5xx
            FROM metric_buckets
            WHERE bucket IN ({placeholders_24})
            """,
            tuple(sorted(buckets_24)),
        ).fetchone()
        rt_rows = conn.execute(
            f"SELECT bucket, avg, p50, p95, p99, count FROM metric_bucket_rt WHERE bucket IN ({placeholders_24}) ORDER BY bucket ASC",
            tuple(sorted(buckets_24)),
        ).fetchall()
        rt_daily_rows = conn.execute(
            """
            SELECT day, avg, p50, p95, p99, count, source_buckets
            FROM metric_bucket_rt_daily
            WHERE day >= ? AND day <= ?
            ORDER BY day ASC
            """,
            (long_start_day, long_end_day),
        ).fetchall()
        block_rows = conn.execute(
            f"SELECT bucket, blocked_429 FROM metric_buckets WHERE bucket IN ({placeholders_24}) ORDER BY bucket ASC",
            tuple(sorted(buckets_24)),
        ).fetchall()
        excluded_test_ip_hits_24 = 0
        excluded_test_ip_hits_48 = 0
        if should_exclude_test_ip and test_ips:
            placeholders_ip = ",".join("?" for _ in test_ips)
            excluded_test_ip_hits_24 = int(
                conn.execute(
                    f"""
                    SELECT COALESCE(SUM(count), 0) AS c
                    FROM metric_bucket_items
                    WHERE kind = 'bucket_ip' AND bucket IN ({placeholders_24}) AND label IN ({placeholders_ip})
                    """,
                    tuple(sorted(buckets_24)) + tuple(test_ips),
                ).fetchone()["c"] or 0
            )
            excluded_test_ip_hits_48 = int(
                conn.execute(
                    f"""
                    SELECT COALESCE(SUM(count), 0) AS c
                    FROM metric_bucket_items
                    WHERE kind = 'bucket_ip' AND bucket IN ({placeholders_48}) AND label IN ({placeholders_ip})
                    """,
                    tuple(sorted(buckets_48)) + tuple(test_ips),
                ).fetchone()["c"] or 0
            )
            top_ips = conn.execute(
                f"""
                SELECT label, SUM(count) AS hits
                FROM metric_bucket_items
                WHERE kind = 'bucket_ip' AND bucket IN ({placeholders_48}) AND label NOT IN ({placeholders_ip})
                GROUP BY label
                ORDER BY hits DESC, label ASC
                LIMIT 10
                """,
                tuple(sorted(buckets_48)) + tuple(test_ips),
            ).fetchall()
        else:
            top_ips = conn.execute(
                f"""
                SELECT label, SUM(count) AS hits
                FROM metric_bucket_items
                WHERE kind = 'bucket_ip' AND bucket IN ({placeholders_48})
                GROUP BY label
                ORDER BY hits DESC, label ASC
                LIMIT 10
                """,
                tuple(sorted(buckets_48)),
            ).fetchall()
        top_uris = conn.execute(
            f"""
            SELECT label, SUM(count) AS hits
            FROM metric_bucket_items
            WHERE kind = 'bucket_uri_all' AND bucket IN ({placeholders_24})
            GROUP BY label
            ORDER BY hits DESC, label ASC
            LIMIT 10
            """,
            tuple(sorted(buckets_24)),
        ).fetchall()
        reasons = conn.execute(
            f"""
            SELECT label, SUM(count) AS hits
            FROM metric_bucket_items
            WHERE kind = 'bucket_reason' AND bucket IN ({placeholders_24})
            GROUP BY label
            ORDER BY hits DESC, label ASC
            LIMIT 10
            """,
            tuple(sorted(buckets_24)),
        ).fetchall()
        uas = conn.execute(
            f"""
            SELECT label, SUM(count) AS hits
            FROM metric_bucket_items
            WHERE kind = 'bucket_ua' AND bucket IN ({placeholders_24})
            GROUP BY label
            ORDER BY hits DESC, label ASC
            LIMIT 10
            """,
            tuple(sorted(buckets_24)),
        ).fetchall()
        ua_classes = conn.execute(
            f"""
            SELECT label, SUM(count) AS hits
            FROM metric_bucket_items
            WHERE kind = 'bucket_ua_class' AND bucket IN ({placeholders_24})
            GROUP BY label
            ORDER BY hits DESC, label ASC
            LIMIT 10
            """,
            tuple(sorted(buckets_24)),
        ).fetchall()
        active_channels = conn.execute(
            """
            SELECT channel_type, COUNT(*) AS cnt
            FROM notification_channels
            WHERE is_enabled = 1
            GROUP BY channel_type
            ORDER BY cnt DESC, channel_type ASC
            """
        ).fetchall()
        notify_recent = conn.execute(
            """
            SELECT workspace_slug, channel_type, event_type, status, detail, created_at
            FROM notification_events
            ORDER BY id DESC
            LIMIT 20
            """
        ).fetchall()
    total_requests = int(totals["total"])
    blocked_429 = int(totals["blocked_429"])
    if should_exclude_test_ip:
        blocked_429 = max(0, blocked_429 - int(excluded_test_ip_hits_24))
    avg_rt = 0.0
    if rt_rows:
        total_weight = sum(float(row["avg"]) * int(row["count"]) for row in rt_rows)
        total_count = sum(int(row["count"]) for row in rt_rows)
        avg_rt = (total_weight / total_count) if total_count else 0.0
    rule_rows = []
    for row in reasons:
        raw = row["label"]
        status_code, _, reason = raw.partition(":")
        if reason == "rate_limit":
            rule_rows.append({"rule": "RL-001 Rate Limit", "severity": "medium", "hits": int(row["hits"])})
        elif reason:
            rule_rows.append({"rule": f"GEN-{status_code} {reason}", "severity": "low", "hits": int(row["hits"])})
    waf = get_workspace_setting(default_workspace)
    action_latency = list_action_latency_summary(default_workspace, hours=24, limit=20)
    action_latency_alerts = list_action_latency_alerts(default_workspace, limit=30)
    chain = soc_chain_summary(default_workspace, hours=24)
    multi_sensor = soc_multi_sensor_summary(default_workspace, hours=24)
    incidents_recent = list_soc_incidents(default_workspace, limit=30)
    sensor_summary = list_sensors_summary(default_workspace)
    # policy_mode別の明示表示が必要なので生クエリで再集計
    stack_since_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    sensor_recent_cutoff = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    with connect() as conn:
        mode_rows = conn.execute(
            """
            SELECT policy_mode, COUNT(*) AS cnt
            FROM sensors
            WHERE workspace_slug = ? AND is_active = 1
            GROUP BY policy_mode
            ORDER BY cnt DESC, policy_mode ASC
            """,
            (default_workspace,),
        ).fetchall()
        sensor_type_health_rows = conn.execute(
            """
            SELECT
              sensor_type,
              COUNT(*) AS total,
              SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) AS active,
              SUM(CASE WHEN is_active = 1 AND COALESCE(last_seen_at, '') >= ? THEN 1 ELSE 0 END) AS healthy_recent
            FROM sensors
            WHERE workspace_slug = ?
            GROUP BY sensor_type
            ORDER BY sensor_type ASC
            """,
            (sensor_recent_cutoff, default_workspace),
        ).fetchall()
        xdr_link_recent = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM xdr_event_links
            WHERE workspace_slug = ? AND created_at >= ?
            """,
            (default_workspace, stack_since_24h),
        ).fetchone()
        xdr_link_pending = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM xdr_event_links
            WHERE workspace_slug = ? AND export_status NOT IN ('linked', 'exported')
            """,
            (default_workspace,),
        ).fetchone()
        remote_status_rows = conn.execute(
            """
            SELECT status, COUNT(*) AS c
            FROM remote_actions
            WHERE workspace_slug = ?
            GROUP BY status
            ORDER BY c DESC, status ASC
            """,
            (default_workspace,),
        ).fetchall()
        remote_recent_row = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM remote_actions
            WHERE workspace_slug = ? AND requested_at >= ?
            """,
            (default_workspace, stack_since_24h),
        ).fetchone()
    remote_status = {str(r["status"] or ""): int(r["c"] or 0) for r in remote_status_rows}
    sensor_type_health = [
        {
            "sensor_type": str(row["sensor_type"] or ""),
            "total": int(row["total"] or 0),
            "active": int(row["active"] or 0),
            "healthy_recent": int(row["healthy_recent"] or 0),
        }
        for row in sensor_type_health_rows
    ]
    policy_mode_counter = {str(r["policy_mode"]): int(r["cnt"] or 0) for r in mode_rows}
    if not policy_mode_counter:
        sensor_scoring_mode = "unknown"
    elif len(policy_mode_counter) == 1:
        sensor_scoring_mode = next(iter(policy_mode_counter.keys()))
    else:
        sensor_scoring_mode = "mixed(" + ", ".join(f"{k}:{v}" for k, v in sorted(policy_mode_counter.items())) + ")"
    edge_enforcement_mode = "off"
    if bool(waf.get("waf_enabled")):
        edge_enforcement_mode = "block" if str(waf.get("waf_mode", "block")) == "block" else "monitor"
    if not bool(waf.get("waf_enabled")):
        effective_response_mode = "observe"
    elif str(waf.get("waf_mode", "block")) == "block":
        effective_response_mode = "block_enforced"
    else:
        effective_response_mode = "observe_only"
    ti_active_count = count_threat_intel_entries(active_only=True)
    ti_recent_matches = list_recent_threat_intel_matches(default_workspace, limit=30)
    flow_summary = list_flow_findings_summary(default_workspace, hours=24, limit=20)
    ti_providers_live = []
    if str(os.getenv("ABUSEIPDB_API_KEY", "")).strip():
        ti_providers_live.append("abuseipdb")
    if str(os.getenv("GREYNOISE_API_KEY", "")).strip():
        ti_providers_live.append("greynoise")
    payload = {
        "generated_at": utcnow(),
        "kpis": {
            "total_requests_24h": total_requests,
            "blocked_429_24h": blocked_429,
            "block_rate_24h": round((blocked_429 / total_requests) * 100, 2) if total_requests else 0.0,
            "avg_response_time_ms_24h": round(avg_rt * 1000, 2),
            "excluded_test_ip_blocked_24h": int(excluded_test_ip_hits_24),
            "status_mix_24h": {
                "s2xx": int(totals["s2xx"]),
                "s3xx": int(totals["s3xx"]),
                "s4xx": int(totals["s4xx"]),
                "s5xx": int(totals["s5xx"]),
            },
        },
        "waf": {
            "workspace_slug": default_workspace,
            "enabled": bool(waf.get("waf_enabled")),
            "mode": waf.get("waf_mode", "block"),
        },
        "mode_summary": {
            "edge_enforcement_mode": edge_enforcement_mode,
            "sensor_scoring_mode": sensor_scoring_mode,
            "effective_response_mode": effective_response_mode,
        },
        "definitions": {
            "exclude_test_ip_on_kpi": should_exclude_test_ip,
            "test_ip_list": ", ".join(test_ips),
            "test_ip_rules": test_ips,
            "excluded_test_ip_blocked_24h": int(excluded_test_ip_hits_24),
            "excluded_test_ip_blocked_48h": int(excluded_test_ip_hits_48),
            "geoasn_enrichment": "private/local + IPS_GEOASN_RULES(static)",
            "geoasn_rule_count": _geoasn_rule_count(),
            "rt_5m_retention_days": short_retention_days,
            "long_term_rt_retention_days": long_retention_days,
            "long_term_rt_bucket": "5min sample -> daily avg(p95/p99/avg)",
        },
        "integration": {
            "enabled_channel_count": sum(int(row["cnt"]) for row in active_channels),
            "enabled_channels": [{"channel_type": row["channel_type"], "count": int(row["cnt"])} for row in active_channels],
            "stack": {
                "window_hours": 24,
                "sensor_recent_window_minutes": 10,
                "xdr_event_links_24h": int(xdr_link_recent["c"] if xdr_link_recent else 0),
                "xdr_link_pending": int(xdr_link_pending["c"] if xdr_link_pending else 0),
                "xdr_remote_actions_24h": int(remote_recent_row["c"] if remote_recent_row else 0),
                "xdr_remote_action_status": remote_status,
                "soc_open_incidents": int(chain.get("open_incidents") or 0),
                "soc_triaged_incidents_24h": int(chain.get("triaged_incidents") or 0),
                "sensor_type_health": sensor_type_health,
            },
        },
        "notification_recent": [dict(row) for row in notify_recent],
        "blocked_series_24h": [{"bucket": row["bucket"], "count": int(row["blocked_429"])} for row in block_rows],
        "response_time_series_24h": [
            {
                "bucket": row["bucket"],
                "avg_ms": round(float(row["avg"]) * 1000, 2),
                "p50_ms": round(float(row["p50"]) * 1000, 2),
                "p95_ms": round(float(row["p95"]) * 1000, 2),
                "p99_ms": round(float(row["p99"]) * 1000, 2),
            }
            for row in rt_rows
        ],
        "response_time_series_long_term": [
            {
                "day": row["day"],
                "avg_ms": round(float(row["avg"]) * 1000, 2),
                "p50_ms": round(float(row["p50"]) * 1000, 2),
                "p95_ms": round(float(row["p95"]) * 1000, 2),
                "p99_ms": round(float(row["p99"]) * 1000, 2),
                "samples": int(row["count"]),
                "source_buckets": int(row["source_buckets"]),
            }
            for row in rt_daily_rows
        ],
        "top_blocked_ips_48h": [{"label": row["label"], "count": int(row["hits"])} for row in top_ips],
        "high_activity_uris_24h": [{"label": row["label"], "count": int(row["hits"])} for row in top_uris],
        "block_reasons_24h": [{"label": row["label"], "count": int(row["hits"])} for row in reasons],
        "monitored_uas_24h": [{"label": row["label"], "count": int(row["hits"])} for row in uas],
        "ua_classification_24h": [{"label": row["label"], "count": int(row["hits"])} for row in ua_classes],
        "detected_rules_24h": rule_rows,
        "action_latency_24h": action_latency,
        "action_latency_alerts_recent": action_latency_alerts,
        "soc_chain_24h": chain,
        "soc_multi_sensor_24h": multi_sensor,
        "soc_incidents_recent": incidents_recent,
        "sensor_summary": sensor_summary,
        "threat_intel": {
            "active_indicators": ti_active_count,
            "live_enabled": _ti_live_enabled(),
            "live_providers": ti_providers_live,
            "recent_matches": ti_recent_matches,
        },
        "flow_analysis_24h": flow_summary,
    }
    _DASHBOARD_SUMMARY_CACHE["at"] = now_mono
    _DASHBOARD_SUMMARY_CACHE["data"] = dict(payload)
    return payload
