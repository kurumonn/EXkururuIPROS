"""CVSS/EPSS vulnerability scoring and CISA KEV sync for EXkururuIPROS."""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from .storage import connect, utcnow

_EPSS_API_URL = "https://api.first.org/data/v1/epss"
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

_CVSS_SEVERITY_THRESHOLDS = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
]

# (cve_id → {score, percentile, fetched_at}), TTL 6 hours
_EPSS_CACHE: dict[str, tuple[float, dict]] = {}
_EPSS_CACHE_TTL = 6 * 3600

# Nginx CVE patch versions {cve_id: (min_mainline, min_stable)}
_NGINX_PATCHED: dict[str, tuple[tuple[int, ...], tuple[int, ...]]] = {
    "CVE-2026-42945": ((1, 31, 0), (1, 30, 1)),
}


# ──────────────────────────────────────────────────────────────────────────────
# Schema (appended to storage.SCHEMA_SQL via storage.py additions)
# ──────────────────────────────────────────────────────────────────────────────

VULN_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS vulnerability_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL DEFAULT 'default',
  cve_id TEXT NOT NULL,
  title TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL DEFAULT '',
  cvss_score REAL,
  cvss_vector TEXT NOT NULL DEFAULT '',
  cvss_severity TEXT NOT NULL DEFAULT 'unknown',
  epss_score REAL,
  epss_percentile REAL,
  kev_flag INTEGER NOT NULL DEFAULT 0,
  kev_date_added TEXT,
  due_date TEXT,
  affected_products TEXT NOT NULL DEFAULT '[]',
  server_status TEXT NOT NULL DEFAULT 'unknown',
  known_ransomware TEXT NOT NULL DEFAULT '',
  published_at TEXT,
  source TEXT NOT NULL DEFAULT 'manual',
  last_seen_at TEXT NOT NULL,
  raw_json TEXT NOT NULL DEFAULT '{}'
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_vuln_records_ws_cve ON vulnerability_records (workspace_slug, cve_id);
CREATE INDEX IF NOT EXISTS idx_vuln_records_severity ON vulnerability_records (workspace_slug, cvss_severity, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_vuln_records_kev ON vulnerability_records (workspace_slug, kev_flag, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_vuln_records_epss ON vulnerability_records (workspace_slug, epss_percentile DESC);

CREATE TABLE IF NOT EXISTS vulnerability_findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL DEFAULT 'default',
  cve_id TEXT NOT NULL,
  asset_host TEXT NOT NULL DEFAULT '',
  asset_version TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'unknown',
  note TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_vuln_findings_ws_cve_host ON vulnerability_findings (workspace_slug, cve_id, asset_host);
CREATE INDEX IF NOT EXISTS idx_vuln_findings_lookup ON vulnerability_findings (workspace_slug, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS vuln_scan_jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workspace_slug TEXT NOT NULL DEFAULT 'default',
  source TEXT NOT NULL DEFAULT 'cisa_kev',
  status TEXT NOT NULL DEFAULT 'pending',
  trigger TEXT NOT NULL DEFAULT 'scheduled',
  found_count INTEGER NOT NULL DEFAULT 0,
  accepted_count INTEGER NOT NULL DEFAULT 0,
  error_message TEXT NOT NULL DEFAULT '',
  checksum_sha256 TEXT NOT NULL DEFAULT '',
  started_at TEXT NOT NULL,
  finished_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vuln_scan_jobs_recent ON vuln_scan_jobs (workspace_slug, created_at DESC);
"""


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "unknown"
    for threshold, label in _CVSS_SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "none"


def _parse_version(ver_str: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", str(ver_str or ""))
    return tuple(int(p) for p in parts[:4])


def _http_get_json(url: str, timeout: int = 10) -> dict | list:
    req = urllib.request.Request(url, headers={"User-Agent": "EXkururuIPROS/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ──────────────────────────────────────────────────────────────────────────────
# CVE server classification
# ──────────────────────────────────────────────────────────────────────────────

def classify_cve_for_server(
    cve_id: str,
    component_versions: dict[str, str],
) -> dict[str, Any]:
    """
    Returns server_vulnerable, severity label, and display context.
    component_versions: {"nginx": "1.31.0", "postgresql": "16.3", ...}
    """
    cve_upper = str(cve_id or "").upper().strip()

    if cve_upper in _NGINX_PATCHED:
        nginx_ver_str = str(component_versions.get("nginx", "") or "")
        nginx_ver = _parse_version(nginx_ver_str)
        mainline_min, stable_min = _NGINX_PATCHED[cve_upper]

        if nginx_ver >= mainline_min or nginx_ver >= stable_min:
            return {
                "server_vulnerable": False,
                "severity": "info",
                "label": "patched_probe",
                "message": f"Attack probe detected. Server is not vulnerable (nginx {nginx_ver_str}).",
                "action": "block_source",
            }
        return {
            "server_vulnerable": True,
            "severity": "high",
            "label": "vulnerable_probe",
            "message": f"Server may be vulnerable (nginx {nginx_ver_str}). Patch immediately.",
            "action": "patch_urgent",
        }

    # Generic fallback: treat as observed probe, no local version data
    return {
        "server_vulnerable": None,
        "severity": "medium",
        "label": "unknown_probe",
        "message": "Attack probe observed. Server vulnerability status unknown.",
        "action": "investigate",
    }


# ──────────────────────────────────────────────────────────────────────────────
# EPSS sync
# ──────────────────────────────────────────────────────────────────────────────

def fetch_epss_scores(cve_ids: list[str]) -> dict[str, dict]:
    """Fetch EPSS scores from FIRST API. Returns {cve_id: {score, percentile}}."""
    now = time.time()
    result: dict[str, dict] = {}
    to_fetch: list[str] = []

    for cve_id in cve_ids:
        cve_upper = cve_id.upper()
        if cve_upper in _EPSS_CACHE:
            ts, data = _EPSS_CACHE[cve_upper]
            if now - ts < _EPSS_CACHE_TTL:
                result[cve_upper] = data
                continue
        to_fetch.append(cve_upper)

    if not to_fetch:
        return result

    # FIRST EPSS API accepts up to 100 CVEs per request
    chunk_size = 100
    for i in range(0, len(to_fetch), chunk_size):
        chunk = to_fetch[i : i + chunk_size]
        cve_param = ",".join(chunk)
        url = f"{_EPSS_API_URL}?cve={urllib.parse.quote(cve_param)}"
        try:
            import urllib.parse as _up
            url = f"{_EPSS_API_URL}?cve={_up.quote(cve_param)}"
            data = _http_get_json(url)
            for item in data.get("data", []):
                cve = str(item.get("cve", "")).upper()
                entry = {
                    "score": float(item.get("epss", 0) or 0),
                    "percentile": float(item.get("percentile", 0) or 0),
                }
                _EPSS_CACHE[cve] = (now, entry)
                result[cve] = entry
        except Exception:
            pass

    return result


# ──────────────────────────────────────────────────────────────────────────────
# CISA KEV sync
# ──────────────────────────────────────────────────────────────────────────────

def sync_cisa_kev(workspace_slug: str = "default") -> dict:
    """Sync CISA Known Exploited Vulnerabilities catalog."""
    started_at = utcnow()
    job_id: int | None = None

    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO vuln_scan_jobs (workspace_slug, source, status, trigger, started_at, created_at) VALUES (?,?,?,?,?,?)",
            (workspace_slug, "cisa_kev", "running", "scheduled", started_at, started_at),
        )
        job_id = cur.lastrowid

    try:
        req = urllib.request.Request(_CISA_KEV_URL, headers={"User-Agent": "EXkururuIPROS/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw_bytes = resp.read()
        payload = json.loads(raw_bytes.decode("utf-8"))
        checksum = _sha256_bytes(raw_bytes)

        vulns: list[dict] = payload.get("vulnerabilities", [])
        accepted = 0
        cve_ids_to_enrich: list[str] = []

        with connect() as conn:
            for v in vulns:
                cve_id = str(v.get("cveID", "") or "").upper().strip()
                if not _CVE_RE.match(cve_id):
                    continue
                title = str(v.get("vulnerabilityName", "") or "")[:255]
                summary = str(v.get("shortDescription", "") or "")
                due_date = str(v.get("dueDate", "") or "") or None
                date_added = str(v.get("dateAdded", "") or "") or None
                ransomware = str(v.get("knownRansomwareCampaignUse", "") or "")
                product_str = f"{v.get('vendorProject','') or ''} {v.get('product','') or ''}".strip()
                affected = json.dumps([product_str] if product_str else [])

                conn.execute(
                    """
                    INSERT INTO vulnerability_records
                      (workspace_slug, cve_id, title, summary, kev_flag, kev_date_added,
                       due_date, known_ransomware, affected_products, source, last_seen_at, raw_json)
                    VALUES (?,?,?,?,1,?,?,?,?,'cisa_kev',?,?)
                    ON CONFLICT(workspace_slug, cve_id) DO UPDATE SET
                      title=excluded.title,
                      summary=excluded.summary,
                      kev_flag=1,
                      kev_date_added=excluded.kev_date_added,
                      due_date=excluded.due_date,
                      known_ransomware=excluded.known_ransomware,
                      affected_products=excluded.affected_products,
                      last_seen_at=excluded.last_seen_at,
                      raw_json=excluded.raw_json
                    """,
                    (workspace_slug, cve_id, title, summary, date_added, due_date,
                     ransomware, affected, utcnow(), json.dumps(v)),
                )
                accepted += 1
                cve_ids_to_enrich.append(cve_id)

        # Enrich with EPSS scores
        if cve_ids_to_enrich:
            epss_map = fetch_epss_scores(cve_ids_to_enrich)
            if epss_map:
                with connect() as conn:
                    for cve_id, epss in epss_map.items():
                        conn.execute(
                            """
                            UPDATE vulnerability_records
                            SET epss_score=?, epss_percentile=?
                            WHERE workspace_slug=? AND cve_id=?
                            """,
                            (epss["score"], epss["percentile"], workspace_slug, cve_id),
                        )

        finished_at = utcnow()
        with connect() as conn:
            conn.execute(
                """UPDATE vuln_scan_jobs SET status='succeeded', found_count=?, accepted_count=?,
                   checksum_sha256=?, finished_at=? WHERE id=?""",
                (len(vulns), accepted, checksum, finished_at, job_id),
            )

        return {"status": "ok", "found": len(vulns), "accepted": accepted}

    except Exception as exc:
        with connect() as conn:
            conn.execute(
                "UPDATE vuln_scan_jobs SET status='failed', error_message=?, finished_at=? WHERE id=?",
                (str(exc)[:500], utcnow(), job_id),
            )
        return {"status": "error", "error": str(exc)}


# ──────────────────────────────────────────────────────────────────────────────
# Upsert / list
# ──────────────────────────────────────────────────────────────────────────────

def upsert_vulnerability_record(
    workspace_slug: str,
    cve_id: str,
    *,
    cvss_score: float | None = None,
    cvss_vector: str = "",
    title: str = "",
    summary: str = "",
    server_status: str = "unknown",
    source: str = "manual",
    raw_json: dict | None = None,
) -> int:
    cve_upper = cve_id.upper().strip()
    severity = cvss_to_severity(cvss_score)
    now = utcnow()
    with connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO vulnerability_records
              (workspace_slug, cve_id, title, summary, cvss_score, cvss_vector,
               cvss_severity, server_status, source, last_seen_at, raw_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(workspace_slug, cve_id) DO UPDATE SET
              title=CASE WHEN excluded.title!='' THEN excluded.title ELSE title END,
              summary=CASE WHEN excluded.summary!='' THEN excluded.summary ELSE summary END,
              cvss_score=COALESCE(excluded.cvss_score, cvss_score),
              cvss_vector=CASE WHEN excluded.cvss_vector!='' THEN excluded.cvss_vector ELSE cvss_vector END,
              cvss_severity=excluded.cvss_severity,
              server_status=excluded.server_status,
              last_seen_at=excluded.last_seen_at
            """,
            (
                workspace_slug, cve_upper, title, summary, cvss_score, cvss_vector,
                severity, server_status, source, now,
                json.dumps(raw_json or {}),
            ),
        )
        return cur.lastrowid or 0


def upsert_vulnerability_finding(
    workspace_slug: str,
    cve_id: str,
    asset_host: str,
    status: str = "unknown",
    note: str = "",
    asset_version: str = "",
) -> None:
    cve_upper = cve_id.upper().strip()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO vulnerability_findings
              (workspace_slug, cve_id, asset_host, asset_version, status, note, updated_at)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(workspace_slug, cve_id, asset_host) DO UPDATE SET
              asset_version=CASE WHEN excluded.asset_version!='' THEN excluded.asset_version ELSE asset_version END,
              status=excluded.status,
              note=excluded.note,
              updated_at=excluded.updated_at
            """,
            (workspace_slug, cve_upper, asset_host, asset_version, status, note, utcnow()),
        )


def list_vulnerability_records(
    workspace_slug: str,
    *,
    severity: str = "",
    kev_only: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    wheres = ["workspace_slug=?"]
    params: list[Any] = [workspace_slug]
    if severity:
        wheres.append("cvss_severity=?")
        params.append(severity)
    if kev_only:
        wheres.append("kev_flag=1")
    sql = f"""
        SELECT id, cve_id, title, cvss_score, cvss_vector, cvss_severity,
               epss_score, epss_percentile, kev_flag, kev_date_added, due_date,
               server_status, known_ransomware, affected_products, source, last_seen_at
        FROM vulnerability_records
        WHERE {' AND '.join(wheres)}
        ORDER BY
          CASE cvss_severity
            WHEN 'critical' THEN 0
            WHEN 'high' THEN 1
            WHEN 'medium' THEN 2
            WHEN 'low' THEN 3
            ELSE 4
          END,
          epss_percentile DESC NULLS LAST,
          last_seen_at DESC
        LIMIT ? OFFSET ?
    """
    params += [limit, offset]
    with connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def get_vuln_summary(workspace_slug: str) -> dict:
    with connect() as conn:
        row = conn.execute(
            """
            SELECT
              COUNT(*) AS total,
              SUM(CASE WHEN cvss_severity='critical' THEN 1 ELSE 0 END) AS critical,
              SUM(CASE WHEN cvss_severity='high' THEN 1 ELSE 0 END) AS high,
              SUM(CASE WHEN cvss_severity='medium' THEN 1 ELSE 0 END) AS medium,
              SUM(CASE WHEN cvss_severity='low' THEN 1 ELSE 0 END) AS low,
              SUM(kev_flag) AS kev_count
            FROM vulnerability_records
            WHERE workspace_slug=?
            """,
            (workspace_slug,),
        ).fetchone()
        row_dict = dict(row) if row else {}

        last_job = conn.execute(
            """
            SELECT status, accepted_count, finished_at
            FROM vuln_scan_jobs
            WHERE workspace_slug=?
            ORDER BY created_at DESC LIMIT 1
            """,
            (workspace_slug,),
        ).fetchone()

    return {
        "total": row_dict.get("total", 0),
        "critical": row_dict.get("critical", 0),
        "high": row_dict.get("high", 0),
        "medium": row_dict.get("medium", 0),
        "low": row_dict.get("low", 0),
        "kev_count": row_dict.get("kev_count", 0),
        "last_sync": dict(last_job) if last_job else None,
    }
