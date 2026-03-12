#!/usr/bin/env python3
from __future__ import annotations

import json
import random
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dashboard.security import db_path
from dashboard.storage import init_db, insert_security_events, list_security_events_for_eval
from scripts.public_e2e_demo import evaluate


def _build_events(seed: int = 20260310) -> list[dict]:
    rng = random.Random(seed)
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    scenarios = [
        {"name": "credential_stuffing_2026", "kind": "attack", "count": 180, "signature": "AUTH-STUFF-2026", "uri": "/account/login/"},
        {"name": "token_replay_hijack_2026", "kind": "attack", "count": 120, "signature": "SESSION-REPLAY-2026", "uri": "/api/v1/session/"},
        {"name": "api_bola_enumeration_2026", "kind": "attack", "count": 140, "signature": "API-BOLA-2026", "uri": "/api/v1/users/"},
        {"name": "graphql_introspection_abuse_2026", "kind": "attack", "count": 120, "signature": "API-GRAPHQL-ABUSE-2026", "uri": "/graphql"},
        {"name": "ssrf_metadata_probe_2026", "kind": "attack", "count": 110, "signature": "SSRF-METADATA-2026", "uri": "/proxy/fetch"},
        {"name": "path_traversal_probe_2026", "kind": "attack", "count": 120, "signature": "PATH-TRAVERSAL-2026", "uri": "/download"},
        {"name": "rce_cve_probe_2026", "kind": "attack", "count": 120, "signature": "CVE-RCE-PROBE-2026", "uri": "/cgi-bin/"},
        {"name": "headless_scraper_ai_2026", "kind": "attack", "count": 160, "signature": "SCRAPE-AI-2026", "uri": "/trpg/create/"},
        {"name": "http_ddos_burst_2026", "kind": "attack", "count": 140, "signature": "HTTP-DDOS-2026", "uri": "/"},
        {"name": "normal_spa_browse", "kind": "benign", "count": 300, "signature": "NORMAL-SPA", "uri": "/"},
        {"name": "search_crawler_verified", "kind": "benign", "count": 140, "signature": "CRAWLER-VERIFIED", "uri": "/trpg/"},
        {"name": "mobile_api_fluctuation", "kind": "benign", "count": 160, "signature": "MOBILE-API-NORMAL", "uri": "/api/v1/items/"},
        {"name": "internal_observability", "kind": "noisy_benign", "count": 120, "signature": "INTERNAL-OBS", "uri": "/secops/api/heartbeat"},
    ]
    events: list[dict] = []
    seq = 1
    for sc in scenarios:
        for _ in range(int(sc["count"])):
            kind = sc["kind"]
            if kind == "attack":
                x = rng.random()
                if x < 0.45:
                    action = "challenge"
                elif x < 0.80:
                    action = "limit"
                elif x < 0.98:
                    action = "block"
                else:
                    action = "observe"
                severity = "critical" if rng.random() < 0.35 else "high"
                gt = "attack"
                src_ip = f"198.51.100.{rng.randint(1, 254)}"
                ua = rng.choice(
                    [
                        "python-requests/2.31.0",
                        "Scrapy/2.11.2 (+https://scrapy.org)",
                        "HeadlessChrome/124.0.0.0",
                        "curl/8.6.0",
                    ]
                )
            elif kind == "noisy_benign":
                action = "observe" if rng.random() < 0.97 else "limit"
                severity = "medium"
                gt = "noisy_benign"
                src_ip = f"10.0.0.{rng.randint(1, 200)}"
                ua = "secops-internal-agent/1.7"
            else:
                y = rng.random()
                if y < 0.78:
                    action = "allow"
                elif y < 0.995:
                    action = "observe"
                else:
                    action = "challenge"
                severity = "low"
                gt = "benign"
                src_ip = f"203.0.113.{rng.randint(1, 254)}"
                ua = rng.choice(
                    [
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36",
                        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
                        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                    ]
                )
            detected_at = (now - timedelta(seconds=rng.randint(0, 24 * 3600 - 1))).isoformat()
            events.append(
                {
                    "event_id": f"latest-bench-{seq:05d}",
                    "detected_at": detected_at,
                    "src_ip": src_ip,
                    "dst_ip": "192.0.2.10",
                    "src_port": rng.randint(1024, 65535),
                    "dst_port": 443,
                    "protocol": "tcp",
                    "signature": sc["signature"],
                    "severity": severity,
                    "score": 85 if gt == "attack" else 20,
                    "action": action,
                    "payload_excerpt": f"{sc['name']} synthetic payload",
                    "scenario": sc["name"],
                    "ground_truth": gt,
                    "uri": sc["uri"],
                    "ua": ua,
                    "processing_ms": round(rng.uniform(10, 130), 3),
                }
            )
            seq += 1
    rng.shuffle(events)
    return events


def _clear_workspace(workspace_slug: str) -> None:
    conn = sqlite3.connect(db_path())
    try:
        conn.execute("DELETE FROM security_events WHERE workspace_slug = ?", (workspace_slug,))
        conn.execute("DELETE FROM soc_incidents WHERE workspace_slug = ?", (workspace_slug,))
        conn.execute("DELETE FROM soc_triage_logs WHERE workspace_slug = ?", (workspace_slug,))
        conn.commit()
    finally:
        conn.close()


def main() -> None:
    workspace_slug = "latest_attack_demo"
    sensor_id = "latest-attack-sensor-01"
    out_path = Path("docs/latest_attack_benchmark.json")
    init_db()
    _clear_workspace(workspace_slug)
    events = _build_events(seed=20260310)
    ingest_result = insert_security_events(workspace_slug, sensor_id, events)
    rows = list_security_events_for_eval(workspace_slug=workspace_slug, since_iso=None, limit=50000)
    effective_events = []
    for row in rows:
        raw = row.get("raw_event") if isinstance(row.get("raw_event"), dict) else {}
        if isinstance(raw, dict):
            effective_events.append(raw)
    metrics = evaluate(effective_events)
    payload = {
        "workspace_slug": workspace_slug,
        "sensor_id": sensor_id,
        "scenario_note": "2025-2026の攻撃トレンドを模した公開可能な合成データ",
        "ingest_result": ingest_result,
        "metrics": metrics,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    print(f"\nwritten: {out_path}")


if __name__ == "__main__":
    main()
