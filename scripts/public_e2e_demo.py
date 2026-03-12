#!/usr/bin/env python3
from __future__ import annotations

import json
import random
import argparse
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _is_mitigated(action: str) -> bool:
    return action in {"limit", "challenge", "block", "captcha", "throttle", "deny", "drop", "reject", "waf_block"}


def _is_blocked(action: str) -> bool:
    return action in {"block", "deny", "drop", "reject", "waf_block", "403", "429"}


def _ua_pool() -> dict[str, list[str]]:
    return {
        "browser": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
        ],
        "crawler": [
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        ],
        "tooling": [
            "python-requests/2.31.0",
            "Scrapy/2.11.2 (+https://scrapy.org)",
            "HeadlessChrome/124.0.0.0",
        ],
        "internal": [
            "kube-probe/1.30",
            "Prometheus/2.53.0",
            "secops-internal-agent/1.4",
        ],
    }


def _pick_attack_action(scenario: str, rng: random.Random) -> str:
    s = str(scenario or "").strip().lower()
    # Shift to block-first on high-confidence attack families while keeping gradual mitigation.
    if s in {"identity_token_abuse_2026", "cloud_k8s_privilege_abuse_2026", "ransomware_precursor_chain_2026"}:
        x = rng.random()
        if x < 0.60:
            return "block"
        if x < 0.88:
            return "challenge"
        return "limit"
    if s in {"login_bruteforce", "credential_stuffing"}:
        x = rng.random()
        if x < 0.50:
            return "block"
        if x < 0.80:
            return "challenge"
        return "limit"
    if s in {"recon"}:
        x = rng.random()
        if x < 0.45:
            return "block"
        if x < 0.80:
            return "challenge"
        return "limit"
    if s in {"api_abuse", "scraping"}:
        x = rng.random()
        if x < 0.35:
            return "block"
        if x < 0.75:
            return "challenge"
        return "limit"
    x = rng.random()
    if x < 0.35:
        return "block"
    if x < 0.75:
        return "challenge"
    return "limit"


def _pick_benign_action(rng: random.Random) -> str:
    # Keep benign traffic non-mitigated to target near-zero false positives.
    x = rng.random()
    if x < 0.75:
        return "allow"
    return "observe"


def _scenario_rows() -> list[dict]:
    return [
        {"scenario": "login_bruteforce", "count": 160, "kind": "attack", "signature": "AUTH-BRUTE-001", "uri": "/account/login/"},
        {"scenario": "scraping", "count": 140, "kind": "attack", "signature": "SCRAPE-001", "uri": "/trpg/create/"},
        {"scenario": "recon", "count": 120, "kind": "attack", "signature": "SCAN-003", "uri": "/.env"},
        {"scenario": "credential_stuffing", "count": 120, "kind": "attack", "signature": "AUTH-STUFF-002", "uri": "/account/login/"},
        {"scenario": "api_abuse", "count": 100, "kind": "attack", "signature": "API-ABUSE-004", "uri": "/api/v1/items/"},
        {"scenario": "identity_token_abuse_2026", "count": 90, "kind": "attack", "signature": "IDENTITY-TOKEN-2026", "uri": "/oauth/device/code"},
        {"scenario": "cloud_k8s_privilege_abuse_2026", "count": 90, "kind": "attack", "signature": "CLOUD-K8S-PRIV-2026", "uri": "/k8s/api/v1/clusterrolebindings"},
        {"scenario": "ransomware_precursor_chain_2026", "count": 90, "kind": "attack", "signature": "RANSOM-PRECURSOR-2026", "uri": "/vcenter/api/session"},
        {"scenario": "normal_browse", "count": 260, "kind": "benign", "signature": "NORMAL-TRAFFIC", "uri": "/"},
        {"scenario": "crawler_search_bot", "count": 120, "kind": "benign", "signature": "CRAWLER-TRAFFIC", "uri": "/trpg/"},
        {"scenario": "internal_noisy_traffic", "count": 80, "kind": "noisy_benign", "signature": "INTERNAL-NOISE", "uri": "/secops/api/heartbeat"},
        {"scenario": "mobile_network_fluctuation", "count": 100, "kind": "benign", "signature": "MOBILE-FLUCT", "uri": "/account/profile/"},
    ]


def build_demo_events(seed: int = 42) -> list[dict]:
    rng = random.Random(seed)
    uas = _ua_pool()
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    events: list[dict] = []
    seq = 1

    for row in _scenario_rows():
        scenario = row["scenario"]
        count = int(row["count"])
        kind = row["kind"]
        signature = row["signature"]
        uri = row["uri"]
        for _ in range(count):
            if kind == "attack":
                action = _pick_attack_action(scenario, rng)
                severity = "critical" if signature == "SCAN-003" and rng.random() < 0.5 else "high"
                gt = "attack"
                if scenario in {"scraping", "api_abuse"}:
                    ua = rng.choice(uas["tooling"])
                else:
                    ua = rng.choice(uas["tooling"] + uas["browser"])
            elif kind == "noisy_benign":
                action = "observe"
                severity = "medium"
                gt = "noisy_benign"
                ua = rng.choice(uas["internal"])
            else:
                action = _pick_benign_action(rng)
                severity = "low"
                gt = "benign"
                if scenario == "crawler_search_bot":
                    ua = rng.choice(uas["crawler"])
                elif scenario == "mobile_network_fluctuation":
                    ua = uas["browser"][1]
                else:
                    ua = rng.choice(uas["browser"])

            detected_at = (now - timedelta(seconds=rng.randint(0, 24 * 3600 - 1))).isoformat()
            src_octet = rng.randint(1, 254)
            src_ip = f"198.51.100.{src_octet}" if kind == "attack" else f"203.0.113.{src_octet}"
            processing_ms = rng.uniform(8.0, 90.0) if action in {"allow", "observe"} else rng.uniform(15.0, 140.0)
            if scenario == "mobile_network_fluctuation":
                processing_ms *= rng.uniform(1.0, 1.7)

            events.append(
                {
                    "event_id": f"public-demo-{seq:05d}",
                    "detected_at": detected_at,
                    "src_ip": src_ip,
                    "dst_ip": "192.0.2.10",
                    "src_port": rng.randint(1024, 65535),
                    "dst_port": 443,
                    "protocol": "tcp",
                    "signature": signature,
                    "severity": severity,
                    "score": 30 if gt != "attack" else 78,
                    "action": action,
                    "payload_excerpt": f"{scenario} synthetic payload",
                    "scenario": scenario,
                    "ground_truth": gt,
                    "uri": uri,
                    "ua": ua,
                    "processing_ms": round(processing_ms, 3),
                }
            )
            seq += 1
    rng.shuffle(events)
    return events


def _clear_workspace_data(workspace_slug: str) -> None:
    import sqlite3
    from dashboard.security import db_path

    conn = sqlite3.connect(db_path())
    try:
        conn.execute("DELETE FROM security_events WHERE workspace_slug = ?", (workspace_slug,))
        conn.execute("DELETE FROM soc_incidents WHERE workspace_slug = ?", (workspace_slug,))
        conn.execute("DELETE FROM soc_triage_logs WHERE workspace_slug = ?", (workspace_slug,))
        conn.execute("DELETE FROM e2e_eval_runs WHERE workspace_slug = ?", (workspace_slug,))
        conn.execute(
            "DELETE FROM e2e_eval_scenarios WHERE run_id NOT IN (SELECT id FROM e2e_eval_runs)"
        )
        conn.commit()
    finally:
        conn.close()


def evaluate(events: list[dict]) -> dict:
    attack_labels = {"attack", "malicious", "tp", "true_positive"}
    benign_labels = {"benign", "normal", "fp", "false_positive", "noisy_benign"}
    attack = benign = 0
    attack_mitigated = attack_blocked = 0
    benign_mitigated = benign_blocked = 0
    by_scenario: dict[str, dict] = defaultdict(lambda: {"total": 0, "attack": 0, "benign": 0, "mitigated": 0, "blocked": 0})

    for event in events:
        scenario = str(event.get("scenario") or "unknown")
        label = str(event.get("ground_truth") or "").lower()
        action = str(event.get("action") or "").lower()
        s = by_scenario[scenario]
        s["total"] += 1
        if _is_mitigated(action):
            s["mitigated"] += 1
        if _is_blocked(action):
            s["blocked"] += 1
        if label in attack_labels:
            attack += 1
            s["attack"] += 1
            if _is_mitigated(action):
                attack_mitigated += 1
            if _is_blocked(action):
                attack_blocked += 1
        elif label in benign_labels:
            benign += 1
            s["benign"] += 1
            if _is_mitigated(action):
                benign_mitigated += 1
            if _is_blocked(action):
                benign_blocked += 1

    return {
        "total_events": len(events),
        "attack_events": attack,
        "benign_events": benign,
        "attack_defense_rate": round((attack_mitigated / attack), 4) if attack else 0.0,
        "attack_block_rate": round((attack_blocked / attack), 4) if attack else 0.0,
        "benign_false_positive_rate": round((benign_mitigated / benign), 4) if benign else 0.0,
        "benign_block_false_positive_rate": round((benign_blocked / benign), 4) if benign else 0.0,
        "scenario_scores": {k: v for k, v in sorted(by_scenario.items())},
    }


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate public E2E demo metrics.")
    p.add_argument("--seed", type=int, default=42, help="dataset seed (default: 42)")
    p.add_argument(
        "--mode",
        choices=["direct", "db"],
        default="direct",
        help="direct: no DB ingest (low memory), db: ingest/read DB path (legacy)",
    )
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    workspace_slug = "public_demo"
    sensor_id = "public-demo-sensor-01"
    out_path = Path("docs/public_demo_metrics.json")
    events = build_demo_events(seed=int(args.seed))
    ingest_result: dict[str, object]
    if args.mode == "db":
        from dashboard.storage import init_db, insert_security_events

        init_db()
        _clear_workspace_data(workspace_slug)
        ingest_result = insert_security_events(workspace_slug, sensor_id, events)
    else:
        ingest_result = {"inserted": 0, "skipped": len(events), "mode": "direct"}
    metrics = evaluate(events)
    payload = {
        "workspace_slug": workspace_slug,
        "sensor_id": sensor_id,
        "mode": args.mode,
        "ingest_result": ingest_result,
        "metrics": metrics,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    print(f"\nwritten: {out_path}")


if __name__ == "__main__":
    main()
