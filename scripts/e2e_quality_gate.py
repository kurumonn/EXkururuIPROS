#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import resource
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.public_e2e_demo import build_demo_events, evaluate
from dashboard.security import db_path
from dashboard.storage import init_db, insert_security_events, list_security_events_for_eval


DEFAULT_THRESHOLDS = {
    "attack_defense_min": 0.95,
    "attack_block_min": 0.35,
    "benign_false_positive_max": 0.01,
    "benign_block_false_positive_max": 0.001,
    "new_attack_defense_min": 0.95,
    "max_cpu_sec": 5.0,
    "max_rss_mb": 256.0,
}
DEFAULT_NEW_ATTACK_SCENARIOS = (
    "identity_token_abuse_2026",
    "cloud_k8s_privilege_abuse_2026",
    "ransomware_precursor_chain_2026",
)


def _to_float(value, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _parse_csv_tokens(raw: str) -> list[str]:
    return [item.strip() for item in str(raw).split(",") if item.strip()]


def _new_attack_coverage(metrics: dict, scenarios: list[str]) -> dict:
    scenario_scores = metrics.get("scenario_scores") if isinstance(metrics.get("scenario_scores"), dict) else {}
    total_attack = 0.0
    total_mitigated = 0.0
    present_count = 0
    details: dict[str, dict] = {}
    for scenario in scenarios:
        row = scenario_scores.get(scenario) if isinstance(scenario_scores, dict) else {}
        attack = _to_float((row or {}).get("attack"), 0.0)
        mitigated = _to_float((row or {}).get("mitigated"), 0.0)
        if attack > 0:
            present_count += 1
        total_attack += attack
        total_mitigated += mitigated
        details[scenario] = {
            "attack_events": int(attack),
            "mitigated_events": int(mitigated),
            "defense_rate": round((mitigated / attack), 4) if attack > 0 else 0.0,
        }
    defense_rate = (total_mitigated / total_attack) if total_attack > 0 else 0.0
    return {
        "target_scenarios": scenarios,
        "present_scenarios": int(present_count),
        "attack_events": int(total_attack),
        "mitigated_events": int(total_mitigated),
        "defense_rate": round(defense_rate, 4),
        "by_scenario": details,
    }


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run deterministic E2E quality gate for NGIPS.")
    p.add_argument("--seed", type=int, default=42, help="dataset seed (default: 42)")
    p.add_argument("--attack-defense-min", type=float, default=DEFAULT_THRESHOLDS["attack_defense_min"])
    p.add_argument("--attack-block-min", type=float, default=DEFAULT_THRESHOLDS["attack_block_min"])
    p.add_argument("--benign-fp-max", type=float, default=DEFAULT_THRESHOLDS["benign_false_positive_max"])
    p.add_argument("--benign-block-fp-max", type=float, default=DEFAULT_THRESHOLDS["benign_block_false_positive_max"])
    p.add_argument("--new-attack-defense-min", type=float, default=DEFAULT_THRESHOLDS["new_attack_defense_min"])
    p.add_argument(
        "--new-attack-scenarios",
        type=str,
        default=",".join(DEFAULT_NEW_ATTACK_SCENARIOS),
        help="comma-separated scenario names treated as newly supported attack families",
    )
    p.add_argument("--max-cpu-sec", type=float, default=DEFAULT_THRESHOLDS["max_cpu_sec"])
    p.add_argument("--max-rss-mb", type=float, default=DEFAULT_THRESHOLDS["max_rss_mb"])
    p.add_argument(
        "--out",
        type=Path,
        default=Path("/tmp/e2e_quality_gate.json"),
        help="output json path (default: /tmp/e2e_quality_gate.json)",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    started_cpu = time.process_time()
    started_wall = time.perf_counter()
    workspace_slug = "quality_gate_demo"
    sensor_id = "quality-gate-sensor"
    init_db()
    conn = sqlite3.connect(db_path())
    try:
        conn.execute("DELETE FROM security_events WHERE workspace_slug = ?", (workspace_slug,))
        conn.execute("DELETE FROM soc_incidents WHERE workspace_slug = ?", (workspace_slug,))
        conn.execute("DELETE FROM soc_triage_logs WHERE workspace_slug = ?", (workspace_slug,))
        conn.commit()
    finally:
        conn.close()

    events = build_demo_events(seed=int(args.seed))
    insert_security_events(workspace_slug, sensor_id, events)
    stored_rows = list_security_events_for_eval(workspace_slug=workspace_slug, since_iso=None, limit=50000)
    effective_events = []
    for row in stored_rows:
        raw = row.get("raw_event") if isinstance(row.get("raw_event"), dict) else {}
        if isinstance(raw, dict):
            effective_events.append(raw)
    metrics = evaluate(effective_events)
    new_attack_scenarios = _parse_csv_tokens(args.new_attack_scenarios)
    new_attack_coverage = _new_attack_coverage(metrics, new_attack_scenarios)
    metrics["new_attack_coverage"] = new_attack_coverage

    resource_snapshot = {
        "cpu_time_sec": round(time.process_time() - started_cpu, 6),
        "wall_time_sec": round(time.perf_counter() - started_wall, 6),
        "max_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 3),
    }
    thresholds = {
        "attack_defense_min": float(args.attack_defense_min),
        "attack_block_min": float(args.attack_block_min),
        "benign_false_positive_max": float(args.benign_fp_max),
        "benign_block_false_positive_max": float(args.benign_block_fp_max),
        "new_attack_defense_min": float(args.new_attack_defense_min),
        "new_attack_scenarios_required": len(new_attack_scenarios),
        "max_cpu_sec": float(args.max_cpu_sec),
        "max_rss_mb": float(args.max_rss_mb),
    }
    checks = [
        {
            "name": "attack_defense_rate",
            "actual": _to_float(metrics.get("attack_defense_rate"), 0.0),
            "op": ">=",
            "threshold": thresholds["attack_defense_min"],
        },
        {
            "name": "attack_block_rate",
            "actual": _to_float(metrics.get("attack_block_rate"), 0.0),
            "op": ">=",
            "threshold": thresholds["attack_block_min"],
        },
        {
            "name": "benign_false_positive_rate",
            "actual": _to_float(metrics.get("benign_false_positive_rate"), 1.0),
            "op": "<=",
            "threshold": thresholds["benign_false_positive_max"],
        },
        {
            "name": "benign_block_false_positive_rate",
            "actual": _to_float(metrics.get("benign_block_false_positive_rate"), 1.0),
            "op": "<=",
            "threshold": thresholds["benign_block_false_positive_max"],
        },
        {
            "name": "new_attack_scenarios_present",
            "actual": int(new_attack_coverage.get("present_scenarios") or 0),
            "op": ">=",
            "threshold": thresholds["new_attack_scenarios_required"],
        },
        {
            "name": "new_attack_defense_rate",
            "actual": _to_float(new_attack_coverage.get("defense_rate"), 0.0),
            "op": ">=",
            "threshold": thresholds["new_attack_defense_min"],
        },
        {
            "name": "cpu_time_sec",
            "actual": _to_float(resource_snapshot.get("cpu_time_sec"), 0.0),
            "op": "<=",
            "threshold": thresholds["max_cpu_sec"],
        },
        {
            "name": "max_rss_mb",
            "actual": _to_float(resource_snapshot.get("max_rss_mb"), 0.0),
            "op": "<=",
            "threshold": thresholds["max_rss_mb"],
        },
    ]
    failed = []
    for c in checks:
        if c["op"] == ">=":
            c["pass"] = bool(c["actual"] >= c["threshold"])
        else:
            c["pass"] = bool(c["actual"] <= c["threshold"])
        if not c["pass"]:
            failed.append(c["name"])

    result = {
        "ok": not failed,
        "failed_checks": failed,
        "seed": int(args.seed),
        "workspace_slug": workspace_slug,
        "test_items": [c["name"] for c in checks],
        "thresholds": thresholds,
        "resource": resource_snapshot,
        "metrics": metrics,
        "checks": checks,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
