from __future__ import annotations

import os
from datetime import datetime, timezone


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
    return action in {"limit", "challenge", "block", "captcha", "throttle", "deny", "drop", "reject", "waf_block"}


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
    threshold_p95_ms = _to_float(os.getenv("IPS_ACTION_P95_MS_MAX", "120"), 120.0)
    threshold_p99_ms = _to_float(os.getenv("IPS_ACTION_P99_MS_MAX", "300"), 300.0)
    min_samples = int(_to_float(os.getenv("IPS_ACTION_SLO_MIN_SAMPLES", "20"), 20))
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
    attack_events = benign_events = attack_mitigated = attack_blocked = benign_mitigated = benign_blocked = 0
    latency_values = []
    scenario_stats: dict[str, dict] = {}
    unknown_attack_events = unknown_attack_mitigated = ti_attack_hits = sandbox_attack_hits = 0
    app_context_events = user_context_events = app_user_context_events = chain_context_events = 0
    for row in events:
        raw = row.get("raw_event") if isinstance(row.get("raw_event"), dict) else {}
        action = str(raw.get("action") or row.get("action") or "").strip().lower()
        label = str(raw.get("ground_truth") or "").strip().lower()
        scenario = str(raw.get("scenario") or raw.get("attack_type") or raw.get("traffic_type") or "unknown").strip().lower()
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
        s = scenario_stats.setdefault(scenario, {"scenario": scenario, "total": 0, "attack": 0, "benign": 0, "mitigated": 0, "blocked": 0, "attack_mitigated": 0, "attack_blocked": 0, "benign_mitigated": 0, "benign_blocked": 0})
        s["total"] += 1
        if _is_mitigated(action):
            s["mitigated"] += 1
        if _is_blocked(action):
            s["blocked"] += 1
        if label in attack_labels:
            attack_events += 1
            s["attack"] += 1
            is_unknown_like = any(x in scenario for x in {"zero", "0day", "unknown", "apt", "novel"})
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
    advanced_threat_coverage = ((unknown_attack_mitigation_rate + threat_intel_hit_rate + sandbox_coverage_rate) / 3.0 if attack_events else 0.0)
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
