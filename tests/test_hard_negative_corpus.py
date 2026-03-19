from __future__ import annotations

from scripts.latest_attack_benchmark import _build_events
from scripts.public_e2e_demo import build_demo_events


def test_public_demo_includes_hard_negative_benign_context() -> None:
    events = build_demo_events(seed=42)
    hard_negative = [event for event in events if "hard_negative" in set(event.get("context_tags", []))]
    assert hard_negative, "expected hard-negative cases in the public demo corpus"
    assert all(str(event.get("ground_truth")) == "benign" for event in hard_negative)


def test_latest_attack_benchmark_includes_hard_negative_benign_context() -> None:
    events = _build_events(seed=20260310)
    hard_negative = [event for event in events if "hard_negative" in set(event.get("context_tags", []))]
    assert hard_negative, "expected hard-negative cases in the attack benchmark corpus"
    assert all(str(event.get("ground_truth")) == "benign" for event in hard_negative)
