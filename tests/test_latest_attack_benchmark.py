from __future__ import annotations

from scripts.latest_attack_benchmark import _build_events
from scripts.public_e2e_demo import evaluate


def test_latest_attack_benchmark_is_block_first_without_raising_false_positives() -> None:
    metrics = evaluate(_build_events(seed=20260310))
    assert metrics["attack_block_rate"] >= 0.35
    assert metrics["benign_false_positive_rate"] <= 0.01
