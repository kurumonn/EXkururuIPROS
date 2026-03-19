from __future__ import annotations

from scripts.public_e2e_demo import evaluate


def test_evaluate_separates_attack_and_benign() -> None:
    events = [
        {"scenario": "attack-a", "ground_truth": "attack", "action": "block"},
        {"scenario": "attack-a", "ground_truth": "attack", "action": "challenge"},
        {"scenario": "benign-a", "ground_truth": "benign", "action": "allow"},
        {"scenario": "benign-a", "ground_truth": "benign", "action": "observe"},
    ]
    metrics = evaluate(events)
    assert metrics["attack_defense_rate"] == 1.0
    assert metrics["benign_false_positive_rate"] == 0.0
    assert metrics["scenario_scores"]["attack-a"]["blocked"] == 1


def test_public_demo_attack_block_rate_is_block_first() -> None:
    metrics = evaluate(build_demo_events(seed=42))
    assert metrics["attack_block_rate"] >= 0.5
    assert metrics["benign_false_positive_rate"] == 0.0
