from __future__ import annotations

import json

from dashboard.storage import (
    connect,
    fetch_pending_actions,
    init_db,
    insert_security_events,
    mythos_defense_summary,
)


def _latest_raw_event() -> dict:
    with connect() as conn:
        row = conn.execute(
            "SELECT raw_event FROM security_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert row is not None
    return json.loads(row["raw_event"])


def test_mythos_canary_env_probe_is_normalized_and_blocked(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("IPS_DB_PATH", str(tmp_path / "ips.db"))
    init_db()

    result = insert_security_events(
        "lab",
        "sensor-01",
        [
            {
                "event_id": "mythos-env-1",
                "detected_at": "2026-05-21T00:00:00+00:00",
                "src_ip": "198.51.100.10",
                "uri": "/%2eenv",
                "status_code": 404,
                "severity": "medium",
                "action": "alert",
            }
        ],
    )

    assert result["accepted"] == 1
    event = _latest_raw_event()
    assert event["normalized_uri"] == "/.env"
    assert "mythos_defense" in event
    assert "env_probe" in event["request_categories"]
    assert "canary_hit" in event["request_categories"]
    assert event["severity"] == "critical"
    assert event["action"] == "block"


def test_mythos_batch_correlation_marks_ai_exploit_chain(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("IPS_DB_PATH", str(tmp_path / "ips.db"))
    init_db()

    events = [
        {"event_id": "chain-1", "src_ip": "203.0.113.20", "uri": "/.env", "status_code": 404},
        {"event_id": "chain-2", "src_ip": "203.0.113.20", "uri": "/cgi-bin/.%2e/.%2e/bin/sh", "status_code": 400},
        {"event_id": "chain-3", "src_ip": "203.0.113.20", "uri": "/api/export?url=http://169.254.169.254/", "status_code": 403},
        {"event_id": "chain-4", "src_ip": "203.0.113.20", "uri": "/graphql?query={__schema}", "status_code": 404},
    ]

    result = insert_security_events("lab", "sensor-01", events)

    assert result["accepted"] == 4
    assert result["mythos_chain_hits"] == 4
    summary = mythos_defense_summary("lab")
    assert summary["suspected_ai_probe_chains"] == 4
    with connect() as conn:
        rows = conn.execute("SELECT raw_event FROM security_events ORDER BY id ASC").fetchall()
    assert all("AI_EXPLOIT_CHAIN" in json.loads(row["raw_event"])["tags"] for row in rows)


def test_pintheft_exposure_queues_kernel_hardening_and_audit(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("IPS_DB_PATH", str(tmp_path / "ips.db"))
    init_db()

    result = insert_security_events(
        "lab",
        "edr-01",
        [
            {
                "event_id": "pintheft-exp-1",
                "event_type": "kernel_exposure_snapshot",
                "host_id": "arch-lab-01",
                "rds_loaded": True,
                "rds_tcp_loaded": True,
                "io_uring_disabled": 0,
                "suid_binary_count": 42,
                "severity": "medium",
                "action": "alert",
            }
        ],
    )

    assert result["accepted"] == 1
    assert result["pintheft_queued"] == 1
    event = _latest_raw_event()
    assert event["signature"] == "PINTHEFT-EXPOSURE-001"
    assert event["pintheft_defense"]["target"] == "rds_tcp,rds"

    actions = fetch_pending_actions("lab", "edr-01", 10)
    assert len(actions) == 1
    assert actions[0]["target_type"] == "kernel_module_blacklist"
    assert actions[0]["target_value"] == "rds_tcp,rds"

    with connect() as conn:
        audit = conn.execute(
            "SELECT action, target_type, target_value FROM policy_audit_logs ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert audit is not None
    assert audit["action"] == "kernel_hardening_queued"
    assert audit["target_type"] == "kernel_module_blacklist"
