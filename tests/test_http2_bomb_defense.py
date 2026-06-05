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


def test_http2_hpack_amplification_is_blocked_and_queues_ip_mitigation(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("IPS_DB_PATH", str(tmp_path / "ips.db"))
    init_db()

    result = insert_security_events(
        "h2lab",
        "edge-01",
        [
            {
                "event_id": "h2bomb-1",
                "detected_at": "2026-06-06T00:00:00+00:00",
                "src_ip": "198.51.100.77",
                "http_version": "h2",
                "header_count": 4000,
                "hpack_indexed_ref_count": 4000,
                "largest_header_bytes": 65536,
                "hpack_table_bytes": 131072,
                "decoded_header_bytes": 4 * 1024 * 1024,
                "severity": "medium",
                "action": "alert",
            }
        ],
    )

    assert result["accepted"] == 1
    assert result["http2_bomb_queued"] == 1

    event = _latest_raw_event()
    assert event["signature"] == "HTTP2-BOMB-HPACK-001"
    assert event["http2_bomb_defense"]["cve"] == "CVE-2026-49975"
    assert event["severity"] == "critical"
    assert event["action"] == "block"
    assert "http2_bomb" in event["tags"]
    assert "cve_2026_49975" in event["tags"]
    assert "header_ref_flood" in event["http2_bomb_defense"]["signals"]

    actions = fetch_pending_actions("h2lab", "edge-01", 10)
    assert any(a["target_type"] == "ip" and a["target_value"] == "198.51.100.77" for a in actions)

    summary = mythos_defense_summary("h2lab")
    assert summary["http2_bomb"]["events"] == 1
    assert summary["http2_bomb"]["critical_events"] == 1
    assert summary["http2_bomb"]["ip_block_actions_active"] >= 1


def test_http2_slowloris_hold_event_type_is_detected(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("IPS_DB_PATH", str(tmp_path / "ips.db"))
    init_db()

    result = insert_security_events(
        "h2lab",
        "edge-01",
        [
            {
                "event_id": "h2bomb-slow-1",
                "src_ip": "203.0.113.40",
                "event_type": "h2_slowloris",
                "http_version": "HTTP/2.0",
                "header_count": 1500,
                "connection_duration_sec": 90,
                "conn_mem_bytes": 64 * 1024 * 1024,
                "severity": "low",
                "action": "observe",
            }
        ],
    )

    assert result["accepted"] == 1
    event = _latest_raw_event()
    assert str(event["signature"]).startswith("HTTP2-BOMB")
    assert "slowloris_hold" in event["http2_bomb_defense"]["signals"]
    assert event["action"] in {"limit", "block"}


def test_normal_http2_traffic_is_not_flagged(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("IPS_DB_PATH", str(tmp_path / "ips.db"))
    init_db()

    result = insert_security_events(
        "h2lab",
        "edge-01",
        [
            {
                "event_id": "h2-normal-1",
                "src_ip": "203.0.113.50",
                "http_version": "h2",
                "header_count": 24,
                "hpack_indexed_ref_count": 12,
                "largest_header_bytes": 512,
                "hpack_table_bytes": 4096,
                "connection_duration_sec": 3,
                "severity": "low",
                "action": "observe",
            }
        ],
    )

    assert result["accepted"] == 1
    assert result["http2_bomb_queued"] == 0
    event = _latest_raw_event()
    assert "http2_bomb_defense" not in event
    assert "http2_bomb" not in (event.get("tags") or [])
