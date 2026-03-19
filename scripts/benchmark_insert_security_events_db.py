#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Benchmark exkururuIPROS insert_security_events DB write path.")
    p.add_argument("--events", type=int, default=1000, help="events per run")
    p.add_argument("--runs", type=int, default=3, help="benchmark runs")
    p.add_argument("--workspace", default="bench-workspace", help="workspace slug")
    p.add_argument("--sensor-id", default="bench-sensor", help="sensor id")
    p.add_argument(
        "--out",
        type=Path,
        default=Path("/tmp/perf_insert_security_events_db.json"),
        help="output json path",
    )
    return p.parse_args()


def _build_events(run_idx: int, count: int) -> list[dict]:
    now = time.time()
    rows: list[dict] = []
    for i in range(max(1, count)):
        rows.append(
            {
                "event_id": f"public-bench-{run_idx}-{int(now)}-{i}",
                "detected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                "src_ip": f"198.51.{(i // 250) % 200}.{(i % 250) + 1}",
                "dst_ip": "192.0.2.10",
                "src_port": 50000 + (i % 1000),
                "dst_port": 443,
                "protocol": "tcp",
                "signature": "benchmark_signature",
                "severity": "low",
                "score": 5.0,
                "action": "observe",
                "payload_excerpt": "public_insert_benchmark",
            }
        )
    return rows


def main() -> int:
    args = parse_args()
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from dashboard.storage import connect, init_db, insert_security_events  # noqa: WPS433

    os.environ["IPS_THREAT_INTEL_INLINE_MODE"] = "off"

    with tempfile.TemporaryDirectory(prefix="ipros-public-bench-") as tmp:
        db_path = str(Path(tmp) / "bench.sqlite3")
        os.environ["IPS_DB_PATH"] = db_path
        os.environ.pop("IPS_DB_DSN", None)
        init_db()

        run_rows: list[dict] = []
        for run_idx in range(1, max(1, args.runs) + 1):
            events = _build_events(run_idx, args.events)
            started = time.perf_counter()
            result = insert_security_events(args.workspace, args.sensor_id, events)
            elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
            with connect() as conn:
                inserted_rows = int(
                    conn.execute(
                        "SELECT COUNT(*) AS c FROM security_events WHERE workspace_slug = ?",
                        (args.workspace,),
                    ).fetchone()["c"]
                )
            throughput = (len(events) * 1000.0 / elapsed_ms) if elapsed_ms > 0 else 0.0
            run_rows.append(
                {
                    "run": run_idx,
                    "events": len(events),
                    "accepted": int(result.get("accepted") or 0),
                    "skipped": int(result.get("skipped") or 0),
                    "elapsed_ms": elapsed_ms,
                    "throughput_eps": round(throughput, 3),
                    "rows_in_db_after_run": inserted_rows,
                }
            )

        avg_elapsed_ms = sum(float(r["elapsed_ms"]) for r in run_rows) / max(1, len(run_rows))
        avg_throughput_eps = sum(float(r["throughput_eps"]) for r in run_rows) / max(1, len(run_rows))
        accepted_avg = sum(int(r["accepted"]) for r in run_rows) / max(1, len(run_rows))

        report = {
            "schema_version": "exkururuipros.insert_security_events.db.v1",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "workload": {
                "runs": max(1, args.runs),
                "events_per_run": max(1, args.events),
                "workspace": args.workspace,
                "sensor_id": args.sensor_id,
            },
            "runs": run_rows,
            "summary": {
                "avg_elapsed_ms": round(avg_elapsed_ms, 3),
                "avg_throughput_eps": round(avg_throughput_eps, 3),
                "avg_accepted": round(float(accepted_avg), 3),
            },
        }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
