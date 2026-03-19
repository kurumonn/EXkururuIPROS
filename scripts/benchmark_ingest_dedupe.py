#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import sqlite3
import tempfile
import time
from pathlib import Path


def _init_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_slug TEXT NOT NULL,
            source_event_key TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_security_events_key ON security_events (workspace_slug, source_event_key)"
    )
    conn.commit()


def _seed_existing(conn: sqlite3.Connection, workspace: str, count: int) -> list[str]:
    keys = [f"evt-{i:08d}" for i in range(max(0, count))]
    conn.executemany(
        "INSERT INTO security_events (workspace_slug, source_event_key) VALUES (?, ?)",
        [(workspace, key) for key in keys],
    )
    conn.commit()
    return keys


def _build_batch(existing_keys: list[str], total: int, duplicate_ratio: float) -> list[str]:
    total = max(1, total)
    duplicate_count = min(total, int(total * duplicate_ratio))
    unique_count = max(0, total - duplicate_count)
    batch: list[str] = []
    if duplicate_count > 0 and existing_keys:
        rng = random.Random(20260311)
        batch.extend(rng.choices(existing_keys, k=duplicate_count))
    start = len(existing_keys) + 1
    batch.extend(f"evt-{start + i:08d}" for i in range(unique_count))
    random.Random(20260312).shuffle(batch)
    return batch


def _run_naive(conn: sqlite3.Connection, workspace: str, batch: list[str]) -> dict[str, float | int]:
    accepted = 0
    skipped = 0
    started = time.perf_counter()
    for source_key in batch:
        row = conn.execute(
            "SELECT 1 FROM security_events WHERE workspace_slug = ? AND source_event_key = ?",
            (workspace, source_key),
        ).fetchone()
        if row is not None:
            skipped += 1
            continue
        conn.execute(
            "INSERT INTO security_events (workspace_slug, source_event_key) VALUES (?, ?)",
            (workspace, source_key),
        )
        accepted += 1
    conn.commit()
    elapsed = time.perf_counter() - started
    return {
        "accepted": accepted,
        "skipped": skipped,
        "elapsed_sec": elapsed,
        "events_per_sec": (len(batch) / elapsed) if elapsed > 0 else 0.0,
    }


def _run_batch(conn: sqlite3.Connection, workspace: str, batch: list[str], chunk_size: int = 400) -> dict[str, float | int]:
    accepted = 0
    skipped = 0
    started = time.perf_counter()

    lookup_keys = sorted({key for key in batch if key})
    existing: set[str] = set()
    for i in range(0, len(lookup_keys), chunk_size):
        chunk = lookup_keys[i : i + chunk_size]
        placeholders = ",".join("?" for _ in chunk)
        rows = conn.execute(
            f"""
            SELECT source_event_key
            FROM security_events
            WHERE workspace_slug = ?
              AND source_event_key IN ({placeholders})
            """,
            (workspace, *chunk),
        ).fetchall()
        for row in rows:
            key = str(row[0] or "").strip()
            if key:
                existing.add(key)

    for source_key in batch:
        if source_key in existing:
            skipped += 1
            continue
        conn.execute(
            "INSERT INTO security_events (workspace_slug, source_event_key) VALUES (?, ?)",
            (workspace, source_key),
        )
        existing.add(source_key)
        accepted += 1
    conn.commit()
    elapsed = time.perf_counter() - started
    return {
        "accepted": accepted,
        "skipped": skipped,
        "elapsed_sec": elapsed,
        "events_per_sec": (len(batch) / elapsed) if elapsed > 0 else 0.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark dedupe query strategy for IPROS ingest path.")
    parser.add_argument("--existing", type=int, default=120000, help="pre-seeded rows in security_events")
    parser.add_argument("--batch", type=int, default=30000, help="incoming event count")
    parser.add_argument("--duplicate-ratio", type=float, default=0.4, help="ratio of incoming duplicate source keys")
    parser.add_argument("--out", type=Path, default=Path("/tmp/perf_ipros_dedupe_query.json"))
    args = parser.parse_args()

    workspace = "benchmark-workspace"
    with tempfile.TemporaryDirectory(prefix="ipros-bench-") as tmp:
        db_path = Path(tmp) / "bench.sqlite3"
        conn1 = sqlite3.connect(db_path)
        conn1.row_factory = sqlite3.Row
        _init_db(conn1)
        existing_keys = _seed_existing(conn1, workspace, max(0, args.existing))
        batch_keys = _build_batch(existing_keys, max(1, args.batch), max(0.0, min(1.0, args.duplicate_ratio)))
        naive = _run_naive(conn1, workspace, batch_keys)
        conn1.close()

        conn2 = sqlite3.connect(db_path)
        conn2.row_factory = sqlite3.Row
        conn2.execute("DELETE FROM security_events")
        conn2.commit()
        _seed_existing(conn2, workspace, max(0, args.existing))
        batch_mode = _run_batch(conn2, workspace, batch_keys)
        conn2.close()

    naive_elapsed = float(naive["elapsed_sec"])
    batch_elapsed = float(batch_mode["elapsed_sec"])
    result = {
        "workload": {
            "existing_rows": int(args.existing),
            "batch_rows": int(args.batch),
            "duplicate_ratio": float(args.duplicate_ratio),
        },
        "naive_per_event_select": naive,
        "batch_lookup_set": batch_mode,
        "comparison": {
            "speedup_batch_vs_naive": (naive_elapsed / batch_elapsed) if batch_elapsed > 0 else None,
        },
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    args.out.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
