#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib


def sensor_home_shard(workspace_slug: str, sensor_id: str, shard_count: int) -> int:
    if shard_count <= 1:
        return 0
    key = f"{workspace_slug}:{sensor_id}".encode("utf-8")
    digest = hashlib.sha256(key).hexdigest()[:8]
    return int(digest, 16) % shard_count


def main() -> int:
    p = argparse.ArgumentParser(description="Print deterministic ingest shard assignment for sensors.")
    p.add_argument("--workspace", required=True, help="workspace slug")
    p.add_argument("--shards", type=int, default=8, help="total shard count (default: 8)")
    p.add_argument("sensor_ids", nargs="+", help="sensor ids")
    args = p.parse_args()

    shard_count = max(1, min(int(args.shards), 128))
    workspace = str(args.workspace).strip()
    for sensor_id in args.sensor_ids:
        sid = str(sensor_id).strip()
        shard = sensor_home_shard(workspace, sid, shard_count)
        print(f"{sid}\tshard={shard}/{shard_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
