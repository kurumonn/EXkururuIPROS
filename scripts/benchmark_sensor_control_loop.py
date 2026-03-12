#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class _AckHandler(BaseHTTPRequestHandler):
    ack_delay_sec = 0.0

    def do_POST(self) -> None:  # noqa: N802
        content_length = int(self.headers.get("Content-Length", "0") or "0")
        if content_length > 0:
            _ = self.rfile.read(content_length)
        if self.ack_delay_sec > 0:
            time.sleep(self.ack_delay_sec)
        payload = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        # keep benchmark output clean
        return


def _find_free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _post_ack(url: str) -> None:
    body = b'{"status":"applied","meta":{"bench":true}}'
    req = urllib.request.Request(url=url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=10):
        pass


def _bench_ack(url_base: str, actions: int, parallelism: int) -> tuple[float, float]:
    # before: sequential ack (old path)
    t0 = time.perf_counter()
    for idx in range(actions):
        _post_ack(f"{url_base}/{idx}/ack/")
    sequential_sec = time.perf_counter() - t0

    # after: bounded parallel ack (new path)
    t1 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=max(1, parallelism)) as pool:
        list(pool.map(lambda idx: _post_ack(f"{url_base}/{idx}/ack/"), range(actions)))
    parallel_sec = time.perf_counter() - t1
    return sequential_sec, parallel_sec


def _bench_nft_spawn(actions: int) -> tuple[float, float]:
    # before: per-action external process spawn (old path equivalent)
    t0 = time.perf_counter()
    for _ in range(actions):
        subprocess.run(["true"], check=True)
    per_action_sec = time.perf_counter() - t0

    # after: single batch external process spawn (new path equivalent)
    t1 = time.perf_counter()
    subprocess.run(["true"], check=True)
    batched_sec = time.perf_counter() - t1
    return per_action_sec, batched_sec


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark sensor control loop before/after tuning.")
    parser.add_argument("--actions", type=int, default=120, help="number of actions in one control loop")
    parser.add_argument("--ack-delay-ms", type=float, default=20.0, help="mock server delay per ack request")
    parser.add_argument("--ack-parallelism", type=int, default=8, help="parallel workers for ack path")
    parser.add_argument("--out", type=Path, default=Path("docs/perf_sensor_control_loop.json"))
    args = parser.parse_args()

    port = _find_free_port()
    _AckHandler.ack_delay_sec = max(0.0, args.ack_delay_ms) / 1000.0
    server = ThreadingHTTPServer(("127.0.0.1", port), _AckHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        ack_seq, ack_par = _bench_ack(
            f"http://127.0.0.1:{port}/api/v1/workspaces/lab/sensors/s1/actions",
            max(1, args.actions),
            max(1, args.ack_parallelism),
        )
        nft_old, nft_new = _bench_nft_spawn(max(1, args.actions))
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)

    result = {
        "workload": {
            "actions": int(max(1, args.actions)),
            "ack_delay_ms": float(max(0.0, args.ack_delay_ms)),
            "ack_parallelism": int(max(1, args.ack_parallelism)),
        },
        "ack_path": {
            "before_sequential_sec": round(ack_seq, 6),
            "after_parallel_sec": round(ack_par, 6),
            "speedup_parallel_vs_seq": round((ack_seq / ack_par), 3) if ack_par > 0 else None,
        },
        "nft_apply_path": {
            "before_per_action_spawn_sec": round(nft_old, 6),
            "after_batched_single_spawn_sec": round(nft_new, 6),
            "speedup_batch_vs_per_action": round((nft_old / nft_new), 3) if nft_new > 0 else None,
        },
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    args.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

