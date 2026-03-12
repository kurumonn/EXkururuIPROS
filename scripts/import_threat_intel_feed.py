#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def _load_payload(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        entries = raw.get("entries")
        if isinstance(entries, list):
            return raw
    if isinstance(raw, list):
        return {"entries": raw}
    raise ValueError("feed file must be a list or object with entries[]")


def main() -> int:
    parser = argparse.ArgumentParser(description="Import canonical threat intel feed into EXkururuIPROS")
    parser.add_argument("--file", required=True, help="path to feed json")
    parser.add_argument("--base-url", default="http://127.0.0.1:8811", help="dashboard base url")
    parser.add_argument("--admin-token", required=True, help="admin bearer token")
    parser.add_argument("--feed-source", default="", help="override feed_source")
    parser.add_argument("--feed-name", default="", help="override feed_name")
    parser.add_argument("--feed-version", default="", help="override feed_version")
    parser.add_argument("--default-ttl-hours", type=int, default=None, help="default ttl for entries")
    args = parser.parse_args()

    payload = _load_payload(Path(args.file))
    if args.feed_source:
        payload["feed_source"] = args.feed_source
    if args.feed_name:
        payload["feed_name"] = args.feed_name
    if args.feed_version:
        payload["feed_version"] = args.feed_version
    if args.default_ttl_hours is not None:
        payload["default_ttl_hours"] = args.default_ttl_hours

    req = urllib.request.Request(
        url=args.base_url.rstrip("/") + "/api/v1/admin/threat-intel/bulk/",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {args.admin_token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
            print(body)
            return 0
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        print(body)
        return 1
    except urllib.error.URLError as exc:
        print(f'{{"ok": false, "error": "request_failed", "detail": "{exc}"}}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
