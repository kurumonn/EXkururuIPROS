"""Cloudflare edge IP normalization for EXkururuIPROS.

Cloudflare routes traffic through edge nodes, so `remote_addr` on the origin
server is a Cloudflare IP, not the real visitor IP.  The actual client IP
arrives in the CF-Connecting-IP (or X-Forwarded-For) header.

Block/ban decisions MUST use the normalized IP, not remote_addr.
"""
from __future__ import annotations

import ipaddress
import os
import threading
import time
import urllib.request

from .storage import connect, utcnow

_CF_IPV4_URL = "https://www.cloudflare.com/ips-v4/"
_CF_IPV6_URL = "https://www.cloudflare.com/ips-v6/"

_CACHE_LOCK = threading.Lock()
_CF_NETWORKS_CACHE: tuple[float, list[ipaddress._BaseNetwork]] | None = None
_CF_CACHE_TTL = 86400  # 24 h

CLOUDFLARE_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cloudflare_ip_ranges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cidr TEXT NOT NULL,
  ip_version INTEGER NOT NULL DEFAULT 4,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_cloudflare_ip_ranges_cidr ON cloudflare_ip_ranges (cidr);
CREATE INDEX IF NOT EXISTS idx_cloudflare_ip_ranges_updated ON cloudflare_ip_ranges (updated_at DESC);
"""


def _fetch_ranges_from_urls() -> list[str]:
    cidrs: list[str] = []
    for url in (_CF_IPV4_URL, _CF_IPV6_URL):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "EXkururuIPROS/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                text = resp.read().decode("utf-8")
            for line in text.splitlines():
                line = line.strip()
                if line:
                    cidrs.append(line)
        except Exception:
            pass
    return cidrs


def sync_cloudflare_ip_ranges() -> dict:
    """Fetch Cloudflare IP ranges and persist to DB. Invalidates in-memory cache."""
    cidrs = _fetch_ranges_from_urls()
    if not cidrs:
        return {"status": "error", "error": "no ranges fetched", "count": 0}

    now = utcnow()
    accepted = 0
    with connect() as conn:
        for cidr in cidrs:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            conn.execute(
                """
                INSERT INTO cloudflare_ip_ranges (cidr, ip_version, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(cidr) DO UPDATE SET updated_at=excluded.updated_at
                """,
                (str(net), net.version, now),
            )
            accepted += 1

    with _CACHE_LOCK:
        global _CF_NETWORKS_CACHE
        _CF_NETWORKS_CACHE = None  # force reload on next call

    return {"status": "ok", "count": accepted}


def _load_cf_networks() -> list[ipaddress._BaseNetwork]:
    global _CF_NETWORKS_CACHE
    now = time.time()

    with _CACHE_LOCK:
        if _CF_NETWORKS_CACHE is not None:
            ts, nets = _CF_NETWORKS_CACHE
            if now - ts < _CF_CACHE_TTL:
                return nets

    networks: list[ipaddress._BaseNetwork] = []
    try:
        with connect() as conn:
            rows = conn.execute("SELECT cidr FROM cloudflare_ip_ranges").fetchall()
        for row in rows:
            try:
                networks.append(ipaddress.ip_network(row["cidr"], strict=False))
            except ValueError:
                pass
    except Exception:
        pass

    # Fallback: well-known Cloudflare ranges (as of 2025) if DB is empty
    if not networks:
        _STATIC_CF = [
            "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
            "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
            "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
            "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
            "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
            "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
            "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
            "2c0f:f248::/32",
        ]
        for cidr in _STATIC_CF:
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass

    with _CACHE_LOCK:
        _CF_NETWORKS_CACHE = (now, networks)

    return networks


def is_cloudflare_ip(ip_str: str) -> bool:
    """Return True if the IP is a Cloudflare edge node."""
    try:
        ip = ipaddress.ip_address(str(ip_str or "").strip())
    except ValueError:
        return False
    for net in _load_cf_networks():
        if ip.version == net.version and ip in net:
            return True
    return False


def normalize_client_ip(remote_addr: str, headers: dict[str, str]) -> tuple[str, bool]:
    """
    Returns (normalized_client_ip, was_cloudflare).

    If remote_addr is a Cloudflare edge IP, the real visitor IP is taken from
    CF-Connecting-IP.  Falls back to X-Forwarded-For leftmost if needed.
    The normalized IP is what should be used for ban/block decisions.
    """
    raw_remote = str(remote_addr or "").strip()
    was_cf = is_cloudflare_ip(raw_remote)

    if not was_cf:
        return raw_remote, False

    # Trusted proxy: use CF-Connecting-IP
    cf_ip = str(headers.get("cf-connecting-ip", "") or "").strip()
    if cf_ip:
        try:
            ipaddress.ip_address(cf_ip)
            return cf_ip, True
        except ValueError:
            pass

    # Fallback: X-Forwarded-For leftmost non-CF entry
    xff = str(headers.get("x-forwarded-for", "") or "").strip()
    if xff:
        for part in reversed(xff.split(",")):
            candidate = part.strip()
            try:
                ipaddress.ip_address(candidate)
                if not is_cloudflare_ip(candidate):
                    return candidate, True
            except ValueError:
                pass

    # Can't determine real IP; return remote_addr as best effort
    return raw_remote, True
