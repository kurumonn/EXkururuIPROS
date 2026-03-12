from __future__ import annotations

import ipaddress
import os
import re
from collections import defaultdict
from datetime import datetime, timezone


PERF_LOG_RE = re.compile(
    r"(?P<remote_addr>\S+) - (?P<real_ip>\S+) "
    r"\[(?P<time>[^\]]+)\] "
    r'"(?P<method>\S+) (?P<uri>\S+) \S+" '
    r"(?P<status>\d+) (?P<bytes>\d+) "
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)" '
    r"rt=(?P<rt>\S+) uct=(?P<uct>\S+) urt=(?P<urt>\S+)"
    r"(?: reason=(?P<reason>\S+))?"
    r"(?: rid=(?P<rid>\S+))?"
)

COMBINED_LOG_RE = re.compile(
    r"(?P<remote_addr>\S+) - \S+ "
    r"\[(?P<time>[^\]]+)\] "
    r'"(?P<method>\S+) (?P<uri>\S+) \S+" '
    r"(?P<status>\d+) (?P<bytes>\d+) "
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

IPS_STATUS_CODES = {"429", "503"}
BUCKET_FORMAT = "%Y%m%d_%H%M"


def _classify_ua(ua: str) -> tuple[str, str, bool]:
    raw = (ua or "").strip()
    if not raw or raw == "-":
        return "scanner", "[empty_ua]", True
    lower = raw.lower()

    internal_markers = (
        "kube-probe",
        "prometheus",
        "grafana",
        "zabbix",
        "datadog",
        "uptime-kuma",
        "healthcheck",
        "secops",
        "kururuipros",
    )
    scanner_markers = (
        "sqlmap",
        "nikto",
        "nmap",
        "masscan",
        "zgrab",
        "nessus",
        "acunetix",
        "dirbuster",
        "wpscan",
    )
    tooling_markers = (
        "python-requests",
        "scrapy",
        "curl",
        "wget",
        "aiohttp",
        "httpclient",
        "okhttp",
        "go-http-client",
        "headlesschrome",
        "phantomjs",
        "playwright",
        "puppeteer",
    )
    crawler_markers = (
        "googlebot",
        "bingbot",
        "baiduspider",
        "yandexbot",
        "duckduckbot",
        "slurp",
        "facebookexternalhit",
        "applebot",
    )
    browser_markers = ("mozilla/", "chrome/", "safari/", "firefox/", "edg/")

    if any(x in lower for x in internal_markers):
        return "internal", raw[:200], False
    if any(x in lower for x in scanner_markers):
        return "scanner", raw[:200], True
    if any(x in lower for x in tooling_markers):
        return "tooling", raw[:200], True
    if any(x in lower for x in crawler_markers):
        return "crawler", raw[:200], True
    if any(x in lower for x in browser_markers):
        return "browser", raw[:200], False
    return "tooling", raw[:200], True


def parse_line(line: str) -> dict | None:
    m = PERF_LOG_RE.match(line)
    if m:
        return m.groupdict()
    m = COMBINED_LOG_RE.match(line)
    if m:
        d = m.groupdict()
        d["real_ip"] = d["remote_addr"]
        d["rt"] = "-"
        d["uct"] = "-"
        d["urt"] = "-"
        d["reason"] = "-"
        return d
    return None


def _time_bucket(time_str: str) -> str:
    try:
        dt = datetime.strptime(time_str.split()[0], "%d/%b/%Y:%H:%M:%S")
        minute = (dt.minute // 5) * 5
        return dt.replace(minute=minute, second=0).strftime(BUCKET_FORMAT)
    except (ValueError, IndexError):
        return datetime.now(timezone.utc).strftime(BUCKET_FORMAT)


def _safe_float(val):
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _should_exclude_record(uri: str, ip: str) -> bool:
    prefixes_raw = os.getenv("IPS_EXCLUDE_URI_PREFIXES", "/secops/api/,/api/v1/dashboard/summary/,/healthz").strip()
    prefixes = [p.strip() for p in prefixes_raw.split(",") if p.strip()]
    for prefix in prefixes:
        if uri.startswith(prefix):
            return True

    ip_rules_raw = os.getenv("IPS_EXCLUDE_IP_RULES", "").strip()
    if not ip_rules_raw:
        return False
    try:
        src_ip = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return False
    for token in [x.strip() for x in ip_rules_raw.split(",") if x.strip()]:
        try:
            if "/" in token:
                net = ipaddress.ip_network(token, strict=False)
                if src_ip.version == net.version and src_ip in net:
                    return True
            else:
                if src_ip == ipaddress.ip_address(token):
                    return True
        except ValueError:
            continue
    return False


def _should_exclude_rt(uri: str) -> bool:
    prefixes_raw = os.getenv(
        "IPS_EXCLUDE_RT_URI_PREFIXES",
        "/api/v1/admin/,/api/v1/workspaces/,/api/v1/dashboard/summary/,/api/v1/metrics/prometheus,/secops/api/,/healthz",
    ).strip()
    prefixes = [p.strip() for p in prefixes_raw.split(",") if p.strip()]
    for prefix in prefixes:
        if uri.startswith(prefix):
            return True
    return False


def aggregate_lines(lines: list[str]) -> dict:
    bucket_counts = defaultdict(lambda: defaultdict(int))
    bucket_ip = defaultdict(lambda: defaultdict(int))
    bucket_uri = defaultdict(lambda: defaultdict(int))
    bucket_ua = defaultdict(lambda: defaultdict(int))
    bucket_ua_class = defaultdict(lambda: defaultdict(int))
    bucket_uri_all = defaultdict(lambda: defaultdict(int))
    bucket_ua_all = defaultdict(lambda: defaultdict(int))
    bucket_reason = defaultdict(lambda: defaultdict(int))
    response_times = defaultdict(list)

    for line in lines:
        parsed = parse_line(line)
        if not parsed:
            continue
        bucket = _time_bucket(parsed.get("time", ""))
        status = str(parsed.get("status", "0"))
        uri = parsed.get("uri", "-")
        ua = (parsed.get("ua") or "-")[:200]
        ua_class, ua_label, ua_suspicious = _classify_ua(ua)
        ip = parsed.get("real_ip") or parsed.get("remote_addr", "-")
        if _should_exclude_record(uri, ip):
            continue
        reason = parsed.get("reason") or "-"
        counts = bucket_counts[bucket]
        counts["total"] += 1
        bucket_uri_all[bucket][uri] += 1
        if ua_label != "[empty_ua]":
            bucket_ua_all[bucket][ua_label] += 1
        bucket_ua_class[bucket][ua_class] += 1
        if status.startswith("2"):
            counts["s2xx"] += 1
        elif status.startswith("3"):
            counts["s3xx"] += 1
        elif status.startswith("4"):
            counts["s4xx"] += 1
        elif status.startswith("5"):
            counts["s5xx"] += 1

        if status in IPS_STATUS_CODES:
            counts["blocked"] += 1
            if status == "429":
                counts["blocked_429"] += 1
            if status == "503":
                counts["blocked_503"] += 1
            bucket_ip[bucket][ip] += 1
            bucket_uri[bucket][uri] += 1
            bucket_ua[bucket][f"{ua_class}:{ua_label}"] += 1
            if reason != "-":
                bucket_reason[bucket][f"{status}:{reason}"] += 1
        elif ua_suspicious:
            bucket_ua[bucket][f"{ua_class}:{ua_label}"] += 1

        rt = _safe_float(parsed.get("rt"))
        if rt is not None and not _should_exclude_rt(uri):
            response_times[bucket].append(rt)

    rt_summary = {}
    for bucket, values in response_times.items():
        values = sorted(values)
        n = len(values)
        if not n:
            continue
        rt_summary[bucket] = {
            "avg": sum(values) / n,
            "p50": values[int(n * 0.5)],
            "p95": values[min(int(n * 0.95), n - 1)],
            "p99": values[min(int(n * 0.99), n - 1)],
            "count": n,
        }

    return {
        "bucket_counts": {k: dict(v) for k, v in bucket_counts.items()},
        "bucket_ip": {k: dict(v) for k, v in bucket_ip.items()},
        "bucket_uri": {k: dict(v) for k, v in bucket_uri.items()},
        "bucket_ua": {k: dict(v) for k, v in bucket_ua.items()},
        "bucket_ua_class": {k: dict(v) for k, v in bucket_ua_class.items()},
        "bucket_uri_all": {k: dict(v) for k, v in bucket_uri_all.items()},
        "bucket_ua_all": {k: dict(v) for k, v in bucket_ua_all.items()},
        "bucket_reason": {k: dict(v) for k, v in bucket_reason.items()},
        "rt_summary": rt_summary,
    }
