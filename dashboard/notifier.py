from __future__ import annotations

import json
import urllib.error
import urllib.request


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        return None


def _build_payload(channel_type: str, event: dict) -> dict:
    if channel_type == "discord":
        return {
            "content": f"[{event.get('severity', 'info').upper()}] {event.get('title', 'IPS Event')}\n{event.get('message', '')}".strip()
        }
    if channel_type == "slack":
        return {
            "text": f"[{event.get('severity', 'info').upper()}] {event.get('title', 'IPS Event')}\n{event.get('message', '')}".strip()
        }
    return event


def send_webhook(channel_type: str, webhook_url: str, event: dict, secret_token: str = "") -> tuple[bool, str]:
    body = json.dumps(_build_payload(channel_type, event), ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json; charset=utf-8"}
    if secret_token:
        headers["X-IPS-Webhook-Token"] = secret_token
    req = urllib.request.Request(webhook_url, data=body, headers=headers, method="POST")
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=5) as resp:
            code = getattr(resp, "status", 200)
            if 200 <= int(code) < 300:
                return True, f"http_{code}"
            return False, f"http_{code}"
    except urllib.error.HTTPError as exc:
        return False, f"http_{exc.code}"
    except Exception as exc:
        return False, f"error:{type(exc).__name__}"
