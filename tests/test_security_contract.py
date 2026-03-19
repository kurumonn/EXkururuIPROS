from __future__ import annotations

import importlib

from dashboard.replay_cache import ReplayCache


class _FakeRedis:
    def __init__(self, clock):
        self._clock = clock
        self._values: dict[str, float] = {}

    def set(self, key, value, nx=False, ex=None):
        now = float(self._clock())
        current = self._values.get(key)
        if nx and current is not None and current > now:
            return False
        self._values[key] = now + float(ex or 0)
        return True


class _BrokenRedis:
    def set(self, key, value, nx=False, ex=None):  # pragma: no cover - exercised by the test
        raise RuntimeError("redis unavailable")


def test_signature_v2_uses_nonce_and_body() -> None:
    security = importlib.import_module("dashboard.security")
    sig1 = security.expected_sensor_signature_v2("secret", "1700000000", b"{}", nonce="nonce-1")
    sig2 = security.expected_sensor_signature_v2("secret", "1700000000", b"{}", nonce="nonce-2")
    sig3 = security.expected_sensor_signature_v2("secret", "1700000000", b"{\"x\":1}", nonce="nonce-1")
    assert sig1 != sig2
    assert sig1 != sig3


def test_replay_guard_rejects_duplicate_key(monkeypatch) -> None:
    security = importlib.import_module("dashboard.security")
    clock = lambda: 1000.0
    fake_redis = _FakeRedis(clock)
    cache = ReplayCache(
        namespace="ips",
        backend="redis",
        redis_url="redis://example.invalid/0",
        fallback_to_memory=True,
        max_items=10,
        default_ttl_sec=60,
        redis_client_factory=lambda: fake_redis,
        clock=clock,
    )
    monkeypatch.setattr(security, "_REPLAY_GUARD", cache, raising=False)
    assert security.replay_guard_add("workspace:sensor:path:ts:sig:nonce", ttl_sec=60, max_items=10) is True
    assert security.replay_guard_add("workspace:sensor:path:ts:sig:nonce", ttl_sec=60, max_items=10) is False


def test_replay_guard_rejects_duplicate_across_cache_instances(monkeypatch) -> None:
    security = importlib.import_module("dashboard.security")
    clock = lambda: 1000.0
    fake_redis = _FakeRedis(clock)
    cache_a = ReplayCache(
        namespace="ips",
        backend="redis",
        redis_url="redis://example.invalid/0",
        fallback_to_memory=True,
        max_items=10,
        default_ttl_sec=60,
        redis_client_factory=lambda: fake_redis,
        clock=clock,
    )
    cache_b = ReplayCache(
        namespace="ips",
        backend="redis",
        redis_url="redis://example.invalid/0",
        fallback_to_memory=True,
        max_items=10,
        default_ttl_sec=60,
        redis_client_factory=lambda: fake_redis,
        clock=clock,
    )
    monkeypatch.setattr(security, "_REPLAY_GUARD", cache_a, raising=False)
    assert security.replay_guard_add("workspace:sensor:path:ts:sig:nonce", ttl_sec=60, max_items=10) is True
    monkeypatch.setattr(security, "_REPLAY_GUARD", cache_b, raising=False)
    assert security.replay_guard_add("workspace:sensor:path:ts:sig:nonce", ttl_sec=60, max_items=10) is False


def test_replay_guard_falls_back_to_memory_when_redis_errors() -> None:
    clock = lambda: 1000.0
    cache = ReplayCache(
        namespace="ips",
        backend="redis",
        redis_url="redis://example.invalid/0",
        fallback_to_memory=True,
        max_items=10,
        default_ttl_sec=60,
        redis_client_factory=lambda: _BrokenRedis(),
        clock=clock,
    )
    assert cache.add("workspace:sensor:path:ts:sig:nonce", ttl_sec=60) is True
    assert cache.add("workspace:sensor:path:ts:sig:nonce", ttl_sec=60) is False


def test_validate_nonce_enforces_format() -> None:
    security = importlib.import_module("dashboard.security")
    assert security.validate_nonce("nonce-abc_123", required=True) == "nonce-abc_123"
    try:
        security.validate_nonce("bad nonce", required=True)
    except ValueError as exc:
        assert "invalid" in str(exc)
    else:
        raise AssertionError("expected ValueError")
