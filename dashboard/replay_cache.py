from __future__ import annotations

import hashlib
import os
import threading
import time
from typing import Any, Callable

try:  # pragma: no cover - optional runtime dependency
    import redis as redis_lib
except Exception:  # pragma: no cover - redis is optional for local/dev installs
    redis_lib = None


class ReplayCache:
    def __init__(
        self,
        *,
        namespace: str,
        backend: str = "auto",
        redis_url: str = "",
        fallback_to_memory: bool = True,
        max_items: int = 200000,
        default_ttl_sec: int = 310,
        redis_client_factory: Callable[[], Any] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.namespace = str(namespace or "").strip() or "replay"
        self.backend = str(backend or "auto").strip().lower() or "auto"
        self.redis_url = str(redis_url or "").strip()
        self.fallback_to_memory = bool(fallback_to_memory)
        self.max_items = max(1000, int(max_items))
        self.default_ttl_sec = max(1, int(default_ttl_sec))
        self._redis_client_factory = redis_client_factory
        self._clock = clock
        self._lock = threading.Lock()
        self._memory_cache: dict[str, float] = {}
        self._redis_client: Any | None = None

    def add(self, raw_key: str, *, ttl_sec: int | None = None, max_items: int | None = None) -> bool:
        ttl = self.default_ttl_sec if ttl_sec is None else max(1, int(ttl_sec))
        if self._should_use_redis():
            client = self._get_redis_client()
            if client is not None:
                try:
                    redis_key = f"{self.namespace}:{self._digest(raw_key)}"
                    return bool(client.set(redis_key, "1", nx=True, ex=ttl))
                except Exception:
                    self._redis_client = None
                    if not self.fallback_to_memory:
                        return False
            elif self.backend == "redis" and not self.fallback_to_memory:
                return False
        return self._memory_add(raw_key, ttl_sec=ttl, max_items=max_items)

    def _should_use_redis(self) -> bool:
        if self.backend == "memory":
            return False
        if self.backend in {"auto", "redis"}:
            return True
        return True

    def _get_redis_client(self) -> Any | None:
        if self._redis_client is not None:
            return self._redis_client
        if self._redis_client_factory is not None:
            client = self._redis_client_factory()
            self._redis_client = client
            return client
        if not self.redis_url or redis_lib is None:
            return None
        client = redis_lib.Redis.from_url(
            self.redis_url,
            decode_responses=True,
            health_check_interval=30,
            retry_on_timeout=True,
            socket_connect_timeout=1,
            socket_timeout=1,
        )
        self._redis_client = client
        return client

    def _memory_add(self, raw_key: str, *, ttl_sec: int, max_items: int | None = None) -> bool:
        key = self._digest(raw_key)
        cap = self.max_items if max_items is None else max(1000, int(max_items))
        now = self._clock()
        expires_at = now + float(ttl_sec)
        with self._lock:
            if len(self._memory_cache) >= cap:
                stale_keys = [item for item, exp in self._memory_cache.items() if exp <= now]
                for stale in stale_keys[: min(10000, len(stale_keys))]:
                    self._memory_cache.pop(stale, None)
                if len(self._memory_cache) >= cap:
                    oldest = sorted(self._memory_cache.items(), key=lambda kv: kv[1])[: max(1, cap // 20)]
                    for stale_key, _ in oldest:
                        self._memory_cache.pop(stale_key, None)
            current = self._memory_cache.get(key)
            if current and current > now:
                return False
            self._memory_cache[key] = expires_at
            return True

    @staticmethod
    def _digest(raw_key: str) -> str:
        return hashlib.sha256(str(raw_key).encode("utf-8")).hexdigest()


def replay_cache_from_env(
    *,
    namespace: str,
    backend_env: str,
    redis_url_env: str,
    fallback_env: str,
    max_items_env: str,
    ttl_env: str,
) -> ReplayCache:
    backend = str(os.getenv(backend_env, "auto") or "auto").strip().lower() or "auto"
    redis_url = str(os.getenv(redis_url_env, "") or "").strip()
    fallback_raw = str(os.getenv(fallback_env, "1") or "").strip().lower()
    max_items_raw = str(os.getenv(max_items_env, "200000") or "").strip()
    ttl_raw = str(os.getenv(ttl_env, "310") or "").strip()
    try:
        max_items = int(max_items_raw)
    except ValueError:
        max_items = 200000
    try:
        default_ttl_sec = int(ttl_raw)
    except ValueError:
        default_ttl_sec = 310
    return ReplayCache(
        namespace=namespace,
        backend=backend,
        redis_url=redis_url,
        fallback_to_memory=fallback_raw in {"1", "true", "on", "yes"},
        max_items=max_items,
        default_ttl_sec=default_ttl_sec,
    )
