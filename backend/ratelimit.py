"""Small in-process limiter for login attempts.

The limiter is intentionally simple: it protects a single API process and is
reset on restart. Deployments with multiple API replicas should put a Redis
backed limiter in front of this module; the interface is kept small so that
replacement stays local.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from .config import get_settings
from .errors import RateLimited


class LoginRateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._failures: dict[str, deque[float]] = {}

    def _prune(self, key: str, now: float, window: float) -> deque[float]:
        bucket = self._failures.setdefault(key, deque())
        while bucket and now - bucket[0] > window:
            bucket.popleft()
        return bucket

    def check(self, key: str) -> None:
        settings = get_settings()
        now = time.monotonic()
        with self._lock:
            bucket = self._prune(key, now, settings.login_window_seconds)
            if len(bucket) >= settings.login_max_attempts:
                retry_after = int(
                    settings.login_window_seconds - (now - bucket[0])
                )
                raise RateLimited(
                    "too many failed login attempts; retry in "
                    f"{max(retry_after, 1)} seconds"
                )

    def failure(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._prune(key, now, get_settings().login_window_seconds).append(now)

    def success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()


login_rate_limiter = LoginRateLimiter()
