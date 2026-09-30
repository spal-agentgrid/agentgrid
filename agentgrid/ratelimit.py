"""In-process token buckets (V1 moves this to the edge/KV)."""
from __future__ import annotations

import threading
import time


class RateLimiter:
    def __init__(self):
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, per_minute: int) -> tuple[bool, float]:
        """Per-minute bucket (burst = per_minute). Returns (allowed, retry_after_seconds)."""
        return self.allow_window(key, per_minute, 60.0)

    def allow_window(self, key: str, limit: int, window_s: float) -> tuple[bool, float]:
        """Token bucket holding at most `limit` tokens, refilled at limit/window_s per second."""
        now = time.monotonic()
        rate = limit / window_s
        with self._lock:
            if len(self._buckets) > 100_000:  # bound memory under abuse
                self._buckets.clear()
            tokens, last = self._buckets.get(key, (float(limit), now))
            tokens = min(float(limit), tokens + (now - last) * rate)
            if tokens >= 1:
                self._buckets[key] = (tokens - 1, now)
                return True, 0.0
            self._buckets[key] = (tokens, now)
            return False, (1 - tokens) / rate
