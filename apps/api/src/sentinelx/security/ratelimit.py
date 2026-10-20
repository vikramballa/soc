"""In-process sliding-window rate limiter.

Adequate for a single API instance (the default deployment). Multi-instance deployments should put
rate limiting in the reverse proxy as well (documented in docs/deployment).
"""

from __future__ import annotations

import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._last_gc = time.monotonic()

    def allow(self, key: str, limit: int, window_s: float = 60.0) -> bool:
        now = time.monotonic()
        q = self._hits[key]
        while q and q[0] <= now - window_s:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        if now - self._last_gc > 300:
            self._gc(now, window_s)
        return True

    def _gc(self, now: float, window_s: float) -> None:
        for k in [k for k, q in self._hits.items() if not q or q[-1] <= now - window_s]:
            del self._hits[k]
        self._last_gc = now

    def reset(self) -> None:
        self._hits.clear()


limiter = RateLimiter()
