"""Sliding-window rate limiting, keyed by client IP.

The key is the IP as uvicorn reports it, which honours ``X-Forwarded-For``
only from the proxies listed in ``FORWARDED_ALLOW_IPS``. Trusting that header
from anyone would let every caller choose its own bucket — and an unlimited
login endpoint is a password-guessing service.
"""

from __future__ import annotations

import re
import threading
import time
from collections import deque

_UNITS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}
_SPEC = re.compile(r"^\s*(\d+)\s*/\s*(second|minute|hour|day)s?\s*$")


def parse_rate(spec: str) -> tuple[int, float]:
    match = _SPEC.match(spec)
    if not match:
        raise ValueError(f"rate limit must look like '60/minute', got {spec!r}")
    return int(match.group(1)), float(_UNITS[match.group(2)])


class RateLimiter:
    def __init__(self, spec: str, max_keys: int = 50_000) -> None:
        self.limit, self.window = parse_rate(spec)
        self.max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str) -> tuple[bool, int]:
        """Record a request. Returns ``(allowed, retry_after_seconds)``."""
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                if len(self._hits) >= self.max_keys:
                    self._evict(cutoff)
                hits = self._hits[key] = deque()
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self.limit:
                return False, max(1, int(hits[0] + self.window - now) + 1)
            hits.append(now)
            return True, 0

    def _evict(self, cutoff: float) -> None:
        # Bounded memory under a flood of distinct IPs: drop idle keys first,
        # then the oldest if that was not enough.
        for key in [k for k, v in self._hits.items() if not v or v[-1] <= cutoff]:
            del self._hits[key]
        while len(self._hits) >= self.max_keys:
            del self._hits[next(iter(self._hits))]
