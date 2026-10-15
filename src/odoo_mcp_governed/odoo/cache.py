"""A TTL + LRU cache for Odoo metadata.

Only schema-level answers are cached — field definitions, model lists, report
lookups — never record data. Caching records would mean an agent could be
served a stale invoice after a human corrected it, and nothing in the audit
log would show that the answer did not come from Odoo.

Keys always include the profile name, and the whole cache is cleared on a
profile switch anyway: two instances can have the same model with different
fields, and answering one with the other's schema is a silent, nasty bug.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Hashable
from typing import Any, TypeVar

T = TypeVar("T")


class TTLCache:
    def __init__(self, ttl: float = 300, max_size: int = 1000, enabled: bool = True) -> None:
        self.ttl = ttl
        self.max_size = max_size
        self.enabled = enabled
        self._data: OrderedDict[Hashable, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def get_or_set(self, key: Hashable, factory: Callable[[], T]) -> T:
        if not self.enabled:
            return factory()
        now = time.monotonic()
        with self._lock:
            entry = self._data.get(key)
            if entry is not None and entry[0] > now:
                self._data.move_to_end(key)
                self.hits += 1
                return entry[1]
            self.misses += 1
        # Compute outside the lock: a slow Odoo call must not block every other
        # cache reader. Two concurrent misses may both compute; that is cheaper
        # than serialising all metadata lookups behind one network call.
        value = factory()
        with self._lock:
            self._data[key] = (now + self.ttl, value)
            self._data.move_to_end(key)
            while len(self._data) > self.max_size:
                self._data.popitem(last=False)
                self.evictions += 1
        return value

    def clear(self) -> int:
        with self._lock:
            count = len(self._data)
            self._data.clear()
            return count

    def stats(self) -> dict[str, Any]:
        with self._lock:
            total = self.hits + self.misses
            return {
                "enabled": self.enabled,
                "size": len(self._data),
                "max_size": self.max_size,
                "ttl_seconds": self.ttl,
                "hits": self.hits,
                "misses": self.misses,
                "evictions": self.evictions,
                "hit_rate": round(self.hits / total, 3) if total else 0.0,
            }
