"""Live detector and risk thresholds — the dashboard's console.

``.env`` supplies the starting values; once an administrator moves a fader,
the result is written to ``tuning.json`` (0600) and wins from then on. Every
change is sealed into the audit chain by the runtime.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from .storage import read_json, write_private_json

# name: (minimum, maximum)
LIMITS: dict[str, tuple[int, int]] = {
    "risk_throttle_threshold": (5, 100),
    "risk_block_threshold": (10, 100),
    "delete_burst_threshold": (1, 100),
    "rate_threshold": (10, 10_000),
    "half_life_minutes": (1, 240),
}


class TuningError(ValueError):
    pass


def validate(values: dict[str, int]) -> dict[str, int]:
    clean: dict[str, int] = {}
    for name, (low, high) in LIMITS.items():
        try:
            number = int(values[name])
        except (KeyError, TypeError, ValueError):
            raise TuningError(f"{name} must be a whole number") from None
        if not low <= number <= high:
            raise TuningError(f"{name} must be between {low} and {high}")
        clean[name] = number
    if clean["risk_throttle_threshold"] >= clean["risk_block_threshold"]:
        raise TuningError("the throttle threshold must be below the block threshold")
    return clean


class TuningStore:
    def __init__(self, path: str | Path, defaults: dict[str, int]) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        stored = read_json(self.path, default=None) or {}
        merged = {**defaults, **{k: v for k, v in stored.items() if k in LIMITS}}
        try:
            self._values = validate(merged)
            self.source = "tuning.json" if stored else ".env"
        except TuningError:
            self._values = validate(defaults)
            self.source = ".env"

    @property
    def values(self) -> dict[str, int]:
        return dict(self._values)

    def update(self, values: dict[str, Any]) -> list[str]:
        """Validate, persist, and return the names that changed."""
        with self._lock:
            new = validate({**self._values, **values})
            changed = sorted(k for k in new if new[k] != self._values[k])
            if changed:
                write_private_json(self.path, new)
                self._values = new
                self.source = "tuning.json"
            return changed
