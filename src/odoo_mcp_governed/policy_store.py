"""The live, editable policy.

``.env`` supplies the *initial* policy. Once an administrator changes anything
in the panel, the result is written to ``policy.json`` (0600) and that file
wins from then on — including across restarts. Changes apply to the next call,
with no restart.

Applying a change is a single attribute swap on the engine, so a call already
in progress finishes under the policy it started with, and the next one sees
the new policy. There is no moment where a call sees half of each.
"""

from __future__ import annotations

import threading
from dataclasses import asdict, fields, replace
from pathlib import Path
from typing import Any

from .config import Settings
from .governance.policy import PolicyConfig
from .storage import read_json, write_private_json

_SET_FIELDS = {
    "allowed_models",
    "writable_models",
    "deletable_models",
    "denied_models",
    "disabled_tools",
    "forbidden_methods",
    "execute_method_allowlist",
    "sensitive_fields",
}
_EDITABLE = _SET_FIELDS | {"allow_execute_method", "max_records_per_call"}


def policy_from_settings(settings: Settings) -> PolicyConfig:
    return PolicyConfig(
        allowed_models=settings.allowed_models,
        writable_models=settings.writable_models,
        deletable_models=settings.deletable_models,
        denied_models=settings.denied_models,
        disabled_tools=settings.disabled_tools,
        forbidden_methods=settings.forbidden_methods,
        allow_execute_method=settings.allow_execute_method,
        execute_method_allowlist=settings.execute_method_allowlist,
        sensitive_fields=settings.sensitive_fields,
        max_records_per_call=settings.max_records_per_call,
    )


def _serialise(config: PolicyConfig) -> dict[str, Any]:
    data = asdict(config)
    return {
        key: sorted(value) if key in _SET_FIELDS else value
        for key, value in data.items()
        if key in _EDITABLE
    }


def _coerce(key: str, value: Any) -> Any:
    if key in _SET_FIELDS:
        if isinstance(value, str):
            value = value.replace("\n", ",").split(",")
        return frozenset(str(v).strip() for v in value if str(v).strip())
    if key == "allow_execute_method":
        return bool(value)
    if key == "max_records_per_call":
        number = int(value)
        if not 1 <= number <= 100_000:
            raise ValueError("max_records_per_call must be between 1 and 100000")
        return number
    raise KeyError(key)


class PolicyStore:
    def __init__(self, path: str | Path, initial: PolicyConfig) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        stored = read_json(self.path, default=None)
        if stored:
            known = {f.name for f in fields(PolicyConfig)}
            updates = {k: _coerce(k, v) for k, v in stored.items() if k in _EDITABLE & known}
            self._config = replace(initial, **updates)
            self.source = "policy.json"
        else:
            self._config = initial
            self.source = ".env"

    @property
    def config(self) -> PolicyConfig:
        return self._config

    def as_dict(self) -> dict[str, Any]:
        return _serialise(self._config)

    def update(self, changes: dict[str, Any]) -> tuple[PolicyConfig, list[str]]:
        """Apply and persist changes. Returns the new config and the keys that
        actually changed — which is what gets written to the audit log."""
        with self._lock:
            unknown = set(changes) - _EDITABLE
            if unknown:
                raise KeyError(f"not editable: {', '.join(sorted(unknown))}")
            coerced = {k: _coerce(k, v) for k, v in changes.items()}
            new = replace(self._config, **coerced)
            changed = sorted(k for k in coerced if getattr(new, k) != getattr(self._config, k))
            if changed:
                write_private_json(self.path, _serialise(new))
                self._config = new
                self.source = "policy.json"
            return self._config, changed
