"""The agent registry: who may connect, with which token, and to what.

Every agent is a token subject. The registry adds what a bare JWT cannot say:

- **Revocation.** Each token has an id (``jti``). One token can be revoked
  without rotating ``JWT_SECRET`` and logging every other agent out; "revoke
  all" for an agent refuses every token it was issued until now, including
  ones minted before the registry existed.
- **Rules that narrow the policy.** An agent can be held to fewer models,
  fewer tools, read-only, a daily call quota and one pinned profile. A rule
  only ever takes away: nothing here can reach what the server policy denies.
- **Record scope.** A domain per model: the agent sees and changes only the
  records it matches — a WhatsApp bot sees its own customer, never the rest.
  Values written ``"{name}"`` are filled from the token's signed ``vars``
  claim, so one rule serves a token per customer. A scoped agent reaches only
  the models its scope names.

Stored as JSON (0600) next to the other state files.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..storage import read_json, write_private_json

VAR_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
PLACEHOLDER = re.compile(r"^\{([a-z][a-z0-9_]{0,31})\}$")
DOMAIN_OPERATORS = frozenset({
    "=", "!=", "<", "<=", ">", ">=", "in", "not in", "like", "ilike", "not like",
    "not ilike", "=like", "=ilike", "child_of", "parent_of",
})


class AgentError(ValueError):
    """An agent rule that cannot be accepted. The message is for the operator."""


class ScopeUnresolved(Exception):
    """A scope placeholder has no value in this token: refuse, never widen."""


def _models(value: Any) -> frozenset[str]:
    if isinstance(value, str):
        value = value.replace("\n", ",").split(",")
    return frozenset(str(v).strip() for v in value or () if str(v).strip())


def domain_problem(domain: Any, where: str) -> str | None:
    """What is wrong with a scope domain, or ``None``. Plain text built from
    the input only, so it is safe to show to the operator."""
    if not isinstance(domain, list):
        return f"scope for {where} must be a list of conditions"
    for item in domain:
        if item in ("&", "|", "!"):
            continue
        if (
            not isinstance(item, (list, tuple)) or len(item) != 3
            or not isinstance(item[0], str) or not item[0]
            or item[1] not in DOMAIN_OPERATORS
        ):
            return f"scope for {where}: {item!r} is not a [field, operator, value] condition"
    return None


def validate_domain(domain: Any, where: str) -> list:
    problem = domain_problem(domain, where)
    if problem:
        raise AgentError(problem)
    return [list(i) if isinstance(i, (list, tuple)) else i for i in domain]


def rule_problem(data: Mapping[str, Any]) -> str | None:
    """Why :meth:`AgentRule.from_dict` would refuse ``data``, or ``None`` —
    worked out without raising, so the panel can say it as is."""
    scope = data.get("scope") or {}
    if isinstance(scope, str):
        if not scope.strip():
            scope = {}
        else:
            try:
                scope = json.loads(scope)
            except ValueError:
                return 'scope is not valid JSON: {"model": [["field", "=", value]]}'
    if not isinstance(scope, dict):
        return 'scope must be an object: {"model": [[field, op, value]]}'
    for model, domain in scope.items():
        if problem := domain_problem(domain, str(model)):
            return problem
    quota = str(data.get("daily_quota") or "0").strip()
    if not quota.lstrip("-").isdigit():
        return "the daily quota must be a whole number"
    if int(quota) < 0:
        return "the daily quota cannot be negative"
    return None


def vars_problem(pairs: list[str]) -> str | None:
    for pair in pairs:
        name = pair.split("=", 1)[0].strip()
        if not VAR_NAME.match(name):
            return f"variable name {name!r}: use a-z, 0-9 and _"
    return None


@dataclass(frozen=True)
class AgentRule:
    name: str
    models: frozenset[str] = frozenset()
    """When non-empty, the only models this agent reaches (``*`` and exact
    names, as in the policy). Never more than the policy allows."""
    tools: frozenset[str] = frozenset()
    """When non-empty, the only tools this agent may call."""
    read_only: bool = False
    daily_quota: int = 0
    """Governed calls per UTC day; 0 means no quota."""
    profile: str = ""
    """When set, the agent always works on this profile, whatever its token
    or the panel says."""
    scope: Mapping[str, tuple] = field(default_factory=dict)
    """Model → domain. When non-empty, the agent reaches only these models and
    only the records each domain matches."""
    note: str = ""

    def validate(self) -> AgentRule:
        if self.daily_quota < 0:
            raise AgentError("the daily quota cannot be negative")
        for model, domain in self.scope.items():
            validate_domain(list(domain), model)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {"models": sorted(self.models), "tools": sorted(self.tools),
                "read_only": self.read_only, "daily_quota": self.daily_quota,
                "profile": self.profile, "scope": {m: list(d) for m, d in self.scope.items()},
                "note": self.note}

    @classmethod
    def from_dict(cls, name: str, data: Mapping[str, Any]) -> AgentRule:
        scope = data.get("scope") or {}
        if isinstance(scope, str):
            try:
                scope = json.loads(scope) if scope.strip() else {}
            except ValueError as exc:
                raise AgentError(f"scope is not valid JSON: {exc}") from None
        if not isinstance(scope, dict):
            raise AgentError('scope must be an object: {"model": [[field, op, value]]}')
        try:
            quota = int(data.get("daily_quota") or 0)
        except (TypeError, ValueError):
            raise AgentError("the daily quota must be a whole number") from None
        return cls(
            name=name, models=_models(data.get("models")), tools=_models(data.get("tools")),
            read_only=bool(data.get("read_only")), daily_quota=quota,
            profile=str(data.get("profile") or "").strip(),
            scope={str(m).strip(): tuple(validate_domain(d, str(m))) for m, d in scope.items()},
            note=str(data.get("note") or "")[:200],
        ).validate()


def resolve(domain: tuple | list, variables: Mapping[str, Any]) -> list:
    """The scope domain with ``"{name}"`` values taken from the token."""
    out: list = []
    for item in domain:
        if not isinstance(item, (list, tuple)):
            out.append(item)
            continue
        name, op, value = item
        if isinstance(value, str) and (m := PLACEHOLDER.match(value)):
            if m.group(1) not in variables:
                raise ScopeUnresolved(m.group(1))
            value = variables[m.group(1)]
        out.append([name, op, value])
    return out


def equalities(domain: list) -> dict[str, Any] | None:
    """``{field: value}`` when the domain is only ``field = value`` conditions
    joined by AND — the only scopes a new record can be made to satisfy."""
    fixed: dict[str, Any] = {}
    for item in domain:
        if item == "&":
            continue
        if not isinstance(item, list) or item[1] != "=" or "." in item[0] or item[0] == "id":
            return None
        fixed[item[0]] = item[2]
    return fixed


def scope_fields(domain: list) -> set[str]:
    return {i[0].split(".", 1)[0] for i in domain if isinstance(i, list)}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AgentStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._mtime: int | None = None
        self._data = self._load()

    def _fresh(self) -> None:
        """Pick up changes another process made — ``odoo-mcp-governed revoke``
        run next to the server takes effect on the next request, no restart.
        Called with the lock held."""
        try:
            mtime = self.path.stat().st_mtime_ns
        except FileNotFoundError:
            mtime = None
        if mtime != self._mtime:
            self._data = self._load()

    def _load(self) -> dict[str, Any]:
        try:
            self._mtime = self.path.stat().st_mtime_ns
        except FileNotFoundError:
            self._mtime = None
        data = read_json(self.path, default=None) or {}
        return {"agents": dict(data.get("agents") or {}), "tokens": dict(data.get("tokens") or {}),
                "revoked_before": dict(data.get("revoked_before") or {}),
                "unregistered_before": dict(data.get("unregistered_before") or {}),
                "archived": dict(data.get("archived") or {})}

    def _save(self) -> None:
        write_private_json(self.path, self._data)
        self._mtime = self.path.stat().st_mtime_ns

    # -- rules -------------------------------------------------------------

    def rules(self) -> dict[str, AgentRule]:
        with self._lock:
            self._fresh()
            agents = dict(self._data["agents"])
        out = {}
        for name, data in agents.items():
            try:
                out[name] = AgentRule.from_dict(name, data)
            except AgentError:
                # A damaged rule must not open the agent up: it is held to
                # nothing at all until an operator fixes it.
                out[name] = AgentRule(name=name, tools=frozenset({"-"}))
        return out

    def rule(self, name: str) -> AgentRule | None:
        return self.rules().get(name)

    def save_rule(self, rule: AgentRule) -> None:
        rule.validate()
        with self._lock:
            self._fresh()
            entry = rule.to_dict() | {"created_at": self._data["agents"].get(
                rule.name, {}).get("created_at") or _now()}
            self._data["agents"][rule.name] = entry
            self._save()

    def delete_rule(self, name: str) -> bool:
        with self._lock:
            self._fresh()
            gone = self._data["agents"].pop(name, None) is not None
            if gone:
                self._save()
            return gone

    # -- tokens ------------------------------------------------------------

    def register(self, issued: Mapping[str, Any], *, label: str = "",
                 variables: Mapping[str, Any] | None = None) -> None:
        with self._lock:
            self._fresh()
            self._data["tokens"][issued["jti"]] = {
                "actor": issued["actor"], "profile": issued.get("profile"),
                "issued_at": issued["issued_at"], "expires_at": issued["expires_at"],
                "label": label[:80], "vars": dict(variables or {}), "revoked_at": None,
            }
            self._prune()
            self._save()

    def tokens(self, actor: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            self._fresh()
            rows = [{"jti": j, **t} for j, t in self._data["tokens"].items()
                    if actor is None or t["actor"] == actor]
        return sorted(rows, key=lambda r: r["issued_at"], reverse=True)

    def revoke(self, jti: str) -> bool:
        with self._lock:
            self._fresh()
            token = self._data["tokens"].get(jti)
            if token is None or token.get("revoked_at"):
                return False
            token["revoked_at"] = _now()
            self._save()
            return True

    def archived(self) -> dict[str, str]:
        """Archived agents and when: hidden from the panel lists, their tokens
        revoked. The audit log keeps their history — it cannot be deleted."""
        with self._lock:
            self._fresh()
            return dict(self._data.get("archived") or {})

    def set_archived(self, name: str, archived: bool) -> None:
        with self._lock:
            self._fresh()
            box = self._data.setdefault("archived", {})
            if archived:
                box[name] = _now()
            else:
                box.pop(name, None)
            self._save()

    def revoke_unregistered(self, actor: str) -> None:
        """Refuse every token of ``actor`` that is not in the registry and was
        issued until now — tokens from before the registry — while the
        registered ones keep working."""
        with self._lock:
            self._fresh()
            now = int(datetime.now(timezone.utc).timestamp())
            self._data.setdefault("unregistered_before", {})[actor] = now
            self._save()

    def revoke_all(self, actor: str) -> int:
        """Refuse every token issued to ``actor`` until now, registered or not."""
        with self._lock:
            self._fresh()
            now = datetime.now(timezone.utc)
            self._data["revoked_before"][actor] = int(now.timestamp())
            count = 0
            for token in self._data["tokens"].values():
                if token["actor"] == actor and not token.get("revoked_at"):
                    token["revoked_at"] = now.isoformat(timespec="seconds")
                    count += 1
            self._save()
            return count

    def refusal(self, claims: Mapping[str, Any], *, require_registered: bool) -> str | None:
        """Why this verified token may not be used, or ``None`` if it may."""
        jti, sub = claims.get("jti"), claims.get("sub")
        with self._lock:
            self._fresh()
            token = self._data["tokens"].get(jti) if isinstance(jti, str) else None
            cutoff = self._data["revoked_before"].get(sub)
            loose_cutoff = self._data.get("unregistered_before", {}).get(sub)
            archived = sub in (self._data.get("archived") or {})
        if archived:
            # Checked at the door, not only by the policy's block list: two
            # independent locks, so unblocking by hand does not reopen it.
            return "agent archived"
        if token is not None and token.get("revoked_at"):
            return "token revoked"
        if token is not None and token.get("actor") != sub:
            return "token registry mismatch"
        if cutoff is not None and int(claims.get("iat", 0)) <= int(cutoff):
            return "token revoked (all tokens of this agent)"
        if token is None and loose_cutoff is not None and int(
                claims.get("iat", 0)) <= int(loose_cutoff):
            return "token revoked (unregistered tokens of this agent)"
        if token is None and require_registered:
            return "token not registered"
        return None

    def _prune(self) -> None:
        # Expired tokens can never be used again; keep the registry small.
        now = datetime.now(timezone.utc)
        for jti in [j for j, t in self._data["tokens"].items()
                    if datetime.fromisoformat(t["expires_at"]) < now]:
            del self._data["tokens"][jti]


def parse_vars(pairs: list[str] | Mapping[str, Any] | None) -> dict[str, Any]:
    """Token variables from ``name=value`` strings; digits become integers."""
    if not pairs:
        return {}
    items = pairs.items() if isinstance(pairs, Mapping) else (
        p.split("=", 1) if "=" in p else (p, "") for p in pairs)
    out: dict[str, Any] = {}
    for name, value in items:
        name = str(name).strip()
        if not VAR_NAME.match(name):
            raise AgentError(f"variable name {name!r}: use a-z, 0-9 and _")
        if isinstance(value, str):
            value = value.strip()
            value = int(value) if value.isdigit() else value[:120]
        if not isinstance(value, (int, str)) or isinstance(value, bool):
            raise AgentError(f"variable {name!r} must be a number or text")
        out[name] = value
    return out
