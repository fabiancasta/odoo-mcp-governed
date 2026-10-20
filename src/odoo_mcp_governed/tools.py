"""The 19 MCP tools.

Every tool follows the same shape: parse arguments, describe the call as a
:class:`~.governance.ToolCall`, run the Odoo work inside
``engine.guard(call)``, report how many records were touched. There is no
other route to the Odoo client — tools receive a :class:`ToolContext`, and the
context only exposes Odoo through the guard.

What a tool reports as ``fields_touched`` matters more than it looks. It is
what the sensitive-field rule checks, so it includes field names referenced in
a search *domain*, not only the fields read or written. Otherwise
``search_count([("password", "=", guess)])`` would be a perfectly legal
password oracle that never "reads" the password field.
"""

from __future__ import annotations

import base64
import binascii
import http.cookiejar
import json
import logging
import ssl
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .governance import GuardedCall, Operation, ToolCall, digest_args
from .governance.agents import ScopeUnresolved, equalities, resolve, scope_fields
from .governance.policy import (
    ALWAYS_DENIED,
    ATTACHMENT_CONTENT_FIELDS,
    ATTACHMENT_MODEL,
    CONFIG_PARAMETER_MODEL,
    OUTSIDE_SCOPE,
    WILDCARD,
    covers,
    is_sensitive,
)
from .runtime import Runtime, Snapshot

log = logging.getLogger(__name__)

DEFAULT_SEARCH_LIMIT = 100
DEFAULT_FIELD_ATTRIBUTES = [
    "string", "type", "required", "readonly", "relation", "selection", "help",
]


class ToolInputError(ValueError):
    """The arguments were malformed. The message is shown to the agent."""


@dataclass
class ToolContext:
    runtime: Runtime
    actor: str
    snapshot: Snapshot
    tool: str
    arguments: dict[str, Any]
    guarded: bool = False
    variables: dict[str, Any] = field(default_factory=dict)
    """The token's signed ``vars`` claim, filling the agent's scope."""

    def guard(
        self,
        *,
        operation: Operation,
        model: str | None = None,
        method: str | None = None,
        fields: Iterable[str] = (),
        count: int | None = None,
    ):
        self.guarded = True
        profile = self.snapshot.profile
        if model and profile.environment == "production" and WILDCARD in self.policy.allowed_models:
            # Only asked when it matters: a production profile reached through
            # a '*' allowlist. Unknown counts as privileged — fail closed.
            access = self.snapshot.settings_access()
            self.runtime.note_privilege(profile.name, access is not False)
        call = ToolCall(
            actor=self.actor,
            profile=self.snapshot.profile.name,
            tool=self.tool,
            operation=operation,
            model=model,
            method=method,
            fields_touched=tuple(sorted(set(fields))),
            record_count=count,
            arg_digest=digest_args(self.arguments),
            model_transient=bool(model) and self.snapshot.is_transient(model),
        )
        return self.runtime.engine.guard(call)

    def odoo(self, model: str, method: str, args: list | None = None, kwargs: dict | None = None):
        return self.snapshot.client.execute(model, method, args, kwargs)

    # -- record scope ------------------------------------------------------

    def scope(self, model: str | None) -> list | None:
        """The agent's record scope on ``model``, or ``None`` if it has none.

        A model the scope does not name is refused by policy; only the models
        it names get here. A placeholder the token does not fill matches no
        record at all — a scope is never widened for want of a value.
        """
        rule = self.policy.agent_rules.get(self.actor)
        if rule is None or not rule.scope or not model or model not in rule.scope:
            return None
        try:
            return resolve(rule.scope[model], self.variables)
        except ScopeUnresolved as missing:
            log.warning("agent %s: scope variable %r missing from its token", self.actor,
                        str(missing))
            return [["id", "=", 0]]

    def scoped_domain(self, model: str, domain: list) -> list:
        """``domain`` AND the agent's scope, each normalised first so that an
        unbalanced ``|`` from the agent can never swallow a scope condition."""
        scope = self.scope(model)
        if scope is None:
            return domain
        if not domain:
            return normalize_domain(scope)
        return ["&", *normalize_domain(scope), *normalize_domain(domain)]

    def outside_scope(
        self, model: str | None, ids: list[int] | None = None, *,
        values: dict[str, Any] | None = None, creating: bool = False,
        any_call: bool = False,
    ) -> set[str]:
        """``{OUTSIDE_SCOPE}`` when the call reaches records outside the
        agent's scope; policy then refuses it. On create, scope fields the
        agent left out are filled in ``values``."""
        scope = self.scope(model)
        if scope is None:
            return set()
        if any_call:
            return {OUTSIDE_SCOPE}
        if ids is not None:
            wanted = set(ids)
            if not wanted:
                return {OUTSIDE_SCOPE}
            found = self.odoo(model, "search_count",
                              [self.scoped_domain(model, [["id", "in", sorted(wanted)]])])
            if found != len(wanted):
                return {OUTSIDE_SCOPE}
        if values is not None:
            fixed = equalities(scope)
            if creating:
                if fixed is None:
                    return {OUTSIDE_SCOPE}
                for name, value in fixed.items():
                    if values.setdefault(name, value) != value:
                        return {OUTSIDE_SCOPE}
            else:
                touched = scope_fields(scope) & set(values)
                if touched and (fixed is None or any(values[f] != fixed.get(f) for f in touched)):
                    return {OUTSIDE_SCOPE}
        return set()

    # -- change journal ----------------------------------------------------

    def snapshot_before(
        self, model: str, ids: list[int], fields: Iterable[str] | None = None
    ) -> dict[int, dict[str, Any]]:
        """Current values of ``ids``, for the change journal. Empty when the
        journal is off. ``fields=None`` means every stored, non-binary field —
        what a delete would lose."""
        if self.runtime.journal is None or not ids:
            return {}
        wanted = set(fields) if fields is not None else None
        try:
            if wanted is None:
                defs = _fields_get(self, model, ["type", "store"])
                names = [
                    n for n, meta in defs.items()
                    if meta.get("store") and meta.get("type") != "binary"
                ] if isinstance(defs, dict) else []
                kwargs = {"fields": names} if names else {}
            else:
                kwargs = {"fields": sorted(wanted)}
            rows = self.odoo(model, "read", [ids], kwargs)
        except Exception:  # noqa: BLE001 - the journal must not block the change
            log.exception("change journal: could not read %s %s before the change", model, ids)
            return {}
        result: dict[int, dict[str, Any]] = {}
        for row in self.redact(rows if isinstance(rows, list) else [], model):
            if not isinstance(row, dict) or not isinstance(row.get("id"), int):
                continue
            values = {k: v for k, v in row.items() if k != "id"}
            if wanted is not None:
                values = {k: v for k, v in values.items() if k in wanted}
            result[row["id"]] = values
        return result

    def journal(
        self,
        guarded: GuardedCall,
        model: str,
        operation: str,
        changes: dict[int, tuple[dict[str, Any] | None, dict[str, Any] | None]],
    ) -> None:
        """Write ``changes`` once the call's audit event is sealed."""
        journal = self.runtime.journal
        if journal is None or not changes:
            return
        guarded.on_recorded.append(
            lambda event: journal.add(
                audit_seq=event.seq, ts=event.ts, actor=event.actor, profile=event.profile,
                model=model, operation=operation, changes=changes,
            )
        )

    def cached(self, key: tuple, factory: Callable[[], Any]) -> Any:
        return self.runtime.cache.get_or_set((self.snapshot.profile.name, *key), factory)

    @property
    def policy(self):
        return self.runtime.engine.policy.config

    def redact(self, records: Any, model: str | None = None) -> Any:
        """Drop credential-like keys from returned records, whatever was asked.

        The policy refuses calls that *name* a sensitive field. This covers the
        other case: an agent that asks for all fields and would receive one.
        On ir.attachment the file content goes too, for the same reason.
        """
        patterns = self.policy.sensitive_fields
        content = ATTACHMENT_CONTENT_FIELDS if model == ATTACHMENT_MODEL else frozenset()
        clean = _strip(records, lambda key: key in content or is_sensitive(key, patterns))
        if model == CONFIG_PARAMETER_MODEL:
            # Reachable only from a configurator profile: settings are its job,
            # secrets are not. A parameter whose key looks like a credential
            # (database.secret, *.access_key, *_token…) comes back without its
            # value.
            for row in clean if isinstance(clean, list) else [clean]:
                if isinstance(row, dict) and is_sensitive(
                    str(row.get("key", "")).replace(".", "_"), patterns
                ):
                    row["value"] = None
        return clean


def _strip(records: Any, hidden: Callable[[str], bool]) -> Any:
    """Drop hidden keys at every depth: web_read and onchange return related
    records nested inside the parent, and those carry fields too."""
    if isinstance(records, list):
        return [_strip(r, hidden) for r in records]
    if isinstance(records, dict):
        return {k: _strip(v, hidden) for k, v in records.items()
                if not (isinstance(k, str) and hidden(k))}
    return records


def collect_field_names(value: Any) -> set[str]:
    """Every field name an argument structure can carry, at any depth.

    Dict keys (value dicts, and the nested ``specification`` of web_read /
    web_search_read / onchange), lists of strings (field lists), and each hop
    of a dotted path. Iterative, so depth is bounded by the request's own
    nesting limit rather than Python's recursion limit.
    """
    found: set[str] = set()
    stack = [value]

    def add(name: str) -> None:
        found.add(name)
        found.update(part for part in name.split(".") if part)

    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, inner in item.items():
                if isinstance(key, str):
                    add(key)
                stack.append(inner)
        elif isinstance(item, (list, tuple)):
            if item and all(isinstance(i, str) for i in item):
                for name in item:
                    add(name)
            else:
                stack.extend(item)
    return found


def _value_oracle(model: str, filtered_on: set[str]) -> set[str]:
    """Mark a filter or sort on a system parameter's value: on a secret one it
    would be a guessing oracle even though the value itself is hidden."""
    return {"domain:value"} if model == CONFIG_PARAMETER_MODEL and "value" in filtered_on else set()


def order_fields(order: str | None) -> set[str]:
    """Field names in an ``order`` clause — sorting by a field leaks it too."""
    names: set[str] = set()
    for part in (order or "").split(","):
        token = part.strip().split(" ", 1)[0]
        if token:
            names.add(token)
            names.update(seg for seg in token.split(".") if seg)
    return names


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    operation: Operation
    properties: dict[str, Any]
    required: tuple[str, ...]
    handler: Callable[[ToolContext], Any]
    annotations: dict[str, Any] = field(default_factory=dict)

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": self.properties,
                "required": list(self.required),
                "additionalProperties": False,
            },
            "annotations": self.annotations,
        }


# --- argument helpers ------------------------------------------------------


def _arg_str(ctx: ToolContext, name: str, *, required: bool = True, default: str = "") -> str:
    value = ctx.arguments.get(name, default)
    if value in (None, "") and not required:
        return default
    if not isinstance(value, str) or not value.strip():
        raise ToolInputError(f"'{name}' must be a non-empty string")
    return value.strip()


def _arg_int(ctx: ToolContext, name: str, default: int, *, minimum: int = 0) -> int:
    value = ctx.arguments.get(name, default)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ToolInputError(f"'{name}' must be an integer >= {minimum}")
    return value


def _arg_dict(ctx: ToolContext, name: str, *, required: bool = True) -> dict[str, Any]:
    value = ctx.arguments.get(name)
    if value is None and not required:
        return {}
    if not isinstance(value, dict):
        raise ToolInputError(f"'{name}' must be an object")
    return value


def _arg_str_list(ctx: ToolContext, name: str) -> list[str] | None:
    value = ctx.arguments.get(name)
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ToolInputError(f"'{name}' must be a list of strings")
    return value


def _arg_ids(ctx: ToolContext) -> list[int]:
    """Accept ``record_id`` (one) or ``ids`` (many), never neither."""
    if "ids" in ctx.arguments and ctx.arguments["ids"] is not None:
        ids = ctx.arguments["ids"]
        if (
            not isinstance(ids, list)
            or not ids
            or not all(isinstance(i, int) and not isinstance(i, bool) and i > 0 for i in ids)
        ):
            raise ToolInputError("'ids' must be a non-empty list of positive integers")
        return list(dict.fromkeys(ids))
    record_id = ctx.arguments.get("record_id")
    if isinstance(record_id, bool) or not isinstance(record_id, int) or record_id <= 0:
        raise ToolInputError("provide 'record_id' (positive integer) or 'ids' (list)")
    return [record_id]


_ARITY = {"!": 1, "&": 2, "|": 2}


def normalize_domain(domain: list) -> list:
    """One complete prefix expression, as Odoo normalises it: implicit ANDs
    made explicit. An operator without enough operands is refused here."""
    result: list = []
    expected = 1
    for token in domain:
        if expected == 0:
            result[0:0] = ["&"]
            expected = 1
        if isinstance(token, str):
            if token not in _ARITY:
                raise ToolInputError(f"domain operator {token!r} is not '&', '|' or '!'")
            expected += _ARITY[token] - 1
        else:
            expected -= 1
        result.append(token)
    if expected != 0:
        raise ToolInputError("domain is incomplete: an operator is missing its conditions")
    return result


def _arg_domain(ctx: ToolContext) -> list[Any]:
    domain = ctx.arguments.get("domain", [])
    if domain is None:
        return []
    if not isinstance(domain, list):
        raise ToolInputError("'domain' must be a list, e.g. [[\"is_company\", \"=\", true]]")
    return domain


def domain_fields(domain: Any) -> set[str]:
    """Every field name a domain refers to, including each hop of a path.

    ``partner_id.user_ids.password`` yields all three segments, so the
    sensitive-field rule sees ``password`` however deep it is nested.
    """
    found: set[str] = set()
    if not isinstance(domain, (list, tuple)):
        return found
    for leaf in domain:
        if isinstance(leaf, (list, tuple)) and len(leaf) == 3 and isinstance(leaf[0], str):
            path = leaf[0]
            found.add(path)
            found.update(part for part in path.split(".") if part)
            if isinstance(leaf[2], (list, tuple)):
                found |= domain_fields(leaf[2])
        elif isinstance(leaf, (list, tuple)):
            found |= domain_fields(leaf)
    return found


def _limit(ctx: ToolContext, default: int = DEFAULT_SEARCH_LIMIT) -> int:
    requested = _arg_int(ctx, "limit", min(default, ctx.policy.max_records_per_call), minimum=1)
    # Requests above the ceiling are passed through as-is so policy can refuse
    # them with a clear reason, rather than silently truncating and letting the
    # agent believe it saw everything.
    return requested


def _decode_base64(data: str, max_bytes: int) -> bytes:
    approx = len(data) * 3 // 4
    if approx > max_bytes * 1.01 + 4:
        raise ToolInputError(f"attachment exceeds the {max_bytes // (1024 * 1024)} MB limit")
    try:
        raw = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        raise ToolInputError("'data_base64' is not valid base64") from None
    if len(raw) > max_bytes:
        raise ToolInputError(f"attachment exceeds the {max_bytes // (1024 * 1024)} MB limit")
    return raw


def _max_attachment_bytes(ctx: ToolContext) -> int:
    return int(ctx.runtime.settings.max_attachment_mb * 1024 * 1024)


def _done(guarded: GuardedCall, count: int | None, result: Any) -> Any:
    guarded.affected(count)
    return result


# --- record tools ----------------------------------------------------------

MODEL = {"type": "string", "description": "Technical model name, e.g. 'res.partner'"}
RECORD_ID = {"type": "integer", "description": "One record id"}
IDS = {"type": "array", "items": {"type": "integer"}, "description": "Several record ids"}
FIELDS = {
    "type": "array",
    "items": {"type": "string"},
    "description": "Fields to return. Omit for all readable fields — prefer naming them.",
}
# "items" is spelled out even where any value goes: MCP accepts arrays without
# it, but OpenAI-compatible tool APIs (Groq, n8n's agents, ...) reject them.
DOMAIN = {
    "type": "array",
    "items": {},
    "description": "Odoo search domain, e.g. [[\"customer_rank\", \">\", 0]]",
}


def _read_fields(ctx: ToolContext, model: str, fields: list[str] | None) -> list[str] | None:
    """The field list to ask Odoo for. ``None`` means all of them.

    When the agent names no fields, binary fields are left out. A contact
    read that way used to come back with ten base64 copies of its photo
    (``image_1920`` … ``avatar_128``): tokens the agent pays for and never
    uses. Named binary fields are still returned. On ir.attachment this also
    keeps the file content out — Odoo cannot even serialise ``raw``, and
    answers HTTP 500 when asked for it.
    """
    if fields:
        return fields
    defs = _fields_get(ctx, model, ["type"])
    if not isinstance(defs, dict):
        return fields
    content = ATTACHMENT_CONTENT_FIELDS if model == ATTACHMENT_MODEL else frozenset()
    return sorted(
        n for n, meta in defs.items()
        if n not in content and meta.get("type") != "binary"
    ) or None


def get_record(ctx: ToolContext) -> Any:
    model = _arg_str(ctx, "model")
    ids = _arg_ids(ctx)
    fields = _arg_str_list(ctx, "fields")
    with ctx.guard(
        operation=Operation.READ, model=model,
        fields={*(fields or ()), *ctx.outside_scope(model, ids)}, count=len(ids)
    ) as g:
        wanted = _read_fields(ctx, model, fields)
        kwargs = {"fields": wanted} if wanted else {}
        records = ctx.redact(ctx.odoo(model, "read", [ids], kwargs), model)
        missing = sorted(set(ids) - {r["id"] for r in records})
        result: dict[str, Any] = {"records": records}
        if missing:
            result["missing_ids"] = missing
        return _done(g, len(records), result)


def search_records(ctx: ToolContext) -> Any:
    model = _arg_str(ctx, "model")
    domain = _arg_domain(ctx)
    fields = _arg_str_list(ctx, "fields")
    limit = _limit(ctx)
    offset = _arg_int(ctx, "offset", 0)
    order = _arg_str(ctx, "order", required=False) or None
    touched = set(fields or ()) | domain_fields(domain) | order_fields(order)
    touched |= _value_oracle(model, domain_fields(domain) | order_fields(order))
    with ctx.guard(operation=Operation.READ, model=model, fields=touched, count=limit) as g:
        domain = ctx.scoped_domain(model, domain)
        kwargs: dict[str, Any] = {"limit": limit, "offset": offset}
        if wanted := _read_fields(ctx, model, fields):
            kwargs["fields"] = wanted
        if order:
            kwargs["order"] = order
        records = ctx.redact(ctx.odoo(model, "search_read", [domain], kwargs), model)
        return _done(
            g,
            len(records),
            {"count": len(records), "limit": limit, "offset": offset, "records": records},
        )


def create_record(ctx: ToolContext) -> Any:
    model = _arg_str(ctx, "model")
    values = _arg_dict(ctx, "values")
    if not values:
        raise ToolInputError("'values' must not be empty")
    values = dict(values)
    outside = ctx.outside_scope(model, values=values, creating=True)
    with ctx.guard(operation=Operation.CREATE, model=model, fields={*values, *outside},
                   count=1) as g:
        created = ctx.odoo(model, "create", [values])
        new_id = created[0] if isinstance(created, list) else created
        if isinstance(new_id, int):
            g.touched([new_id])
            ctx.journal(g, model, "create", {new_id: (None, ctx.redact(values, model))})
        return _done(g, 1, {"id": new_id, "model": model})


def update_record(ctx: ToolContext) -> Any:
    model = _arg_str(ctx, "model")
    ids = _arg_ids(ctx)
    values = _arg_dict(ctx, "values")
    if not values:
        raise ToolInputError("'values' must not be empty")
    outside = ctx.outside_scope(model, ids, values=values)
    with ctx.guard(
        operation=Operation.WRITE, model=model, fields={*values, *outside}, count=len(ids)
    ) as g:
        before = ctx.snapshot_before(model, ids, values)
        ctx.odoo(model, "write", [ids, values])
        g.touched(ids)
        after = ctx.redact(values, model)
        ctx.journal(g, model, "write", {i: (before.get(i), after) for i in ids})
        return _done(g, len(ids), {"success": True, "ids": ids, "fields": sorted(values)})


def delete_record(ctx: ToolContext) -> Any:
    model = _arg_str(ctx, "model")
    ids = _arg_ids(ctx)
    with ctx.guard(operation=Operation.DELETE, model=model,
                   fields=ctx.outside_scope(model, ids), count=len(ids)) as g:
        before = ctx.snapshot_before(model, ids)
        ctx.odoo(model, "unlink", [ids])
        g.touched(ids)
        ctx.journal(g, model, "unlink", {i: (before.get(i), None) for i in ids})
        return _done(g, len(ids), {"success": True, "deleted_ids": ids})


def execute_method(ctx: ToolContext) -> Any:
    model = _arg_str(ctx, "model")
    method = _arg_str(ctx, "method")
    args = ctx.arguments.get("args", []) or []
    kwargs = ctx.arguments.get("kwargs", {}) or {}
    if not isinstance(args, list) or not isinstance(kwargs, dict):
        raise ToolInputError("'args' must be a list and 'kwargs' an object")
    # Best-effort description of what the call touches: record ids if the first
    # argument looks like them, the keys of any value dicts passed along, and
    # any list of strings — read(ids, ['password']) and default_get(['x'])
    # name their fields that way.
    count = None
    if args and isinstance(args[0], list) and all(isinstance(i, int) for i in args[0]):
        count = len(args[0])
    touched = collect_field_names([args, kwargs])
    for item in [*args, *kwargs.values()]:
        touched |= domain_fields(item)
    # A scoped agent may call a method only on records of its own.
    touched |= ctx.outside_scope(model, args[0] if count else [])
    with ctx.guard(
        operation=Operation.EXECUTE, model=model, method=method, fields=touched, count=count
    ) as g:
        result = ctx.odoo(model, method, args, kwargs)
        if count is not None:
            # What a method changes is unknowable from outside; which records
            # it was called on is not.
            g.touched(args[0])
        return _done(g, count, {"result": ctx.redact(result, model)})


def call_onchange(ctx: ToolContext) -> Any:
    model = _arg_str(ctx, "model")
    values = _arg_dict(ctx, "values")
    changed = _arg_str_list(ctx, "field_names") or list(values)
    spec = ctx.arguments.get("fields_spec")
    if spec is not None and not isinstance(spec, dict):
        raise ToolInputError("'fields_spec' must be an object")
    touched = set(changed) | collect_field_names(values) | collect_field_names(spec or {})
    # Onchange values can name any record (a partner id), and it answers with
    # that record's data: a scoped agent has no use for it.
    touched |= ctx.outside_scope(model, any_call=True)
    with ctx.guard(operation=Operation.READ, model=model, fields=touched, count=1) as g:
        if spec is None:
            spec = _default_onchange_spec(ctx, model)
        result = ctx.odoo(model, "onchange", [[], values, changed, spec])
        if isinstance(result, dict) and isinstance(result.get("value"), dict):
            result["value"] = ctx.redact(result["value"], model)
        return _done(g, 0, result)


def _default_onchange_spec(ctx: ToolContext, model: str) -> dict[str, Any]:
    """Ask for every simple field, so the answer shows what the change *causes*.

    Requesting only the fields the agent sent would hide exactly the
    information onchange exists to provide.
    """
    defs = _fields_get(ctx, model, ["type"])
    patterns = ctx.policy.sensitive_fields
    return {
        name: {}
        for name, meta in defs.items()
        if meta.get("type") not in ("one2many", "many2many", "binary")
        and not is_sensitive(name, patterns)
    }


# --- schema tools ----------------------------------------------------------


def _fields_get(ctx: ToolContext, model: str, attributes: list[str]) -> dict[str, Any]:
    return ctx.cached(
        ("fields_get", model, tuple(sorted(attributes))),
        lambda: ctx.odoo(model, "fields_get", [], {"attributes": attributes}),
    )


def get_model_fields(ctx: ToolContext) -> Any:
    model = _arg_str(ctx, "model")
    attributes = _arg_str_list(ctx, "attributes") or DEFAULT_FIELD_ATTRIBUTES
    with ctx.guard(operation=Operation.META, model=model) as g:
        defs = _fields_get(ctx, model, attributes)
        return _done(g, None, {"model": model, "field_count": len(defs), "fields": defs})


def get_field_names(ctx: ToolContext) -> Any:
    model = _arg_str(ctx, "model")
    with ctx.guard(operation=Operation.META, model=model) as g:
        defs = _fields_get(ctx, model, ["type", "string"])
        names = {
            name: f"{meta.get('type')} — {meta.get('string')}"
            for name, meta in sorted(defs.items())
        }
        return _done(g, None, {"model": model, "fields": names})


def model_info(ctx: ToolContext) -> Any:
    model = _arg_str(ctx, "model")
    with ctx.guard(operation=Operation.META, model=model) as g:
        rows = ctx.cached(
            ("ir.model", model),
            lambda: ctx.odoo(
                "ir.model",
                "search_read",
                [[["model", "=", model]]],
                {"fields": ["name", "model", "info", "transient", "modules"], "limit": 1},
            ),
        )
        if not rows:
            raise ToolInputError(f"model {model!r} does not exist in this database")
        info = rows[0]
        defs = _fields_get(ctx, model, ["type"])
        access = {op: _has_access(ctx, model, op) for op in ("read", "write", "create", "unlink")}
        policy = ctx.policy
        read_only = ctx.snapshot.profile.read_only
        configurator = ctx.snapshot.profile.name in policy.configurator_profiles
        return _done(
            g,
            None,
            {
                "model": info["model"],
                "name": info["name"],
                # ir.model.info is the Python class docstring, often a mixin's.
                "description": info["name"],
                "transient": info.get("transient", False),
                "modules": info.get("modules", ""),
                "field_count": len(defs),
                "odoo_access": access,
                "governance": {
                    "readable": covers(model, policy.allowed_models, configurator),
                    "writable": not read_only
                    and covers(model, policy.writable_models, configurator),
                    "deletable": not read_only
                    and covers(model, policy.deletable_models, configurator),
                    "profile_read_only": read_only,
                },
            },
        )


def _has_access(ctx: ToolContext, model: str, operation: str) -> bool | None:
    """Odoo 18+ ``has_access`` (a record method), falling back to the older
    ``check_access_rights``. ``None`` means neither answered."""
    from .odoo import OdooError

    try:
        return bool(ctx.odoo(model, "has_access", [[], operation]))
    except OdooError:
        pass
    try:
        return bool(ctx.odoo(model, "check_access_rights", [operation, False]))
    except OdooError:
        return None


def list_models(ctx: ToolContext) -> Any:
    term = _arg_str(ctx, "filter", required=False)
    limit = _arg_int(ctx, "limit", 200, minimum=1)
    with ctx.guard(operation=Operation.META, model=None) as g:
        domain = [["model", "ilike", term]] if term else []
        rows = ctx.cached(
            ("list_models", term),
            lambda: ctx.odoo(
                "ir.model", "search_read", [domain], {"fields": ["model", "name", "transient"]}
            ),
        )
        policy = ctx.policy
        # Only what this server would actually let the agent read: listing
        # unreachable models just invites calls that will be refused.
        name = ctx.snapshot.profile.name
        configurator = name in policy.configurator_profiles
        open_level = configurator or name in policy.sandbox_profiles
        rule = policy.agent_rules.get(ctx.actor)
        visible = [
            {**row, "writable": covers(row["model"], policy.writable_models, configurator)}
            for row in rows
            if row["model"] not in ALWAYS_DENIED
            and (configurator or row["model"] not in policy.denied_models)
            and covers(row["model"], policy.allowed_models, configurator)
            and (not row.get("transient") or open_level
                 or row["model"] in policy.transient_allowlist)
            and (rule is None or (
                (not rule.models or covers(row["model"], rule.models, configurator))
                and (not rule.scope or row["model"] in rule.scope)))
        ]
        return _done(
            g,
            None,
            {
                "count": len(visible[:limit]),
                "total_matching": len(visible),
                "allowlist": "all models" if WILDCARD in policy.allowed_models else "restricted",
                "models": visible[:limit],
            },
        )


# --- search helpers --------------------------------------------------------


def name_search(ctx: ToolContext) -> Any:
    model = _arg_str(ctx, "model")
    name = ctx.arguments.get("name", "") or ""
    if not isinstance(name, str):
        raise ToolInputError("'name' must be a string")
    domain = _arg_domain(ctx)
    operator = _arg_str(ctx, "operator", required=False, default="ilike")
    limit = _limit(ctx, default=10)
    with ctx.guard(
        operation=Operation.READ, model=model,
        fields=domain_fields(domain) | _value_oracle(model, domain_fields(domain)), count=limit
    ) as g:
        # Positional arguments: the keyword was renamed from ``args`` to
        # ``domain`` in Odoo 18, and position works on both sides of that.
        pairs = ctx.odoo(model, "name_search",
                         [name, ctx.scoped_domain(model, domain), operator, limit])
        results = [{"id": p[0], "name": p[1]} for p in pairs]
        return _done(g, len(results), {"count": len(results), "results": results})


def search_count(ctx: ToolContext) -> Any:
    model = _arg_str(ctx, "model")
    domain = _arg_domain(ctx)
    touched = domain_fields(domain) | _value_oracle(model, domain_fields(domain))
    with ctx.guard(operation=Operation.READ, model=model, fields=touched) as g:
        count = ctx.odoo(model, "search_count", [ctx.scoped_domain(model, domain)])
        # Counting reads no record content, so it does not feed mass_read.
        return _done(g, None, {"model": model, "count": count})


# --- reports and attachments -----------------------------------------------


def get_report(ctx: ToolContext) -> Any:
    report_name = _arg_str(ctx, "report_name")
    ids = _arg_ids(ctx)
    rows = ctx.cached(
        ("report", report_name),
        lambda: ctx.odoo(
            "ir.actions.report",
            "search_read",
            [[["report_name", "=", report_name]]],
            {"fields": ["model", "report_type", "name"], "limit": 1},
        ),
    )
    if not rows:
        raise ToolInputError(f"no report named {report_name!r}")
    report = rows[0]
    # Governed on the model the report renders, not on ir.actions.report: a
    # PDF of an invoice is a read of the invoice.
    with ctx.guard(
        operation=Operation.READ, model=report["model"], method=report_name, count=len(ids),
        fields=ctx.outside_scope(report["model"], ids),
    ) as g:
        if report.get("report_type") != "qweb-pdf":
            raise ToolInputError(f"{report_name!r} is not a PDF report")
        pdf = _render_pdf(ctx, report_name, ids)
        return _done(
            g,
            len(ids),
            {
                "report": report_name,
                "model": report["model"],
                "ids": ids,
                "filename": f"{report_name.replace('.', '_')}.pdf",
                "mimetype": "application/pdf",
                "size_bytes": len(pdf),
                "data_base64": base64.b64encode(pdf).decode("ascii"),
            },
        )


def _render_pdf(ctx: ToolContext, report_name: str, ids: list[int]) -> bytes:
    """Render through Odoo's own report route, using a web session.

    The ORM renderer is private, so it cannot be called over RPC at all —
    the documented route is ``/report/pdf/<name>/<ids>``, which needs a web
    session. Web sessions require the account password: Odoo accepts API keys
    for RPC only. A profile configured with only an API key therefore cannot
    render reports, and this says so rather than failing obscurely.
    """
    from .odoo import OdooConnectionError, OdooError

    profile = ctx.snapshot.profile
    if not profile.password:
        raise OdooError(
            "get_report needs the profile's password: Odoo does not accept API keys "
            "for web sessions, and reports can only be rendered through one",
            kind="ConfigurationError",
        )
    context = ssl.create_default_context()
    if not profile.ssl_verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), urllib.request.HTTPSHandler(context=context)
    )
    login = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {
                "db": profile.database,
                "login": profile.username,
                "password": profile.password,
            },
        }
    ).encode()
    limit = _max_attachment_bytes(ctx)
    try:
        request = urllib.request.Request(
            f"{profile.url}/web/session/authenticate",
            data=login,
            headers={"Content-Type": "application/json"},
        )
        with opener.open(request, timeout=profile.timeout) as response:
            body = json.loads(response.read(1_000_000))
        if body.get("error") or not (body.get("result") or {}).get("uid"):
            raise OdooConnectionError("web session login failed for this profile")
        path = f"/report/pdf/{urllib.parse.quote(report_name)}/{','.join(map(str, ids))}"
        with opener.open(f"{profile.url}{path}", timeout=profile.timeout) as response:
            if "pdf" not in response.headers.get("Content-Type", ""):
                raise OdooError("Odoo did not return a PDF for this report", kind="ReportError")
            data = response.read(limit + 1)
    except OdooError:
        raise
    except Exception as exc:  # urllib raises a wide family; none of it is for the agent
        raise OdooConnectionError(f"report rendering failed ({type(exc).__name__})") from None
    if len(data) > limit:
        raise OdooError("rendered PDF exceeds MAX_ATTACHMENT_MB", kind="ReportError")
    return data


def upload_attachment(ctx: ToolContext) -> Any:
    model = _arg_str(ctx, "model")
    record_id = ctx.arguments.get("record_id")
    if isinstance(record_id, bool) or not isinstance(record_id, int) or record_id <= 0:
        raise ToolInputError("'record_id' must be a positive integer")
    filename = _arg_str(ctx, "filename")
    data = _arg_str(ctx, "data_base64")
    mimetype = _arg_str(ctx, "mimetype", required=False) or None
    raw = _decode_base64(data, _max_attachment_bytes(ctx))
    # Attaching a file to a record changes that record, so it needs write
    # permission on the record's model — governed as a create against it.
    with ctx.guard(
        operation=Operation.CREATE, model=model,
        fields={"attachment", *ctx.outside_scope(model, [record_id])}, count=1
    ) as g:
        values: dict[str, Any] = {
            "name": filename,
            "datas": base64.b64encode(raw).decode("ascii"),
            "res_model": model,
            "res_id": record_id,
        }
        if mimetype:
            values["mimetype"] = mimetype
        created = ctx.odoo("ir.attachment", "create", [values])
        new_id = created[0] if isinstance(created, list) else created
        if isinstance(new_id, int):
            g.touched([new_id])
        return _done(
            g, 1, {"id": new_id, "filename": filename, "size_bytes": len(raw), "res_model": model}
        )


def list_attachments(ctx: ToolContext) -> Any:
    """The files attached to one record — the only way to discover files.

    Governed as a read of the record's own model, so a denied or system
    owner is refused before ir.attachment is touched, and only metadata is
    returned.
    """
    model = _arg_str(ctx, "model")
    record_id = ctx.arguments.get("record_id")
    if isinstance(record_id, bool) or not isinstance(record_id, int) or record_id <= 0:
        raise ToolInputError("'record_id' must be a positive integer")
    with ctx.guard(operation=Operation.READ, model=model, count=1,
                   fields={"attachment", *ctx.outside_scope(model, [record_id])}) as g:
        rows = ctx.odoo(
            "ir.attachment",
            "search_read",
            [[["res_model", "=", model], ["res_id", "=", record_id]]],
            {"fields": ["name", "mimetype", "file_size", "create_date"], "limit": 100},
        )
        files = [
            {k: r.get(k) for k in ("id", "name", "mimetype", "file_size", "create_date")}
            for r in rows if isinstance(r, dict)
        ]
        return _done(g, len(files), {"model": model, "record_id": record_id,
                                     "count": len(files), "attachments": files})


def get_attachment(ctx: ToolContext) -> Any:
    attachment_id = ctx.arguments.get("attachment_id")
    if isinstance(attachment_id, bool) or not isinstance(attachment_id, int) or attachment_id <= 0:
        raise ToolInputError("'attachment_id' must be a positive integer")
    # Metadata first, to learn which model the file belongs to. Nothing from
    # this read reaches the agent unless governance then allows the call.
    meta = ctx.odoo(
        "ir.attachment",
        "read",
        [[attachment_id]],
        {"fields": ["name", "mimetype", "file_size", "res_model", "res_id", "res_field"]},
    )
    owner = (meta[0].get("res_model") if meta else None) or "ir.attachment"
    checked = {"attachment"}
    if meta:
        # Which field holds the file, and what kind of file it is: keys and
        # certificates are refused whatever record they belong to.
        if meta[0].get("res_field"):
            checked.add(str(meta[0]["res_field"]))
        name = str(meta[0].get("name") or "").lower()
        if "." in name:
            checked.add("file:" + name[name.rindex("."):])
        mimetype = str(meta[0].get("mimetype") or "").lower()
        if "pkcs12" in mimetype or "x-pem" in mimetype or "x-x509" in mimetype:
            checked.add("file:.p12")
        res_id = meta[0].get("res_id")
        checked |= ctx.outside_scope(owner, [res_id] if isinstance(res_id, int) and res_id else [])
    with ctx.guard(operation=Operation.READ, model=owner, fields=checked, count=1) as g:
        if not meta:
            raise ToolInputError(f"attachment {attachment_id} does not exist")
        info = meta[0]
        if (info.get("file_size") or 0) > _max_attachment_bytes(ctx):
            raise ToolInputError("attachment exceeds MAX_ATTACHMENT_MB")
        data = ctx.odoo("ir.attachment", "read", [[attachment_id]], {"fields": ["datas"]})
        return _done(
            g,
            1,
            {
                "id": attachment_id,
                "filename": info["name"],
                "mimetype": info.get("mimetype"),
                "size_bytes": info.get("file_size"),
                "res_model": info.get("res_model"),
                "res_id": info.get("res_id"),
                "data_base64": (data[0].get("datas") or "") if data else "",
            },
        )


# --- server tools ----------------------------------------------------------


def cache_stats(ctx: ToolContext) -> Any:
    with ctx.guard(operation=Operation.ADMIN) as g:
        return _done(g, None, ctx.runtime.cache.stats())


def server_status(ctx: ToolContext) -> Any:
    from . import __version__
    from .odoo import OdooError

    with ctx.guard(operation=Operation.ADMIN) as g:
        client = ctx.snapshot.client
        odoo: dict[str, Any] = {"reachable": False}
        try:
            version = client.version()
            odoo = {
                "reachable": True,
                "server_version": version.get("server_version"),
                "authenticated": bool(client.uid),
            }
        except OdooError as exc:
            odoo["error"] = exc.kind
        policy = ctx.policy
        audit = ctx.runtime.audit
        warnings = list(policy.validate())
        if odoo.get("authenticated"):
            access = ctx.snapshot.settings_access()
            odoo["settings_access"] = access
            if access is not False:
                warnings.append(
                    "the profile's Odoo user has Settings access (or it could not be "
                    "verified): if a policy rule is missing, Odoo's own access control will "
                    "not stop the agent. Connect with a dedicated least-privilege user."
                )
        return _done(
            g,
            None,
            {
                "server": {"name": "odoo-mcp-governed", "version": __version__},
                "profile": _profile_status(ctx.snapshot.profile),
                "odoo": odoo,
                "governance": {
                    "warnings": warnings,
                    "audit_events": audit.store.count(),
                    "audit_chain_keyed": audit.keyed,
                    "policy_source": ctx.runtime.policy_store.source,
                    "allowed_models": sorted(policy.allowed_models),
                    "writable_models": sorted(policy.writable_models),
                    "deletable_models": sorted(policy.deletable_models),
                    "denied_models": sorted(policy.denied_models),
                    "execute_method": policy.allow_execute_method,
                    "max_records_per_call": policy.max_records_per_call,
                },
            },
        )


def _profile_status(profile) -> dict[str, Any]:
    """The profile as the agent should read it: what is in effect, not flags.

    ``allow_writes`` only lifts the production default, so showing it raw on a
    development profile read as "read-only" when it was not.
    """
    status = {
        k: v for k, v in profile.public().items() if k not in ("allow_writes", "read_only")
    }
    status["writes_enabled"] = not profile.read_only
    status["level"] = profile.level if profile.environment != "production" else "business"
    if profile.configurator and profile.environment != "production":
        status["level_note"] = (
            "configurator: the whole system is reachable — modules, settings, users, views, "
            "automations; API keys, attachments outside list_attachments/get_attachment and "
            "credential fields are not, and module changes or code wait for a human"
        )
    if profile.sandbox and profile.environment != "production":
        status["sandbox"] = True
        status["sandbox_note"] = (
            "sandbox: model lists and the execute_method allowlist do not apply and risk is "
            "only observed; the denylist, credential fields and audit still do"
        )
    if profile.environment == "production":
        status["production_writes_override"] = profile.allow_writes
        status["writes_note"] = (
            "production profile with allow_writes: writes are enabled"
            if profile.allow_writes
            else "production profile: read-only; set allow_writes on the profile to lift it"
        )
    else:
        status["writes_note"] = (
            f"{profile.environment} profile: writes are enabled; each model still needs "
            "WRITABLE_MODELS"
        )
    return status


# --- registry --------------------------------------------------------------

READ_ONLY = {"readOnlyHint": True, "destructiveHint": False}
WRITES = {"readOnlyHint": False, "destructiveHint": False}
DESTRUCTIVE = {"readOnlyHint": False, "destructiveHint": True}

TOOLS: dict[str, Tool] = {
    t.name: t
    for t in [
        Tool(
            "get_record",
            "Read one or more records by id.",
            Operation.READ,
            {"model": MODEL, "record_id": RECORD_ID, "ids": IDS, "fields": FIELDS},
            ("model",),
            get_record,
            READ_ONLY,
        ),
        Tool(
            "search_records",
            "Search records with an Odoo domain and return the matching rows.",
            Operation.READ,
            {
                "model": MODEL,
                "domain": DOMAIN,
                "fields": FIELDS,
                "limit": {"type": "integer", "description": "Max rows (default 100)"},
                "offset": {"type": "integer"},
                "order": {"type": "string", "description": "e.g. 'create_date desc'"},
            },
            ("model",),
            search_records,
            READ_ONLY,
        ),
        Tool(
            "create_record",
            "Create a record.",
            Operation.CREATE,
            {"model": MODEL, "values": {"type": "object", "description": "Field values"}},
            ("model", "values"),
            create_record,
            WRITES,
        ),
        Tool(
            "update_record",
            "Update one or more existing records.",
            Operation.WRITE,
            {
                "model": MODEL,
                "record_id": RECORD_ID,
                "ids": IDS,
                "values": {"type": "object", "description": "Field values to write"},
            },
            ("model", "values"),
            update_record,
            WRITES,
        ),
        Tool(
            "delete_record",
            "Delete one or more records. Irreversible.",
            Operation.DELETE,
            {"model": MODEL, "record_id": RECORD_ID, "ids": IDS},
            ("model",),
            delete_record,
            DESTRUCTIVE,
        ),
        Tool(
            "execute_method",
            "Call a public model method, e.g. sale.order.action_confirm. Restricted by policy.",
            Operation.EXECUTE,
            {
                "model": MODEL,
                "method": {"type": "string"},
                "args": {"type": "array", "items": {},
                         "description": "Positional args; record ids first"},
                "kwargs": {"type": "object"},
            },
            ("model", "method"),
            execute_method,
            DESTRUCTIVE,
        ),
        Tool(
            "call_onchange",
            "Simulate a form change and return the values Odoo would compute. Saves nothing.",
            Operation.READ,
            {
                "model": MODEL,
                "values": {"type": "object", "description": "Current form values"},
                "field_names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Fields that changed (default: keys of values)",
                },
                "fields_spec": {"type": "object", "description": "Optional onchange spec"},
            },
            ("model", "values"),
            call_onchange,
            READ_ONLY,
        ),
        Tool(
            "get_model_fields",
            "Field definitions of a model (type, relation, required...).",
            Operation.META,
            {"model": MODEL, "attributes": {"type": "array", "items": {"type": "string"}}},
            ("model",),
            get_model_fields,
            READ_ONLY,
        ),
        Tool(
            "get_field_names",
            "Compact list of a model's field names with type and label.",
            Operation.META,
            {"model": MODEL},
            ("model",),
            get_field_names,
            READ_ONLY,
        ),
        Tool(
            "model_info",
            "Model description, Odoo access rights and what this server's policy permits.",
            Operation.META,
            {"model": MODEL},
            ("model",),
            model_info,
            READ_ONLY,
        ),
        Tool(
            "list_models",
            "List the models this server allows access to, optionally filtered.",
            Operation.META,
            {
                "filter": {"type": "string", "description": "Substring of the model name"},
                "limit": {"type": "integer"},
            },
            (),
            list_models,
            READ_ONLY,
        ),
        Tool(
            "name_search",
            "Find records by display name — the quick way to resolve a name to an id.",
            Operation.READ,
            {
                "model": MODEL,
                "name": {"type": "string"},
                "domain": DOMAIN,
                "operator": {"type": "string", "description": "Default 'ilike'"},
                "limit": {"type": "integer", "description": "Default 10"},
            },
            ("model",),
            name_search,
            READ_ONLY,
        ),
        Tool(
            "search_count",
            "Count records matching a domain.",
            Operation.READ,
            {"model": MODEL, "domain": DOMAIN},
            ("model",),
            search_count,
            READ_ONLY,
        ),
        Tool(
            "get_report",
            "Render a PDF report (e.g. an invoice) for records. Returns base64.",
            Operation.READ,
            {
                "report_name": {"type": "string", "description": "e.g. 'account.report_invoice'"},
                "record_id": RECORD_ID,
                "ids": IDS,
            },
            ("report_name",),
            get_report,
            READ_ONLY,
        ),
        Tool(
            "upload_attachment",
            "Attach a file (base64) to a record.",
            Operation.CREATE,
            {
                "model": MODEL,
                "record_id": RECORD_ID,
                "filename": {"type": "string"},
                "data_base64": {"type": "string"},
                "mimetype": {"type": "string"},
            },
            ("model", "record_id", "filename", "data_base64"),
            upload_attachment,
            WRITES,
        ),
        Tool(
            "list_attachments",
            "List the files attached to one record (name, type, size).",
            Operation.READ,
            {"model": MODEL, "record_id": RECORD_ID},
            ("model", "record_id"),
            list_attachments,
            READ_ONLY,
        ),
        Tool(
            "get_attachment",
            "Download an attachment as base64.",
            Operation.READ,
            {"attachment_id": {"type": "integer"}},
            ("attachment_id",),
            get_attachment,
            READ_ONLY,
        ),
        Tool(
            "cache_stats",
            "Metadata cache statistics.",
            Operation.ADMIN,
            {},
            (),
            cache_stats,
            READ_ONLY,
        ),
        Tool(
            "server_status",
            "Server, active Odoo profile and governance status.",
            Operation.ADMIN,
            {},
            (),
            server_status,
            READ_ONLY,
        ),
    ]
}

# The tool surface is a contract with every connected agent. A real check, not
# an assert: asserts vanish under ``python -O``.
if len(TOOLS) != 19:
    raise RuntimeError(f"the tool surface is a contract — 19 tools, found {len(TOOLS)}")
