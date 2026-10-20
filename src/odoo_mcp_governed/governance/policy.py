"""Preventive policy — the rules that stop a call before Odoo ever sees it.

Policy answers one question: *is this actor permitted to do this at all?* It
knows nothing about history or behaviour; that is the detectors' job. Keeping
the two apart matters because they fail differently. A policy mistake is a
permission bug you can reason about from the config file. A detector mistake
is a false positive in a statistical heuristic. You do not want the second
kind deciding whether a call is legal.

Three design choices worth defending:

**Default deny.** An empty ``ALLOWED_MODELS`` permits nothing. Every widening
is something a human typed. An allowlist that ships permissive is an allowlist
nobody ever tightens.

**Separate gates for read, write and delete.** Being allowed to read
``res.partner`` must not imply being allowed to delete from it. Most agent
integrations need to read broadly and write narrowly, and a single
"allowed models" list cannot express that.

**``execute_method`` cannot launder a destructive call.** It is the widest
surface in any Odoo API wrapper — arbitrary method, arbitrary model. Calling
``unlink`` through it would otherwise sidestep the delete gate entirely, so
the ORM's own write primitives are refused there and have to go through the
tools that are actually governed as writes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from .events import Operation, ToolCall

REASON_SEPARATOR = ": "


def reason_code(reason: str) -> str:
    """The stable machine-readable prefix of a reason string.

    Reasons are stored as ``"code: human explanation"``. Detectors and
    dashboards match on the code; humans read the rest.
    """
    return reason.split(REASON_SEPARATOR, 1)[0]


def _reason(code: str, detail: str) -> str:
    return f"{code}{REASON_SEPARATOR}{detail}"


# Model methods that must never be reachable through ``execute_method``.
# The ORM write primitives are here because they would bypass the write and
# delete gates. ``copy`` is a create in disguise. ``_`` -prefixed methods are
# refused wholesale as private API, separately from this list.
BLOCKED_METHODS = frozenset(
    {
        "create",
        "write",
        "unlink",
        "copy",
        "copy_data",
        "browse",
        "execute_kw",
        "check_access_rights",
        "check_access_rule",
        "sudo",
        "with_user",
        "with_env",
        "load",
        "import_data",
        "_read",
        "_write",
        "_create",
        "_unlink",
    }
)

# Models that are refused regardless of any allowlist, including ``*``.
# Each entry either executes arbitrary Python inside Odoo, holds system
# secrets or credentials, or can switch Odoo's own access control off. Reaching
# any of them through an agent is equivalent to handing over the server.
DEFAULT_DENIED_MODELS = frozenset(
    {
        "ir.actions.server",   # runs Python
        "base.automation",     # runs Python on record events
        "ir.cron",             # runs Python on a schedule
        "ir.config_parameter", # database.secret, third-party API keys
        "res.users.apikeys",   # every user's API keys
        "ir.rule",             # record rules — disable them and ACLs vanish
        "ir.model.access",     # model ACLs
        "ir.mail_server",      # SMTP credentials
        "fetchmail.server",    # IMAP/POP credentials
        "auth.oauth.provider", # OAuth client secrets
        "res.config.settings", # reads and writes ir.config_parameter for you
        "res.config",          # the base of every settings wizard
        "ir.module.module",    # install runs module code, uninstall drops tables
        "base.module.upgrade",   # same, through the upgrade wizard
        "base.module.uninstall", # same, through the uninstall wizard
    }
)

# The subset whose removal from the denylist deserves a startup warning even
# when it was deliberate: these are code execution and credential theft.
CRITICAL_DENIED_MODELS = frozenset(
    {
        "ir.actions.server",
        "base.automation",
        "ir.cron",
        "ir.config_parameter",
        "res.users.apikeys",
        "res.config.settings",
        "ir.module.module",
    }
)

# Attachment *content* is only served by get_attachment and upload_attachment,
# which check the record the attachment belongs to. Through the generic tools
# ir.attachment is one model holding every other model's files, so reading
# ``datas`` there would skip that check for all of them at once.
ATTACHMENT_MODEL = "ir.attachment"
# index_content is the text Odoo extracts from a file for its own search:
# reading it, or filtering on it, reveals the file as surely as datas does.
ATTACHMENT_CONTENT_FIELDS = frozenset({"datas", "raw", "db_datas", "store_fname", "index_content"})

WILDCARD = "*"


def matches(model: str, models: frozenset[str]) -> bool:
    """Whether ``model`` is covered by a model list that may contain ``*``."""
    return WILDCARD in models or model in models


# Fields whose values must never leave Odoo through this server, on any model.
# These are glob patterns matched case-insensitively against every field name a
# call touches. Patterns, not exact names, because modules add credentials
# under compound names — ``stripe_secret_key``, ``unsplash_access_key`` — and a
# module installed after the server was configured must not leak through a
# ``*`` allowlist.
#
# The built-in floor applies whatever the configuration says, like
# :data:`BLOCKED_METHODS`. SENSITIVE_FIELDS can add to it, never remove from it.
BUILTIN_SENSITIVE_FIELDS = frozenset(
    {"*password*", "*secret*", "*token*", "*api_key*", "*apikey*", "*private_key*"}
)

# The configurable part, as shipped. Replacing it through SENSITIVE_FIELDS
# keeps the floor above.
SENSITIVE_FIELDS = frozenset({"*_key", "*hmac*", "*credential*", "totp_*", "*_pass"})


def is_sensitive(field_name: str, patterns: frozenset[str]) -> bool:
    name = field_name.lower()
    return any(fnmatchcase(name, p.lower()) for p in BUILTIN_SENSITIVE_FIELDS | patterns)


@dataclass(frozen=True)
class PolicyConfig:
    """The permission surface. Everything here defaults to the safe end."""

    allowed_models: frozenset[str] = frozenset()
    """Models readable at all. Empty denies everything; ``*`` allows every
    model not in :attr:`denied_models`."""

    writable_models: frozenset[str] = frozenset()
    """Models that may be created in or written to. Should be a subset of
    :attr:`allowed_models`; :meth:`validate` complains if it is not."""

    deletable_models: frozenset[str] = frozenset()
    """Models that may be deleted from. Keep this as near empty as you can."""

    max_records_per_call: int = 500
    """Ceiling on records read or affected by one call. Caps the blast radius
    of both a runaway agent and a bulk exfiltration attempt."""

    allow_execute_method: bool = False
    """``execute_method`` is off until someone deliberately turns it on."""

    execute_method_allowlist: frozenset[str] = frozenset()
    """When non-empty, the only method names ``execute_method`` may call.
    Strongly recommended: name the handful of business actions you need."""

    sensitive_fields: frozenset[str] = field(default=SENSITIVE_FIELDS)

    denied_models: frozenset[str] = field(default=DEFAULT_DENIED_MODELS)
    """Refused always, and checked before any allowlist — a ``*`` allowlist
    does not reach these. Defence in depth: the allowlist says what an agent
    needs, the denylist says what nobody gets."""

    disabled_tools: frozenset[str] = frozenset()
    """Tools switched off entirely. They disappear from ``tools/list`` and are
    refused if called anyway."""

    forbidden_methods: frozenset[str] = frozenset()
    """Extra method names refused by ``execute_method``, on top of the
    built-in :data:`BLOCKED_METHODS` that cannot be removed."""

    read_only_profiles: frozenset[str] = frozenset()
    """Profiles on which nothing may be created, written, deleted or executed,
    whatever the model lists say. Derived from the profiles themselves
    (production without ``allow_writes``), not edited as policy."""

    approval_required: frozenset[str] = frozenset()
    """Operations that wait for a human: any of ``delete``, ``bulk`` (create,
    write or delete above ``approval_bulk_threshold`` records) and
    ``execute``. Empty switches approvals off."""

    approval_bulk_threshold: int = 20

    panic: bool = False
    """The operator's emergency stop: every call is refused, introspection
    included, until a human resumes. Checked before anything else."""

    blocked_actors: frozenset[str] = frozenset()
    """Agents (token subjects) refused outright, whatever they ask for. Other
    agents keep working."""

    transient_allowlist: frozenset[str] = frozenset()
    """Wizards (transient models) agents may use. Every other wizard is
    refused: a wizard acts on other models — a merge wizard rewrites and
    deletes partners — without going through their write and delete gates."""

    sandbox_profiles: frozenset[str] = frozenset()
    """Non-production profiles marked as sandboxes: model lists and the
    execute_method switch and allowlist do not apply there, and risk is only
    observed. The floor — denylist, credential fields, attachment content,
    blocked methods, panic and blocked agents — still does. Derived from the
    profiles, not edited as policy."""

    privileged_profiles: frozenset[str] = frozenset()
    """Production profiles whose Odoo user has Settings access (or could not
    be checked). On these a ``*`` allowlist is refused: if a policy rule were
    missing, nothing in Odoo's own access control would stop the agent.
    Derived at runtime, not edited as policy."""

    def validate(self) -> list[str]:
        """Config problems worth warning about at startup. Never raises —
        returns warnings so the caller can log them all at once."""
        warnings: list[str] = []
        for name, models in (
            ("WRITABLE_MODELS", self.writable_models),
            ("DELETABLE_MODELS", self.deletable_models),
        ):
            if WILDCARD in self.allowed_models:
                continue
            orphans = models - self.allowed_models - {WILDCARD}
            if orphans:
                warnings.append(
                    f"{name} lists models missing from ALLOWED_MODELS, so they are "
                    f"unreachable: {', '.join(sorted(orphans))}"
                )
        if not self.allowed_models:
            warnings.append("ALLOWED_MODELS is empty — every data call will be denied")
        if WILDCARD in self.deletable_models:
            warnings.append(
                "DELETABLE_MODELS is '*' — any model outside the denylist can be deleted from"
            )
        lifted = CRITICAL_DENIED_MODELS - self.denied_models
        if lifted:
            warnings.append(
                "DENIED_MODELS no longer blocks models that allow code execution or "
                f"credential theft: {', '.join(sorted(lifted))}"
            )
        if self.allow_execute_method and not self.execute_method_allowlist:
            warnings.append(
                "execute_method is enabled with no method allowlist — any non-blocked "
                "model method can be called. Set EXECUTE_METHOD_ALLOWLIST."
            )
        if self.max_records_per_call > 10_000:
            warnings.append(
                f"MAX_RECORDS_PER_CALL is {self.max_records_per_call}, high enough that "
                "a single call can pull most of a table"
            )
        return warnings


@dataclass(frozen=True)
class PolicyVerdict:
    allowed: bool
    reasons: tuple[str, ...] = ()

    @property
    def codes(self) -> tuple[str, ...]:
        return tuple(reason_code(r) for r in self.reasons)


class PolicyEngine:
    """Stateless evaluation of a single call against :class:`PolicyConfig`."""

    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    def evaluate(self, call: ToolCall) -> PolicyVerdict:
        reasons: list[str] = []
        cfg = self.config

        if cfg.panic:
            return PolicyVerdict(
                allowed=False,
                reasons=(
                    _reason(
                        "panic_stop",
                        "the operator stopped this server with the panic switch: every call "
                        "is refused until a human resumes it. Do not retry; tell the user.",
                    ),
                ),
            )
        if call.actor in cfg.blocked_actors:
            return PolicyVerdict(
                allowed=False,
                reasons=(
                    _reason(
                        "actor_blocked",
                        f"the operator blocked agent {call.actor!r}: every call from it is "
                        "refused. Do not retry; tell the user.",
                    ),
                ),
            )

        if call.tool in cfg.disabled_tools:
            return PolicyVerdict(
                allowed=False,
                reasons=(_reason("tool_disabled", f"{call.tool!r} is disabled by policy"),),
            )

        # Server introspection touches no Odoo data at all.
        if call.operation is Operation.ADMIN:
            return PolicyVerdict(allowed=True)

        if (
            call.model
            and call.profile in cfg.privileged_profiles
            and WILDCARD in cfg.allowed_models
        ):
            return PolicyVerdict(
                allowed=False,
                reasons=(
                    _reason(
                        "privileged_wildcard",
                        f"profile {call.profile!r} is production and its Odoo user has "
                        "Settings access (or it could not be verified), so '*' model lists "
                        "are refused on it: list the models explicitly, or connect with a "
                        "dedicated least-privilege Odoo user",
                    ),
                ),
            )

        if call.profile in cfg.read_only_profiles and (
            call.operation.mutates or call.operation is Operation.EXECUTE
        ):
            return PolicyVerdict(
                allowed=False,
                reasons=(
                    _reason(
                        "profile_read_only",
                        f"profile {call.profile!r} is production and read-only; nothing "
                        "can be created, changed, deleted or executed on it",
                    ),
                ),
            )

        if call.model is not None and call.model in cfg.denied_models:
            # Final, and reported alone: once a model is on the denylist the
            # other gates are irrelevant, and listing them would suggest that
            # fixing them might help.
            return PolicyVerdict(
                allowed=False,
                reasons=(
                    _reason(
                        "model_denied",
                        f"{call.model!r} is on the denylist (DENIED_MODELS) and is never "
                        "reachable through this server",
                    ),
                ),
            )

        if call.model == ATTACHMENT_MODEL and (
            call.operation.mutates or call.operation is Operation.EXECUTE
        ):
            # Who an attachment belongs to is what get_attachment checks, so
            # moving one (res_model / res_id) would launder a denied model's
            # file onto an allowed record. Part of the floor: sandbox too.
            return PolicyVerdict(
                allowed=False,
                reasons=(
                    _reason(
                        "attachment_write",
                        "attachments are created only through upload_attachment, which checks "
                        "the record they belong to; the generic tools may read their metadata "
                        "but not create, change, delete or run methods on them",
                    ),
                ),
            )

        sandbox = call.profile in cfg.sandbox_profiles
        if (
            call.model is not None
            and call.model_transient
            and not sandbox
            and call.model not in cfg.transient_allowlist
        ):
            return PolicyVerdict(
                allowed=False,
                reasons=(
                    _reason(
                        "transient_model",
                        f"{call.model!r} is a wizard (transient model): wizards change other "
                        "models' records without those models' own permissions, so they are "
                        "refused unless listed in TRANSIENT_ALLOWLIST",
                    ),
                ),
            )
        allowed = frozenset({WILDCARD}) if sandbox else cfg.allowed_models
        writable = frozenset({WILDCARD}) if sandbox else cfg.writable_models
        deletable = frozenset({WILDCARD}) if sandbox else cfg.deletable_models

        if call.model is not None and not matches(call.model, allowed):
            # Schema introspection is gated too: field names and relations are
            # a map of the database, and handing that out is how someone finds
            # what to go after next.
            reasons.append(
                _reason("model_not_allowed", f"{call.model!r} is not in ALLOWED_MODELS")
            )

        if call.operation in (Operation.CREATE, Operation.WRITE):
            if call.model is None:
                reasons.append(_reason("model_required", f"{call.operation.value} needs a model"))
            elif not matches(call.model, writable):
                reasons.append(
                    _reason("model_not_writable", f"{call.model!r} is not in WRITABLE_MODELS")
                )

        if call.operation is Operation.DELETE:
            if call.model is None:
                reasons.append(_reason("model_required", "delete needs a model"))
            elif not matches(call.model, deletable):
                reasons.append(
                    _reason("model_not_deletable", f"{call.model!r} is not in DELETABLE_MODELS")
                )

        if call.operation is Operation.EXECUTE:
            reasons.extend(self._evaluate_execute(call, sandbox=sandbox))

        reasons.extend(self._evaluate_fields(call))
        reasons.extend(self._evaluate_volume(call))

        return PolicyVerdict(allowed=not reasons, reasons=tuple(reasons))

    def _evaluate_execute(self, call: ToolCall, *, sandbox: bool = False) -> list[str]:
        cfg = self.config
        reasons: list[str] = []

        if not cfg.allow_execute_method and not sandbox:
            return [
                _reason(
                    "execute_disabled",
                    "execute_method is disabled; set ALLOW_EXECUTE_METHOD=true to enable it",
                )
            ]

        method = call.method
        if not method:
            return [_reason("method_required", "execute_method needs a method name")]

        if method.startswith("_"):
            reasons.append(
                _reason("method_private", f"{method!r} is private ORM API and is never callable")
            )
        elif method in BLOCKED_METHODS or method in cfg.forbidden_methods:
            reasons.append(
                _reason(
                    "method_blocked",
                    f"{method!r} would bypass the write and delete gates; use the "
                    "dedicated tool for that operation instead",
                )
            )
        elif (
            not sandbox
            and cfg.execute_method_allowlist
            and method not in cfg.execute_method_allowlist
        ):
            reasons.append(
                _reason("method_not_allowed", f"{method!r} is not in EXECUTE_METHOD_ALLOWLIST")
            )

        # An arbitrary method may write, so it needs write permission on the model.
        if call.model and not sandbox and not matches(call.model, cfg.writable_models):
            reasons.append(
                _reason(
                    "model_not_writable",
                    f"execute_method on {call.model!r} requires it in WRITABLE_MODELS, "
                    "since a model method may write",
                )
            )
        return reasons

    def _evaluate_fields(self, call: ToolCall) -> list[str]:
        hits = sorted(
            {f for f in call.fields_touched if is_sensitive(f, self.config.sensitive_fields)}
        )
        reasons = []
        if hits:
            reasons.append(
                _reason(
                    "sensitive_field",
                    f"refusing to touch credential fields: {', '.join(hits)}",
                )
            )
        if call.model == ATTACHMENT_MODEL:
            content = sorted(set(call.fields_touched) & ATTACHMENT_CONTENT_FIELDS)
            if content:
                reasons.append(
                    _reason(
                        "attachment_content",
                        f"{', '.join(content)} on ir.attachment is only available through "
                        "get_attachment and upload_attachment, which check the record "
                        "the attachment belongs to",
                    )
                )
        return reasons

    def _evaluate_volume(self, call: ToolCall) -> list[str]:
        limit = self.config.max_records_per_call
        if call.record_count is not None and call.record_count > limit:
            return [
                _reason(
                    "volume_exceeded",
                    f"{call.record_count} records requested, limit is {limit}",
                )
            ]
        return []
