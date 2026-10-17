"""The MCP protocol: JSON-RPC 2.0 messages in, JSON-RPC responses out.

One dispatcher serves both transports. Stdio and HTTP differ in how bytes
arrive and who the caller is; they do not differ in what a ``tools/call``
means, and having one implementation is what guarantees that governance
applies identically on both.

Error reporting follows the MCP convention: a tool that ran and failed —
refused by governance, rejected by Odoo, given bad arguments — returns a
normal result with ``isError: true`` and a readable message, because that is
something the model should see and react to. JSON-RPC errors are reserved for
protocol problems (unknown method, malformed request).
"""

from __future__ import annotations

import json
import logging
from typing import Any

from . import __version__
from .governance import Decision, GovernanceDenied, Judgement, Outcome, ToolCall, digest_args
from .governance.policy import REASON_SEPARATOR
from .odoo import OdooError
from .runtime import NoActiveProfile, Runtime
from .tools import TOOLS, ToolContext, ToolInputError

log = logging.getLogger(__name__)

SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

INSTRUCTIONS = (
    "Tools for an Odoo ERP. Every call is checked against an access policy and "
    "recorded in an audit log. If a call is refused, the message says why — do "
    "not retry a refused call with variations; ask the user instead."
)


def agent_message(judgement: Judgement) -> str:
    """What a refused agent is told.

    Policy refusals are explained in full: knowing that ``res.users`` is not
    allowed lets a well-behaved agent stop. Risk-based refusals are not: the
    signals and thresholds that produced them stay in the audit log. An agent
    that has been prompt-injected and is told "3 deletes in 60s trips the
    detector" will simply do two.
    """
    policy_reasons = [r.split(REASON_SEPARATOR, 1)[-1] for r in judgement.policy.reasons]
    if policy_reasons:
        return "Refused by policy: " + "; ".join(policy_reasons)
    return (
        "Refused by governance controls: recent activity from this client has been "
        "flagged as unusual. Stop and ask the user; an administrator can review the "
        "audit log."
    )


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _result(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _text(payload: Any, *, is_error: bool = False) -> dict[str, Any]:
    text = payload if isinstance(payload, str) else json.dumps(
        payload, ensure_ascii=False, default=str, indent=1
    )
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


class Dispatcher:
    def __init__(self, runtime: Runtime) -> None:
        self.runtime = runtime

    def handle_payload(self, payload: Any, actor: str, profile: str | None = None) -> Any:
        """A single message or a batch. Returns ``None`` when nothing is owed
        (notifications only)."""
        if isinstance(payload, list):
            if not payload:
                return _error(None, INVALID_REQUEST, "empty batch")
            responses = [
                r for r in (self.handle(m, actor, profile) for m in payload) if r is not None
            ]
            return responses or None
        return self.handle(payload, actor, profile)

    def handle(
        self, message: Any, actor: str, profile: str | None = None
    ) -> dict[str, Any] | None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _error(None, INVALID_REQUEST, "not a JSON-RPC 2.0 message")
        method = message.get("method")
        request_id = message.get("id")
        is_notification = "id" not in message

        if not isinstance(method, str):
            # A response from the client (we never send requests) or garbage.
            return None if is_notification else _error(request_id, INVALID_REQUEST, "no method")

        params = message.get("params") or {}
        if not isinstance(params, dict):
            return _error(request_id, INVALID_PARAMS, "params must be an object")

        try:
            if method == "initialize":
                result = self._initialize(params)
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = self._tools_list()
            elif method == "tools/call":
                result = self._tools_call(params, actor, profile)
            elif method.startswith("notifications/"):
                return None
            else:
                return None if is_notification else _error(
                    request_id, METHOD_NOT_FOUND, f"method not found: {method}"
                )
        except _InvalidParams as exc:
            return _error(request_id, INVALID_PARAMS, str(exc))
        except Exception:
            log.exception("unhandled error in %s", method)
            return _error(request_id, INTERNAL_ERROR, "internal error")

        return None if is_notification else _result(request_id, result)

    # -- methods -----------------------------------------------------------

    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else LATEST_PROTOCOL_VERSION
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "odoo-mcp-governed", "version": __version__},
            "instructions": INSTRUCTIONS,
        }

    def _tools_list(self) -> dict[str, Any]:
        disabled = self.runtime.engine.policy.config.disabled_tools
        return {"tools": [t.schema() for name, t in TOOLS.items() if name not in disabled]}

    def _tools_call(
        self, params: dict[str, Any], actor: str, profile: str | None = None
    ) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or name not in TOOLS:
            raise _InvalidParams(f"unknown tool: {name!r}")
        if not isinstance(arguments, dict):
            raise _InvalidParams("arguments must be an object")

        tool = TOOLS[name]
        try:
            snapshot = self.runtime.snapshot_for(profile)
        except NoActiveProfile as exc:
            return _text(str(exc), is_error=True)

        ctx = ToolContext(
            runtime=self.runtime, actor=actor, snapshot=snapshot, tool=name, arguments=arguments
        )
        try:
            return _text(tool.handler(ctx))
        except GovernanceDenied as denied:
            log.info("denied %s for %s: %s", name, actor, denied.judgement.explain())
            return _text(agent_message(denied.judgement), is_error=True)
        except ToolInputError as exc:
            self._record_unguarded_failure(ctx, tool.operation, exc)
            return _text(f"Invalid arguments: {exc}", is_error=True)
        except OdooError as exc:
            self._record_unguarded_failure(ctx, tool.operation, exc)
            return _text(f"Odoo error ({exc.kind}): {exc}", is_error=True)
        except Exception as exc:
            self._record_unguarded_failure(ctx, tool.operation, exc)
            log.exception("tool %s failed", name)
            return _text("Internal error while running the tool.", is_error=True)

    def _record_unguarded_failure(self, ctx: ToolContext, operation, exc: Exception) -> None:
        """Failures that happened before the guard was entered — argument
        validation, mostly — would otherwise leave no trace. They are exactly
        the calls the repeated-errors detector needs to see: an agent guessing
        at arguments is an agent probing."""
        if ctx.guarded:
            return  # the guard already recorded it
        args = ctx.arguments
        model = args.get("model") if isinstance(args.get("model"), str) else None
        call = ToolCall(
            actor=ctx.actor,
            profile=ctx.snapshot.profile.name,
            tool=ctx.tool,
            operation=operation,
            model=model,
            arg_digest=digest_args(args),
        )
        self.runtime.audit.record(
            call, decision=Decision.ALLOW, outcome=Outcome.ERROR, error_type=type(exc).__name__
        )


class _InvalidParams(ValueError):
    pass
