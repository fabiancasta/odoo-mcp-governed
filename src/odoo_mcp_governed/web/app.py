"""The HTTP application: MCP endpoint, health check, admin panel.

Hardening carried in from day one, each item for a concrete reason:

* No ``/docs``, ``/redoc`` or ``/openapi.json`` — an API map is reconnaissance.
* Request bodies are capped (``MAX_BODY_MB``) by counting bytes as they
  arrive, so a chunked upload without ``Content-Length`` is capped too.
* Unhandled errors return a bare 500; details go to the server log only.
* Strict security headers on every response; the admin pages additionally
  run under a CSP that allows no script at all.
* ``Mcp-Session-Id`` is validated against a narrow pattern and never echoed
  back unvalidated.
* Rate limits per client IP on the MCP endpoint, health check and login.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import time
from dataclasses import replace
from typing import Any
from urllib.parse import urlencode, urlsplit

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from .. import __version__
from ..governance import ChainStatus, Decision, Operation, Outcome, ToolCall
from ..governance.agents import AgentError, AgentRule, parse_vars, rule_problem, vars_problem
from ..governance.approvals import GRANT_MINUTES
from ..governance.policy import is_system_model
from ..odoo import OdooClient, OdooError
from ..policy_store import LIST_FIELDS
from ..profiles import PROFILE_NAME, Profile, ProfileError
from ..protocol import INVALID_REQUEST, PARSE_ERROR, Dispatcher, _error
from ..runtime import Runtime, UndoError
from ..storage import read_json, write_private_json
from ..tools import TOOLS
from ..tuning import LIMITS, TuningError
from . import permissions, views
from .auth import AdminSessions, AuthError, TokenStore, csrf_matches, password_matches, verify_token
from .metrics import summarise
from .ratelimit import RateLimiter
from .totp import TotpVerifier

log = logging.getLogger(__name__)

SESSION_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
ACTOR_NAME = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")

BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
ADMIN_CSP = (
    "default-src 'none'; script-src 'self'; connect-src 'self'; "
    "style-src 'unsafe-inline'; img-src 'self' data:; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)
API_CSP = "default-src 'none'; frame-ancestors 'none'"

MODEL_NAME = re.compile(r"^(\*|[a-z][a-z0-9_]*(\.[a-z0-9_]+)*)$")

FLASH = {
    "profile_saved": ("Profile saved.", "ok"),
    "profile_activated": ("Profile activated — the next call goes to the new instance.", "ok"),
    "profile_deleted": ("Profile deleted.", "ok"),
    "policy_applied": ("Policy applied to the next call.", "ok"),
    "policy_unchanged": ("Nothing changed.", "ok"),
    "token_regenerated": (
        "New token generated. Revoke the previous one on the Agents page if it is no "
        "longer needed.",
        "ok",
    ),
    "agent_saved": ("Agent saved. Its rule applies to its next call.", "ok"),
    "agent_deleted": ("Agent deleted: tokens revoked, agent blocked, rule removed. Its audit "
                      "history stays.", "ok"),
    "agent_archived": ("Agent archived: tokens revoked and agent blocked. Find it under "
                       "“Archived agents” to restore it.", "ok"),
    "agent_restored": ("Agent restored and unblocked. Issue it a new token.", "ok"),
    "token_revoked": ("Revoked. The token is refused from its next request.", "ok"),
    "grant_revoked": ("Standing approval withdrawn.", "ok"),
    "permissions_default": ("This profile uses the default permissions again.", "ok"),
    "anchor_written": ("Anchor written to anchors.log.", "ok"),
    "panic_on": ("PANIC: every agent is stopped. Calls are refused until you resume.", "bad"),
    "panic_off": ("Service resumed. Agents can call again.", "ok"),
    "panic_confirm": ("Tick 'confirm' to resume service.", "bad"),
    "actor_blocked": ("Agent blocked. Its next call is refused.", "ok"),
    "actor_unblocked": ("Agent unblocked.", "ok"),
    "undone": ("Change undone. The undo is in the audit log.", "ok"),
    "tuning_applied": ("Thresholds applied to the next call.", "ok"),
    "permissions_saved": ("Permissions saved and applied to the next call.", "ok"),
    "approved": ("Approved. The agent may now repeat that exact call once.", "ok"),
    "denied": ("Denied. The agent is told not to retry.", "ok"),
    "approval_gone": ("That request is no longer pending.", "bad"),
    "permissions_error": ("Permissions not saved: the form held an invalid value.", "bad"),
    "undo_confirm": ("Tick the box next to Undo to confirm.", "bad"),
    "csrf": ("Form expired. Please try again.", "bad"),
}


class HeaderSizeLimit:
    """Refuse requests whose headers add up to more than ``max_bytes``."""

    def __init__(self, app, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            size = sum(len(k) + len(v) for k, v in scope.get("headers") or [])
            if size > self.max_bytes:
                body = b'{"error": "request headers too large"}'
                await send({"type": "http.response.start", "status": 431,
                            "headers": [(b"content-type", b"application/json"),
                                        (b"content-length", str(len(body)).encode())]})
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


def nesting_depth_exceeds(value: Any, limit: int) -> bool:
    """Whether ``value`` nests lists and objects deeper than ``limit``.

    Iterative on purpose: the point is to refuse input that would exhaust
    recursion, so the check itself must not recurse.
    """
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, (list, dict)):
            if depth > limit:
                return True
            children = item.values() if isinstance(item, dict) else item
            stack.extend((child, depth + 1) for child in children)
    return False


class BodySizeLimit:
    """Buffer the body up to a limit, then hand it on; refuse anything larger.

    Counting bytes as they arrive — rather than trusting ``Content-Length`` —
    is what catches chunked uploads, which carry no length up front.
    """

    def __init__(self, app, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD", "OPTIONS"):
            await self.app(scope, receive, send)
            return
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_bytes:
            await self._too_large(send)
            return
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > self.max_bytes:
                await self._too_large(send)
                return
            chunks.append(message.get("body", b""))
            if not message.get("more_body"):
                break
        body = b"".join(chunks)
        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    @staticmethod
    async def _too_large(send) -> None:
        payload = b'{"error":"request body too large"}'
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(payload)).encode())]})
        await send({"type": "http.response.body", "body": payload})


def create_app(runtime: Runtime) -> FastAPI:
    settings = runtime.settings
    settings.require_http_secrets()

    app = FastAPI(
        title="odoo-mcp-governed",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    dispatcher = Dispatcher(runtime)
    sessions = AdminSessions(settings.admin_session_ttl)
    tokens = TokenStore(settings)
    limits = {
        "mcp": RateLimiter(settings.rate_limit_mcp),
        "mcp_ip": RateLimiter(settings.rate_limit_mcp_ip),
        "auth_fail": RateLimiter(settings.rate_limit_auth_fail),
        "health": RateLimiter(settings.rate_limit_health),
        "login": RateLimiter(settings.rate_limit_login),
    }
    totp = TotpVerifier(settings.admin_totp_secret) if settings.admin_totp_secret else None
    cookie_name = "__Host-gov_admin" if settings.https_mode else "gov_admin"
    chain_cache: dict[str, Any] = {"at": 0.0, "status": None}

    app.add_middleware(BodySizeLimit, max_bytes=int(settings.max_body_mb * 1024 * 1024))
    app.add_middleware(HeaderSizeLimit, max_bytes=settings.max_header_kb * 1024)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        views.NAV_STATE.set(lambda: {
            "approvals": len(runtime.approvals.pending()),
            "panic": runtime.engine.policy.config.panic,
        })
        response = await call_next(request)
        for key, value in BASE_HEADERS.items():
            response.headers.setdefault(key, value)
        is_html = response.headers.get("content-type", "").startswith("text/html")
        response.headers.setdefault("Content-Security-Policy", ADMIN_CSP if is_html else API_CSP)
        if settings.https_mode:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        log.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse({"error": "internal error"}, status_code=500)

    # -- helpers -----------------------------------------------------------

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def too_many(retry: int) -> Response:
        return JSONResponse(
            {"error": "rate limit exceeded"}, status_code=429, headers={"Retry-After": str(retry)}
        )

    def limited(bucket: str, request: Request, key: str | None = None,
                cost: int = 1) -> Response | None:
        allowed, retry = limits[bucket].hit(key or client_ip(request), cost)
        return None if allowed else too_many(retry)

    def origin_of(url: str) -> str:
        parts = urlsplit(url.strip())
        return f"{parts.scheme}://{parts.netloc}".lower() if parts.scheme else ""

    trusted_origins = {origin_of(o) for o in settings.mcp_allowed_origins} - {""}
    if settings.mcp_public_url:
        trusted_origins.add(origin_of(settings.mcp_public_url))

    def origin_allowed(origin: str | None) -> bool:
        """The DNS-rebinding check the MCP specification asks for.

        A browser always says where a request came from; a web page that got
        its hostname to resolve to 127.0.0.1 still sends its own Origin. CLI
        and desktop clients send none, and are not what this defends against.
        """
        if origin is None:
            return True
        if origin_of(origin) in trusted_origins:
            return True
        host = urlsplit(origin).hostname or ""
        return host in ("localhost", "127.0.0.1", "::1")

    def chain_status(force: bool = False) -> ChainStatus:
        # Full verification is linear in the log size; the dashboard refreshes
        # it at most every 30 seconds unless an action asks for it.
        now = time.monotonic()
        if force or chain_cache["status"] is None or now - chain_cache["at"] > 30:
            chain_cache["status"] = runtime.audit.verify()
            chain_cache["at"] = now
        return chain_cache["status"]

    def session_for(request: Request):
        return sessions.get(request.cookies.get(cookie_name))

    def admin_actor(request: Request) -> str:
        return f"admin@{client_ip(request)}"

    def back(code: str, path: str = "/admin") -> RedirectResponse:
        return RedirectResponse(f"{path}?{urlencode({'m': code})}", status_code=303)

    async def admin_form(request: Request):
        """The session and form of an admin POST, or ``None`` if unauthorised."""
        session = session_for(request)
        if session is None:
            return None, None
        form = await request.form()
        if not csrf_matches(session, form.get("csrf")):
            return session, None
        return session, form

    # -- MCP ---------------------------------------------------------------

    async def mcp_endpoint(request: Request) -> Response:
        if (blocked := limited("mcp_ip", request)) is not None:
            return blocked
        ip = client_ip(request)
        if not origin_allowed(request.headers.get("origin")):
            return JSONResponse({"error": "origin not allowed"}, status_code=403)
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        try:
            if scheme.lower() != "bearer" or not token.strip():
                raise AuthError("missing bearer token")
            claims = verify_token(settings, token.strip())
            refusal = runtime.agents.refusal(
                claims, require_registered=settings.require_registered_tokens)
            if refusal:
                raise AuthError(refusal)
        except AuthError as exc:
            # Limited per IP, but only ever applied to failures: a valid token
            # from the same IP — another container on the same Docker bridge —
            # must keep working while someone floods bad ones. Once an IP is
            # over the limit its failures are no longer audited one by one,
            # so a flood cannot flood the audit log either.
            if retry := limits["auth_fail"].exhausted(ip):
                return too_many(retry)
            limits["auth_fail"].hit(ip)
            # Failed authentication is recorded: a stream of them is a
            # credential-stuffing attempt, and the audit log should show it.
            runtime.audit.record(
                ToolCall(actor=f"anonymous@{ip}", profile=runtime.profile_name,
                         tool="mcp.auth", operation=Operation.ADMIN),
                decision=Decision.DENY,
                reasons=(f"auth_failed: {exc}",),
                outcome=Outcome.DENIED,
            )
            # Why it failed stays in the audit log above. The caller learns only
            # that it failed: "expired" versus "wrong issuer" is a hint for the
            # next attempt, and a fixed text cannot leak anything internal.
            return JSONResponse(
                {"error": "invalid or expired token"},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )
        actor = claims["sub"]

        session_header = request.headers.get("mcp-session-id")
        if session_header is not None and not SESSION_ID.match(session_header):
            return JSONResponse({"error": "invalid Mcp-Session-Id"}, status_code=400)

        content_type = request.headers.get("content-type", "")
        if "application/json" not in content_type:
            return JSONResponse({"error": "Content-Type must be application/json"}, status_code=415)
        try:
            payload = json.loads(await request.body())
        except (ValueError, UnicodeDecodeError, RecursionError):
            # RecursionError: tens of thousands of nested brackets.
            return JSONResponse(_error(None, PARSE_ERROR, "parse error"), status_code=400)
        if nesting_depth_exceeds(payload, settings.max_json_depth):
            return JSONResponse(
                _error(None, INVALID_REQUEST,
                       f"message nests deeper than {settings.max_json_depth} levels"),
                status_code=400,
            )

        messages = payload if isinstance(payload, list) else [payload]
        if len(messages) > settings.mcp_max_batch:
            return JSONResponse(
                _error(None, INVALID_REQUEST,
                       f"batch of {len(messages)} exceeds the limit of {settings.mcp_max_batch}"),
                status_code=400,
            )
        # Per actor, not per IP: every client behind a Docker bridge or a
        # proxy shares one address. Each message in a batch is one request.
        blocked = limited("mcp", request, key=f"actor:{actor}", cost=max(len(messages), 1))
        if blocked is not None:
            return blocked

        pinned = claims.get("profile")
        pinned = str(pinned) if isinstance(pinned, str) and pinned else None
        rule = runtime.engine.policy.config.agent_rules.get(actor)
        if rule is not None and rule.profile:
            # The registry pins the agent; a token claiming another profile
            # is refused by policy rather than quietly rerouted.
            pinned = pinned or rule.profile
        if pinned is None and settings.require_pinned_profile:
            runtime.audit.record(
                ToolCall(actor=actor, profile=runtime.profile_name, tool="mcp.auth",
                         operation=Operation.ADMIN),
                decision=Decision.DENY,
                reasons=("profile_not_pinned: REQUIRE_PINNED_PROFILE is on and this agent "
                         "has no pinned profile",),
                outcome=Outcome.DENIED,
            )
            return JSONResponse(
                {"error": "this agent is not pinned to an Odoo profile; ask the administrator"},
                status_code=403)
        try:
            variables = parse_vars(claims.get("vars") if isinstance(claims.get("vars"), dict)
                                   else None)
        except AgentError:
            variables = {}
        result = await run_in_threadpool(dispatcher.handle_payload, payload, actor, pinned,
                                         variables)
        headers: dict[str, str] = {}
        if any(isinstance(m, dict) and m.get("method") == "initialize" for m in messages):
            headers["Mcp-Session-Id"] = secrets.token_urlsafe(24)
        if result is None:
            return Response(status_code=202, headers=headers)
        return JSONResponse(result, headers=headers)

    app.add_api_route("/mcp", mcp_endpoint, methods=["POST"])
    app.add_api_route("/", mcp_endpoint, methods=["POST"])

    @app.api_route("/mcp", methods=["GET", "DELETE"])
    async def mcp_other() -> Response:
        # No server-initiated stream and no server-side session state to end,
        # both of which the MCP spec lets a server decline with 405.
        return JSONResponse({"error": "method not allowed"}, status_code=405,
                            headers={"Allow": "POST"})

    @app.get("/")
    async def root() -> dict[str, Any]:
        return {"name": "odoo-mcp-governed", "version": __version__, "mcp_endpoint": "/mcp"}

    @app.get("/health")
    async def health(request: Request) -> Response:
        if (blocked := limited("health", request)) is not None:
            return blocked
        profile = runtime.profiles.active()
        if profile is None:
            odoo = "unconfigured"
        else:
            # Version needs no credentials; a short timeout keeps a hung Odoo
            # from hanging the health check. No error text is returned.
            probe = OdooClient(profile.url, profile.database, profile.username, "",
                               ssl_verify=profile.ssl_verify, timeout=min(5.0, profile.timeout))
            odoo = "reachable" if await run_in_threadpool(probe.ping) else "unreachable"
        return JSONResponse({"status": "ok", "odoo": odoo})

    # -- admin: session ----------------------------------------------------

    @app.get("/admin", response_class=HTMLResponse)
    async def admin_home(request: Request, edit: str | None = None, m: str | None = None,
                         tab: str = ""):
        session = session_for(request)
        if session is None:
            return HTMLResponse(views.login_page(totp=totp is not None))
        return await run_in_threadpool(lambda: render_dashboard(
            session, edit_name=edit, flash_code=m, tab=tab[:20]))

    def render_dashboard(session, *, edit_name=None, flash_code=None, error=None,
                         edit_override=None, status_code=200, tab="") -> HTMLResponse:
        flash, kind = FLASH.get(flash_code or "", (None, "ok"))
        if error:
            flash, kind = error, "bad"
        edit = edit_override
        if edit is None and edit_name and PROFILE_NAME.match(edit_name):
            profile = runtime.profiles.get(edit_name)
            edit = profile.public() if profile else None
        snap = runtime.profiles.active()
        odoo_ok = None
        if snap is not None:
            odoo_ok = OdooClient(snap.url, snap.database, snap.username, "",
                                 ssl_verify=snap.ssl_verify, timeout=3).ping()
        warnings = runtime.engine.policy.config.validate()
        agents = _agents(runtime)
        if odoo_ok:
            try:
                access = runtime.snapshot().settings_access()
            except Exception:  # noqa: BLE001 - a warning must never break the panel
                access = None
            if access is not False:
                warnings.append(
                    f"The Odoo user of profile '{snap.name}' has Settings access (or it could "
                    "not be verified): if a policy rule is missing, Odoo will not stop the agent. "
                    "Use a dedicated least-privilege user."
                )
        if not runtime.audit.keyed:
            warnings.append("AUDIT_HMAC_KEY is not set — the audit chain is unkeyed.")
        html = views.dashboard(
            csrf=session.csrf,
            profiles=runtime.profiles.public(),
            active=runtime.profiles.active_name,
            odoo_ok=odoo_ok,
            chain=chain_status(),
            keyed=runtime.audit.keyed,
            policy=runtime.policy_store.as_dict(),
            policy_source=runtime.policy_store.source,
            tool_names=TOOLS.keys(),
            warnings=warnings,
            edit=edit,
            flash=flash,
            flash_kind=kind,
            panic=runtime.engine.policy.config.panic,
            agents=agents,
            summary=_summary(runtime),
            max_risk=max((a[1] for a in agents), default=0),
            tuning=runtime.tuning.values,
            tuning_source=runtime.tuning.source,
            tab=tab or _tab_for(flash_code, error, edit),
            profile_cards=views.profile_cards(
                runtime.profiles.public(), summaries=profile_summaries(),
                own=set(runtime.policy_store.config.profile_lists),
                agents_by_profile=pinned_agents()),
        )
        return HTMLResponse(html, status_code=status_code)

    def profile_summaries() -> dict[str, str]:
        from .agent_tree import counts, effective
        ro = runtime.profiles.read_only_names()
        return {p["name"]: counts(effective(runtime.engine.policy.config, None, p["name"], ro))
                for p in runtime.profiles.public()}

    def pinned_agents() -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for name, rule in runtime.agents.rules().items():
            if rule.profile:
                out.setdefault(rule.profile, []).append(name)
        return out

    def agent_summaries(names) -> dict[str, str]:
        """Read / change / delete counts on the profile each agent lands on."""
        from .agent_tree import counts, effective
        cfg, ro = runtime.engine.policy.config, runtime.profiles.read_only_names()
        rules, active = cfg.agent_rules, runtime.profiles.active_name
        out = {}
        for name in names:
            rule = rules.get(name)
            profile = (rule.profile if rule and rule.profile else active) or ""
            if profile:
                out[name] = (counts(effective(cfg, rule, profile, ro))
                             + f"<span>on {esc_(profile)}</span>")
        return out

    def actor_stats() -> dict[str, tuple[int, int, str]]:
        from datetime import timedelta as _td

        from ..governance.events import utcnow
        stats = runtime.audit.store.actor_stats(utcnow() - _td(hours=24))
        return {a: s for a, s in stats.items()
                if not a.startswith(("admin@", "anonymous@")) and a != "system"}

    async def dashboard_error(session, error: str, **kwargs) -> HTMLResponse:
        return await run_in_threadpool(
            render_dashboard, session, error=error, status_code=400, **kwargs
        )

    @app.post("/admin", response_class=HTMLResponse)
    async def admin_login(request: Request):
        allowed, retry = limits["login"].hit(client_ip(request))
        if not allowed:
            return HTMLResponse(
                views.login_page(f"Too many attempts. Try again in {retry}s.",
                                 totp=totp is not None),
                status_code=429, headers={"Retry-After": str(retry)},
            )
        form = await request.form()
        supplied = str(form.get("password") or "")
        ok = password_matches(settings.admin_password, supplied)
        if totp is not None:
            # Both checked every time, so the answer never says which was wrong.
            ok = totp.verify(str(form.get("totp") or "")) and ok
        await run_in_threadpool(runtime.record_login, admin_actor(request), success=ok)
        if not ok:
            error = "Wrong password or code." if totp is not None else "Wrong password."
            return HTMLResponse(views.login_page(error, totp=totp is not None),
                                status_code=401)
        sid, _ = sessions.create(client_ip(request))
        response = RedirectResponse("/admin/agents", status_code=303)
        response.set_cookie(
            cookie_name, sid, httponly=True, samesite="strict", secure=settings.https_mode,
            path="/", max_age=int(settings.admin_session_ttl.total_seconds()),
        )
        return response

    @app.post("/admin/logout")
    async def admin_logout(request: Request):
        sessions.revoke(request.cookies.get(cookie_name))
        response = RedirectResponse("/admin", status_code=303)
        response.delete_cookie(cookie_name, path="/")
        return response

    # -- admin: profiles ---------------------------------------------------

    @app.post("/admin/profile/save", response_class=HTMLResponse)
    async def profile_save(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf")
        try:
            timeout = float(form.get("timeout") or 30)
        except ValueError:
            timeout = -1
        profile = Profile(
            name=str(form.get("name") or "").strip(),
            url=str(form.get("url") or "").strip().rstrip("/"),
            database=str(form.get("database") or "").strip(),
            username=str(form.get("username") or "").strip(),
            api_key=str(form.get("api_key") or ""),
            password=str(form.get("password") or ""),
            ssl_verify=form.get("ssl_verify") == "1",
            timeout=timeout,
            environment=str(form.get("environment") or "production"),
            allow_writes=form.get("allow_writes") == "1",
            sandbox=form.get("level") == "sandbox",
            configurator=form.get("level") == "configurator",
        )
        try:
            await run_in_threadpool(runtime.save_profile, profile, actor=admin_actor(request))
        except ProfileError as exc:
            return await dashboard_error(session, str(exc), edit_override=profile.public())
        return back("profile_saved")

    @app.post("/admin/profile/activate", response_class=HTMLResponse)
    async def profile_activate(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf")
        try:
            await run_in_threadpool(runtime.activate_profile, str(form.get("name") or ""),
                                    actor=admin_actor(request))
        except ProfileError as exc:
            return await dashboard_error(session, str(exc))
        return back("profile_activated")

    @app.post("/admin/profile/delete", response_class=HTMLResponse)
    async def profile_delete(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf")
        if form.get("confirm") != "yes":
            return await dashboard_error(session, "Tick 'confirm' to delete.")
        try:
            await run_in_threadpool(runtime.delete_profile, str(form.get("name") or ""),
                                    actor=admin_actor(request))
        except ProfileError as exc:
            return await dashboard_error(session, str(exc))
        return back("profile_deleted")

    # -- admin: live dashboard ---------------------------------------------

    @app.get("/static/panel.js")
    async def panel_js() -> Response:
        return Response(views.PANEL_JS, media_type="application/javascript",
                        headers={"Cache-Control": "no-cache"})

    @app.get("/admin/live", response_class=HTMLResponse)
    async def live_fragment(request: Request):
        if session_for(request) is None:
            return RedirectResponse("/admin", status_code=303)

        def build() -> str:
            agents = _agents(runtime)
            return views.charts_fragment(
                _summary(runtime), max_risk=max((a[1] for a in agents), default=0)
            )

        return HTMLResponse(await run_in_threadpool(build),
                            headers={"Cache-Control": "no-store"})

    @app.post("/admin/tuning")
    async def tuning_update(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf")
        values = {k: form.get(k) for k in LIMITS}
        try:
            changed = await run_in_threadpool(runtime.update_tuning, values,
                                              actor=admin_actor(request))
        except TuningError as exc:
            return await dashboard_error(session, f"Thresholds not applied: {exc}")
        return back("tuning_applied" if changed else "policy_unchanged")

    # -- admin: permissions table -----------------------------------------

    def odoo_models(profile: str = "") -> list[dict[str, Any]]:
        snap = runtime.snapshot_for(profile or None)
        return runtime.cache.get_or_set(
            (snap.profile.name, "permissions", "ir.model"),
            lambda: snap.client.execute(
                "ir.model", "search_read", [[]], {"fields": ["model", "name", "transient"]}
            ),
        )

    def seen_models() -> dict[str, list[str]]:
        return read_json(settings.data_dir / "models_seen.json", default=None) or {}

    def target_profile(value: Any) -> str:
        """A profile tab of the permissions page: '' is the default lists."""
        name = str(value or "").strip()
        return name if name and runtime.profiles.get(name) is not None else ""

    def lists_for(profile: str) -> dict[str, frozenset[str]]:
        cfg = runtime.policy_store.config.for_profile(profile or None)
        return {k: frozenset(getattr(cfg, k)) for k in LIST_FIELDS}

    def save_lists(profile: str, lists: dict[str, Any], actor: str) -> None:
        if profile:
            runtime.set_profile_lists(profile, lists, actor=actor)
        else:
            runtime.update_policy({k: sorted(v) for k, v in lists.items()}, actor=actor)

    def to_permissions(code: str, profile: str) -> RedirectResponse:
        query = {"m": code} | ({"profile": profile} if profile else {})
        return RedirectResponse(f"/admin/permissions?{urlencode(query)}", status_code=303)

    @app.get("/admin/permissions", response_class=HTMLResponse)
    async def permissions_view(request: Request, q: str = "", m: str | None = None,
                               profile: str = ""):
        session = session_for(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        profile = target_profile(profile)
        error = None
        try:
            models = await run_in_threadpool(odoo_models, profile)
        except Exception as exc:  # noqa: BLE001 - shown to the admin, not raised
            models, error = [], f"Could not read the model list from Odoo ({type(exc).__name__})."
        cfg = runtime.policy_store.config
        flash, kind = FLASH.get(m or "", (None, "ok"))
        tabs = [(p["name"], p.get("environment", ""), p["name"] in cfg.profile_lists)
                for p in runtime.profiles.public()]
        return HTMLResponse(views.permissions_page(
            csrf=session.csrf, groups=permissions.group(models if isinstance(models, list)
                                                        else [], q),
            policy={k: sorted(v) for k, v in lists_for(profile).items()},
            denied=cfg.denied_models,
            seen=set(seen_models().get(profile or runtime.profile_name, [])), query=q[:100],
            error=error, flash=flash, flash_kind=kind, profiles=tabs, profile=profile,
            own=profile in cfg.profile_lists,
            read_only=bool(profile) and profile in runtime.profiles.read_only_names(),
        ))

    def mark_seen(profile: str, models: list[str]) -> None:
        seen = seen_models()
        key = profile or runtime.profile_name
        seen[key] = sorted(set(seen.get(key, [])) | set(models))
        write_private_json(settings.data_dir / "models_seen.json", seen)

    def save_levels(request: Request, profile: str, levels: dict[str, str]):
        denied = runtime.policy_store.config.denied_models
        lists = {k: set(v) for k, v in lists_for(profile).items()}
        for model, level in levels.items():
            if model in denied or level not in ("none", "read", "write", "delete"):
                continue
            views.set_level(lists, model, level)
        save_lists(profile, lists, admin_actor(request))
        mark_seen(profile, list(levels))

    @app.post("/admin/permissions/app")
    async def permissions_app(request: Request):
        """One click: every business model of an app at one level."""
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf", "/admin/permissions")
        profile = target_profile(form.get("profile"))
        app_key, level = str(form.get("app") or ""), str(form.get("level") or "")
        try:
            models = await run_in_threadpool(odoo_models, profile)
        except Exception:  # noqa: BLE001 - nothing to apply without the list
            return to_permissions("permissions_error", profile)
        targets = [str(m.get("model")) for m in models if isinstance(m, dict)
                   and not m.get("transient") and m.get("model")
                   and permissions.app_key(str(m["model"])) == app_key
                   and not is_system_model(str(m["model"]))]
        if not targets or level not in ("none", "read", "write", "delete"):
            return to_permissions("permissions_error", profile)
        try:
            await run_in_threadpool(save_levels, request, profile, dict.fromkeys(targets, level))
        except (ValueError, KeyError):
            return to_permissions("permissions_error", profile)
        query = {"m": "permissions_saved"} | ({"profile": profile} if profile else {})
        return RedirectResponse(f"/admin/permissions?{urlencode(query)}#app-{app_key}",
                                status_code=303)

    @app.post("/admin/permissions/models")
    async def permissions_models(request: Request):
        """The fine-tune form of an app: one level per model."""
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf", "/admin/permissions")
        profile = target_profile(form.get("profile"))
        levels = {k[4:]: str(v) for k, v in form.items()
                  if k.startswith("lvl:") and MODEL_NAME.match(k[4:]) and k[4:] != "*"}
        if not levels:
            return to_permissions("permissions_error", profile)
        try:
            await run_in_threadpool(save_levels, request, profile, levels)
        except (ValueError, KeyError):
            return to_permissions("permissions_error", profile)
        app_key = str(form.get("app") or "")
        query = {"m": "permissions_saved"} | ({"profile": profile} if profile else {})
        anchor = f"#app-{app_key}" if MODEL_NAME.match(app_key) else ""
        return RedirectResponse(f"/admin/permissions?{urlencode(query)}{anchor}",
                                status_code=303)

    @app.post("/admin/permissions/reset")
    async def permissions_reset(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        profile = target_profile(form.get("profile") if form is not None else "")
        if form is None or not profile:
            return back("csrf", "/admin/permissions")
        await run_in_threadpool(lambda: runtime.set_profile_lists(
            profile, None, actor=admin_actor(request)))
        return to_permissions("permissions_default", profile)

    @app.post("/admin/permissions/chip")
    async def permissions_chip(request: Request):
        """One model in or out of one gate: the + and × of the quick view."""
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf", "/admin/permissions")
        profile = target_profile(form.get("profile"))
        gate, action = str(form.get("gate") or ""), str(form.get("action") or "")
        model = str(form.get("model") or "").strip()
        order = {"r": 0, "w": 1, "d": 2}
        if gate not in order or action not in ("add", "remove") or not MODEL_NAME.match(model):
            return to_permissions("permissions_error", profile)
        lists = {k: set(v) for k, v in lists_for(profile).items()}
        if action == "add":
            # Change and delete include read.
            for name in {"r": LIST_FIELDS[:1], "w": LIST_FIELDS[:2],
                         "d": (LIST_FIELDS[0], LIST_FIELDS[2])}[gate]:
                lists[name].add(model)
        else:
            # Taking read away takes change and delete with it.
            for name in LIST_FIELDS if gate == "r" else (LIST_FIELDS[order[gate]],):
                lists[name].discard(model)
        try:
            await run_in_threadpool(save_lists, profile, lists, admin_actor(request))
        except (ValueError, KeyError):
            return to_permissions("permissions_error", profile)
        target = back_to(form, "")
        if target:
            return RedirectResponse(f"{target}&m=permissions_saved", status_code=303)
        return to_permissions("permissions_saved", profile)

    @app.post("/admin/permissions")
    async def permissions_save(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf", "/admin/permissions")
        profile = target_profile(form.get("profile"))
        cfg = runtime.policy_store.config.for_profile(profile or None)
        shown = {str(v) for v in form.getlist("shown")} - cfg.denied_models
        try:
            models = await run_in_threadpool(odoo_models, profile)
        except Exception:  # noqa: BLE001 - whole-app ticks then cover only what was shown
            models = []
        by_app: dict[str, set[str]] = {}
        for name in shown:
            by_app.setdefault(permissions.app_key(name), set()).add(name)
        lists = {}
        for key, field_name in (("r", "allowed_models"), ("w", "writable_models"),
                                ("d", "deletable_models")):
            ticked = {str(v) for v in form.getlist(key)}
            for app_key in form.getlist(f"app_{key}"):
                ticked |= by_app.get(str(app_key), set())
            if form.get(f"all_{key}") == "1":
                lists[field_name] = frozenset({"*"})
            else:
                lists[field_name] = permissions.merge(getattr(cfg, field_name), shown, ticked)
        if "*" not in lists["allowed_models"]:
            implied = (lists["writable_models"] | lists["deletable_models"]) - {"*"}
            lists["allowed_models"] = lists["allowed_models"] | implied
        try:
            await run_in_threadpool(save_lists, profile, lists, admin_actor(request))
        except (ValueError, KeyError):
            return to_permissions("permissions_error", profile)
        if isinstance(models, list) and models:
            seen = seen_models()
            seen[profile or runtime.profile_name] = sorted(
                str(x.get("model")) for x in models if isinstance(x, dict) and x.get("model"))
            write_private_json(settings.data_dir / "models_seen.json", seen)
        return to_permissions("permissions_saved", profile)

    # -- admin: activity report --------------------------------------------

    @app.get("/admin/report", response_class=HTMLResponse)
    async def report_view(request: Request, days: int = 7, profile: str = ""):
        if session_for(request) is None:
            return RedirectResponse("/admin", status_code=303)
        from .. import report

        chosen = profile if profile and runtime.profiles.get(profile) else None
        data = await run_in_threadpool(report.build, runtime, days=max(1, min(days, 366)),
                                       profile=chosen)
        return HTMLResponse(views.report_html(
            data, profiles=[p["name"] for p in runtime.profiles.public()]))

    # -- admin: approvals --------------------------------------------------

    @app.get("/admin/approvals", response_class=HTMLResponse)
    async def approvals_view(request: Request, m: str | None = None):
        session = session_for(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        flash, kind = FLASH.get(m or "", (None, "ok"))
        return HTMLResponse(views.approvals_page(
            csrf=session.csrf, pending=runtime.approvals.pending(),
            recent=runtime.approvals.recent(), grants=runtime.approvals.grants(),
            enabled=bool(runtime.engine.policy.config.approval_required),
            notifier=runtime.notifier.enabled,
            ttl_minutes=int(runtime.approvals.ttl.total_seconds() // 60),
            flash=flash, flash_kind=kind,
        ))

    @app.post("/admin/approvals/decide")
    async def approvals_decide(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf", "/admin/approvals")
        raw, decision = str(form.get("id") or ""), form.get("decision")
        if not raw.isdigit() or decision not in ("approve", "deny", "approve_similar",
                                                 "approve_group", "deny_group"):
            return back("approval_gone", "/admin/approvals")
        minutes = str(form.get("minutes") or "30")
        grant = int(minutes) if decision == "approve_similar" and minutes.isdigit() else 0
        if decision == "approve_similar" and grant not in GRANT_MINUTES:
            return back("approval_gone", "/admin/approvals")
        decided = await run_in_threadpool(
            lambda: runtime.decide_approval(
                int(raw), decision.startswith("approve"), actor=admin_actor(request),
                grant_minutes=grant, group=decision.endswith(("_group", "_similar"))))
        decision = "approve" if decision.startswith("approve") else "deny"
        if not decided:
            return back("approval_gone", "/admin/approvals")
        return back("approved" if decision == "approve" else "denied", "/admin/approvals")

    @app.post("/admin/approvals/grant/revoke")
    async def grant_revoke(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        raw = str(form.get("id") or "") if form is not None else ""
        if not raw.isdigit():
            return back("csrf", "/admin/approvals")
        with runtime.admin_action(admin_actor(request), "admin.approval.grant_revoke",
                                  detail={"grant": int(raw)}):
            runtime.approvals.revoke_grant(int(raw))
        return back("grant_revoked", "/admin/approvals")

    # -- admin: agent registry -----------------------------------------------

    def agents_page(session, *, flash=None, kind="ok", issued=None, edit=None, tab="",
                    open_form=False):
        rules = runtime.agents.rules()
        seen = actor_stats()
        names = set(rules) | set(seen) | {t["actor"] for t in runtime.agents.tokens()}
        return HTMLResponse(views.agents_page(
            csrf=session.csrf, rules=rules, tokens=runtime.agents.tokens(),
            profiles=[p["name"] for p in runtime.profiles.public()],
            tools=sorted(TOOLS), issued=issued, edit=rules.get(edit) if edit else None,
            flash=flash, flash_kind=kind, require_registered=settings.require_registered_tokens,
            selected=tab, read_only_profiles=runtime.profiles.read_only_names(),
            seen=seen, summaries=agent_summaries(names),
            new_name=edit if edit and edit not in rules and ACTOR_NAME.match(edit) else "",
            open_form=open_form or kind == "bad", archived=runtime.agents.archived(),
        ))

    def roster() -> list[tuple[str, str]]:
        rules, seen = runtime.agents.rules(), actor_stats()
        names = sorted((set(rules) | set(seen) | {t["actor"] for t in runtime.agents.tokens()})
                       - set(runtime.agents.archived()))
        out = []
        for n in names:
            rule = rules.get(n)
            bits = []
            if rule is None:
                bits.append("policy")
            else:
                bits += ["read-only"] * rule.read_only + ([f"📌 {rule.profile}"] if rule.profile
                                                          else [])
            if n in seen:
                bits.append(f"{seen[n][0]} calls/24h")
            out.append((n, " · ".join(bits) or "rule"))
        return out

    def render_tree(session, name: str, *, flash=None, kind="ok", issued=None):
        from .agent_tree import tree_page

        cfg = runtime.engine.policy.config
        rule = runtime.agents.rule(name)
        return HTMLResponse(tree_page(
            csrf=session.csrf, name=name, rule=rule, policy=cfg,
            profiles=runtime.profiles.public(), active=runtime.profiles.active_name,
            read_only_profiles=runtime.profiles.read_only_names(),
            tokens=runtime.agents.tokens(name), stats=actor_stats().get(name),
            tools=sorted(TOOLS), blocked=name in cfg.blocked_actors, flash=flash,
            flash_kind=kind, agents_list=roster(), issued=issued,
            archived=runtime.agents.archived().get(name),
            edit_form=views.rule_form(csrf=session.csrf, e=rule or AgentRule(name=name),
                                      profiles=[p["name"] for p in runtime.profiles.public()],
                                      tools=sorted(TOOLS)),
        ))

    @app.get("/admin/agents/view", response_class=HTMLResponse)
    async def agent_view(request: Request, name: str = "", m: str | None = None):
        """One agent as a tree of what it can really do."""

        session = session_for(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if not ACTOR_NAME.match(name):
            return back("csrf", "/admin/agents")
        flash, kind = FLASH.get(m or "", (None, "ok"))
        return await run_in_threadpool(lambda: render_tree(session, name, flash=flash,
                                                           kind=kind))

    def back_to(form, default: str) -> str:
        """Where a quick action returns: the agent tree it came from, if any."""
        target = str(form.get("back") or "") if form is not None else ""
        if target.startswith("/admin/agents/view?name=") and ACTOR_NAME.match(
                target.split("=", 1)[1]):
            return target
        return default

    @app.post("/admin/agents/archive")
    async def agents_archive(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf", "/admin/agents")
        name, action = str(form.get("name") or ""), str(form.get("action") or "")
        if not ACTOR_NAME.match(name) or action not in ("archive", "delete", "restore"):
            return back("csrf", "/admin/agents")
        if action == "restore":
            await run_in_threadpool(lambda: runtime.restore_agent(name, actor=admin_actor(request)))
            return RedirectResponse(
                f"/admin/agents/view?{urlencode({'name': name, 'm': 'agent_restored'})}",
                status_code=303)
        if form.get("confirm") != "yes":
            return back("csrf", "/admin/agents")
        await run_in_threadpool(lambda: runtime.archive_agent(
            name, actor=admin_actor(request), delete_rule=action == "delete"))
        return back("agent_deleted" if action == "delete" else "agent_archived", "/admin/agents")

    @app.post("/admin/agents/quick")
    async def agents_quick(request: Request):
        """Read-only, quota and pinned profile from the agent tree; creates the
        rule if the agent had none."""
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf", "/admin/agents")
        name = str(form.get("name") or "")
        quota = str(form.get("daily_quota") or "0")
        if not ACTOR_NAME.match(name) or not quota.isdigit():
            return back("csrf", "/admin/agents")
        rule = runtime.agents.rule(name) or AgentRule(name=name)
        try:
            await run_in_threadpool(lambda: runtime.save_agent(replace(
                rule, read_only=form.get("read_only") == "yes", daily_quota=int(quota),
                profile=str(form.get("profile") or "")), actor=admin_actor(request)))
        except (AgentError, ValueError):
            return back("csrf", f"/admin/agents/view?name={name}")
        query = urlencode({"name": name, "m": "agent_saved"})
        return RedirectResponse(f"/admin/agents/view?{query}", status_code=303)

    @app.get("/admin/agents", response_class=HTMLResponse)
    async def agents_view(request: Request, m: str | None = None, edit: str | None = None,
                          tab: str = "", new: str = "", name: str = ""):
        session = session_for(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if name and ACTOR_NAME.match(name):
            return RedirectResponse(f"/admin/agents/view?{urlencode({'name': name})}",
                                    status_code=303)
        flash, kind = FLASH.get(m or "", (None, "ok"))
        return agents_page(session, flash=flash, kind=kind, edit=edit, tab=tab[:64],
                           open_form=bool(new or edit))

    @app.post("/admin/agents/model")
    async def agents_model(request: Request):
        """The + and × on an agent card: one model into or out of its rule."""
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf", "/admin/agents")
        name, model = str(form.get("name") or ""), str(form.get("model") or "").strip()
        kind = "tools" if form.get("kind") == "tool" else "models"
        valid = model in TOOLS if kind == "tools" else bool(MODEL_NAME.match(model))
        if not ACTOR_NAME.match(name) or not valid or form.get("action") not in (
                "add", "remove"):
            return back("csrf", "/admin/agents")
        rule = runtime.agents.rule(name) or AgentRule(name=name)
        current = getattr(rule, kind)
        values = current | {model} if form.get("action") == "add" else current - {model}
        await run_in_threadpool(lambda: runtime.save_agent(
            replace(rule, **{kind: frozenset(values)}), actor=admin_actor(request)))
        target = back_to(form, "/admin/agents")
        sep = "&" if "?" in target else "?"
        return RedirectResponse(f"{target}{sep}m=agent_saved", status_code=303)

    @app.post("/admin/agents/save", response_class=HTMLResponse)
    async def agents_save(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf", "/admin/agents")
        name = str(form.get("name") or "").strip()
        data = {
            "models": str(form.get("models") or ""), "tools": form.getlist("tools"),
            "read_only": form.get("read_only") == "yes",
            "daily_quota": str(form.get("daily_quota") or "0"),
            "profile": str(form.get("profile") or ""), "scope": str(form.get("scope") or ""),
            "note": str(form.get("note") or ""),
        }
        # Checked before, not caught after: what the operator reads is built
        # from the form, never from an exception.
        problem = rule_problem(data)
        if not ACTOR_NAME.match(name):
            problem = "agent names may only contain letters, digits and _ . @ -"
        elif data["profile"] and runtime.profiles.get(data["profile"]) is None:
            problem = "that profile does not exist"
        if problem:
            return agents_page(session, flash=f"Agent not saved: {problem}", kind="bad")
        try:
            rule = AgentRule.from_dict(name, data)
            await run_in_threadpool(runtime.save_agent, rule, actor=admin_actor(request))
        except (AgentError, ValueError):
            return agents_page(session, flash="Agent not saved: the form held an invalid value.",
                               kind="bad")
        return back("agent_saved", "/admin/agents")

    @app.post("/admin/agents/delete")
    async def agents_delete(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None or form.get("confirm") != "yes":
            return back("csrf", "/admin/agents")
        await run_in_threadpool(runtime.delete_agent, str(form.get("name") or ""),
                                actor=admin_actor(request))
        return back("agent_deleted", "/admin/agents")

    @app.post("/admin/agents/token", response_class=HTMLResponse)
    async def agents_token(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf", "/admin/agents")
        name = str(form.get("name") or "").strip()
        hours = str(form.get("hours") or "").strip()
        pairs = [v for v in str(form.get("vars") or "").split(",") if v.strip()]
        problem = vars_problem(pairs) or (
            None if ACTOR_NAME.match(name) else "agent names may only contain letters, digits "
            "and _ . @ -")
        if problem:
            return agents_page(session, flash=f"No token issued: {problem}", kind="bad")
        try:
            variables = parse_vars(pairs)
            issued = await run_in_threadpool(lambda: runtime.issue_agent_token(
                name, actor=admin_actor(request), hours=int(hours) if hours.isdigit() else None,
                variables=variables, label=str(form.get("label") or "")))
        except (AgentError, ValueError):
            return agents_page(session, flash="No token issued: invalid value.", kind="bad")
        # Shown once, in this response only: it is not stored to be shown again.
        if form.get("from_tree") == "1":
            return render_tree(session, name, issued=issued)
        return agents_page(session, issued=issued)

    @app.post("/admin/agents/revoke")
    async def agents_revoke(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf", "/admin/agents")
        name = str(form.get("name") or "")
        if form.get("kind") == "unregistered" and ACTOR_NAME.match(name):
            await run_in_threadpool(lambda: runtime.revoke_unregistered_tokens(
                name, actor=admin_actor(request)))
            return RedirectResponse(
                f"/admin/agents/view?{urlencode({'name': name, 'm': 'token_revoked'})}",
                status_code=303)
        if form.get("jti"):
            await run_in_threadpool(runtime.revoke_token, str(form.get("jti")),
                                    actor=admin_actor(request))
        elif form.get("name") and form.get("confirm") == "yes":
            await run_in_threadpool(runtime.revoke_agent_tokens, str(form.get("name")),
                                    actor=admin_actor(request))
        else:
            return back("csrf", "/admin/agents")
        return back("token_revoked", "/admin/agents")

    # -- admin: emergency controls ----------------------------------------

    @app.post("/admin/panic")
    async def panic_on(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf")
        # No confirmation on the way in: an emergency stop that asks "are you
        # sure?" is slower exactly when speed matters.
        await run_in_threadpool(runtime.set_panic, True, actor=admin_actor(request))
        return back("panic_on")

    @app.post("/admin/resume")
    async def panic_off(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf")
        if form.get("confirm") != "yes":
            return back("panic_confirm")
        await run_in_threadpool(runtime.set_panic, False, actor=admin_actor(request))
        return back("panic_off")

    async def _set_blocked(request: Request, blocked: bool):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf")
        try:
            await run_in_threadpool(runtime.set_actor_blocked, str(form.get("actor") or ""),
                                    blocked, actor=admin_actor(request))
        except ValueError as exc:
            return await dashboard_error(session, str(exc))
        return back("actor_blocked" if blocked else "actor_unblocked")

    @app.post("/admin/actor/block")
    async def actor_block(request: Request):
        return await _set_blocked(request, True)

    @app.post("/admin/actor/unblock")
    async def actor_unblock(request: Request):
        return await _set_blocked(request, False)

    # -- admin: policy -----------------------------------------------------

    @app.post("/admin/policy", response_class=HTMLResponse)
    async def policy_update(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf")
        enabled = set(form.getlist("enabled_tools"))
        changes: dict[str, Any] = {
            "disabled_tools": sorted(set(TOOLS) - enabled),
            "allow_execute_method": form.get("allow_execute_method") == "1",
        }
        for key in ("allowed_models", "writable_models", "deletable_models", "denied_models",
                    "execute_method_allowlist", "forbidden_methods", "sensitive_fields",
                    "transient_allowlist"):
            changes[key] = str(form.get(key) or "")
        changes["approval_required"] = [str(v) for v in form.getlist("approval_required")]
        changes["approval_bulk_threshold"] = int(form.get("approval_bulk_threshold") or 20)
        try:
            changes["max_records_per_call"] = int(form.get("max_records_per_call") or 500)
            _, changed = await run_in_threadpool(
                runtime.update_policy, changes, actor=admin_actor(request)
            )
        except (ValueError, KeyError) as exc:
            return await dashboard_error(session, f"Policy not applied: {exc}")
        return back("policy_applied" if changed else "policy_unchanged")

    # -- admin: token ------------------------------------------------------

    def mcp_url(request: Request) -> str:
        if settings.mcp_public_url:
            return settings.mcp_public_url.rstrip("/") + "/mcp"
        return str(request.base_url).rstrip("/") + "/mcp"

    @app.get("/token", response_class=HTMLResponse)
    async def token_view(request: Request):
        session = session_for(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        return HTMLResponse(views.token_page(
            csrf=session.csrf, token=tokens.current(), mcp_url=mcp_url(request),
            profiles=[p["name"] for p in runtime.profiles.public()],
        ))

    @app.post("/admin/token/regenerate")
    async def token_regenerate(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf", "/token")
        actor = str(form.get("actor") or "claude").strip()
        profile = str(form.get("profile") or "").strip() or None
        if not ACTOR_NAME.match(actor) or form.get("confirm") != "yes":
            return back("csrf", "/token")
        if profile is not None and runtime.profiles.get(profile) is None:
            return back("csrf", "/token")
        with runtime.admin_action(admin_actor(request), "admin.token.regenerate",
                                  detail={"actor": actor, "profile": profile}):
            tokens.regenerate(actor, profile, registry=runtime.agents)
        return back("token_regenerated", "/token")

    # -- admin: audit ------------------------------------------------------

    @app.get("/admin/logs", response_class=HTMLResponse)
    async def audit_view(request: Request, actor: str = "", tool: str = "", decision: str = "",
                         outcome: str = "", q: str = "", limit: int = 200, m: str | None = None,
                         model: str = "", kind: str = "", hours: int = 0, hour: str = "",
                         agents: str = ""):
        """The audit log, filtered. Every number on the dashboard links here
        with the filter that reproduces it."""
        session = session_for(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        from datetime import datetime as _dt
        from datetime import timedelta as _td

        from ..governance.events import utcnow
        from .metrics import CATEGORY_ORDER, categorise

        decisions: tuple[str, ...] = ()
        if decision == "flagged":
            decisions = (Decision.ALLOW_FLAGGED.value, Decision.THROTTLE.value)
        decision = decision if decision in {d.value for d in Decision} | {"flagged"} else ""
        outcome = outcome if outcome in {o.value for o in Outcome} else ""
        model = model if MODEL_NAME.match(model or "") and model != "*" else ""
        kind = kind if kind in CATEGORY_ORDER else ""
        since = until = None
        if hour:
            try:
                since = _dt.strptime(hour, "%Y-%m-%dT%H").replace(tzinfo=utcnow().tzinfo)
                until = since + _td(hours=1)
            except ValueError:
                hour = ""
        elif 0 < hours <= 24 * 90:
            since = (utcnow() - _td(hours=hours - 1)).replace(minute=0, second=0, microsecond=0)
        else:
            hours = 0
        wanted = max(1, min(limit, 2000))
        events = await run_in_threadpool(lambda: runtime.audit.store.search(
            actor=actor or None, tool_prefix=tool or None,
            decision=None if decisions else decision or None, decisions=decisions,
            outcome=outcome or None, text=q or None, model=model or None,
            since=since, until=until, agents_only=agents == "1",
            limit=5000 if kind else wanted,
        ))
        if kind:
            events = [e for e in events if categorise(e.reasons) == kind][:wanted]
        actors = await run_in_threadpool(_actor_risk, runtime)
        flash, _ = FLASH.get(m or "", (None, "ok"))
        return HTMLResponse(views.audit_page(
            csrf=session.csrf, events=events, chain=chain_status(force=bool(m)),
            keyed=runtime.audit.keyed, actors=actors,
            filters={"actor": actor, "tool": tool, "decision": decision, "q": q,
                     "limit": str(limit), "model": model, "kind": kind,
                     "hours": str(hours) if hours else "", "hour": hour,
                     "agents": "1" if agents == "1" else ""},
            flash=flash,
        ))

    @app.get("/admin/changes", response_class=HTMLResponse)
    async def changes_view(request: Request, model: str = "", record_id: str = "",
                           limit: int = 200, m: str | None = None, e: str | None = None):
        session = session_for(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        rid = int(record_id) if record_id.isdigit() else None
        journal = runtime.journal
        entries = [] if journal is None else await run_in_threadpool(
            journal.search, model=model or None, record_id=rid, limit=max(1, min(limit, 2000))
        )
        flash, kind = FLASH.get(m or "", (None, "ok"))
        if e:
            flash, kind = e[:300], "bad"
        return HTMLResponse(views.changes_page(
            entries=entries, enabled=journal is not None,
            filters={"model": model, "record_id": record_id, "limit": str(limit)},
            csrf=session.csrf, flash=flash, flash_kind=kind,
        ))

    @app.post("/admin/changes/undo")
    async def changes_undo(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf", "/admin/changes")
        if form.get("confirm") != "yes":
            return back("undo_confirm", "/admin/changes")
        raw = str(form.get("change_id") or "")
        if not raw.isdigit():
            return back("undo_confirm", "/admin/changes")
        try:
            await run_in_threadpool(runtime.undo_change, int(raw), actor=admin_actor(request))
        except UndoError as exc:
            return RedirectResponse(f"/admin/changes?{urlencode({'e': str(exc)})}",
                                    status_code=303)
        except OdooError as exc:
            return RedirectResponse(
                f"/admin/changes?{urlencode({'e': f'Odoo refused the undo: {exc.kind}'})}",
                status_code=303)
        return back("undone", "/admin/changes")

    @app.post("/admin/audit/anchor")
    async def audit_anchor(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf", "/admin/logs")
        with runtime.admin_action(admin_actor(request), "admin.audit.anchor"):
            runtime.audit.write_anchor(settings.anchors_file)
        return back("anchor_written", "/admin/logs")

    return app


def _tab_for(flash_code: str | None, error: str | None, edit: Any) -> str:
    """The dashboard tab an action returns to."""
    code = flash_code or ""
    if edit is not None or code.startswith("profile_") or (error or "").startswith("Profile"):
        return "profiles"
    if code.startswith(("policy_", "tuning_")) or (error or "").startswith(("Policy", "Threshold")):
        return "policy"
    return "summary"


def esc_(value: Any) -> str:
    from html import escape
    return escape(str(value), quote=True)


def _summary(runtime: Runtime) -> dict[str, Any]:
    from datetime import timedelta

    from ..governance.events import utcnow

    now = utcnow()
    return summarise(runtime.audit.since(now - timedelta(hours=24)), now=now)


def _agents(runtime: Runtime) -> list[tuple[str, int, int, bool]]:
    """Agents for the dashboard: everyone active in the risk window, plus every
    blocked agent even if quiet — a block you cannot see is one you forget."""
    blocked = runtime.engine.policy.config.blocked_actors
    rows = [
        (actor, score, count, actor in blocked)
        for actor, score, count in _actor_risk(runtime)
        if not actor.startswith(("admin@", "anonymous@")) and actor != "system"
    ]
    seen = {r[0] for r in rows}
    rows += [(actor, 0, 0, True) for actor in sorted(blocked - seen)]
    return rows


def _actor_risk(runtime: Runtime) -> list[tuple[str, int, int]]:
    """Each actor active in the risk window, with its current decayed score."""
    from ..governance.events import utcnow

    now = utcnow()
    window = runtime.engine.risk.config.window
    recent = runtime.audit.since(now - window)
    by_actor: dict[str, list] = {}
    for event in recent:
        by_actor.setdefault(event.actor, []).append(event)
    rows = [
        (actor, runtime.engine.risk.score([], events, now), len(events))
        for actor, events in by_actor.items()
    ]
    return sorted(rows, key=lambda r: (-r[1], r[0]))
