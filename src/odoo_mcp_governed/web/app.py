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
from typing import Any
from urllib.parse import urlencode, urlsplit

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from .. import __version__
from ..governance import ChainStatus, Decision, Operation, Outcome, ToolCall
from ..odoo import OdooClient
from ..profiles import PROFILE_NAME, Profile, ProfileError
from ..protocol import INVALID_REQUEST, PARSE_ERROR, Dispatcher, _error
from ..runtime import Runtime
from ..tools import TOOLS
from . import views
from .auth import AdminSessions, AuthError, TokenStore, csrf_matches, password_matches, verify_token
from .ratelimit import RateLimiter

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
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)
API_CSP = "default-src 'none'; frame-ancestors 'none'"

FLASH = {
    "profile_saved": ("Profile saved.", "ok"),
    "profile_activated": ("Profile activated — the next call goes to the new instance.", "ok"),
    "profile_deleted": ("Profile deleted.", "ok"),
    "policy_applied": ("Policy applied to the next call.", "ok"),
    "policy_unchanged": ("Nothing changed.", "ok"),
    "token_regenerated": (
        "New token generated. The previous one still works until JWT_SECRET is rotated.",
        "ok",
    ),
    "anchor_written": ("Anchor written to anchors.log.", "ok"),
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
    cookie_name = "__Host-gov_admin" if settings.https_mode else "gov_admin"
    chain_cache: dict[str, Any] = {"at": 0.0, "status": None}

    app.add_middleware(BodySizeLimit, max_bytes=int(settings.max_body_mb * 1024 * 1024))
    app.add_middleware(HeaderSizeLimit, max_bytes=settings.max_header_kb * 1024)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
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
        # Checked before verifying, so a stream of bad tokens stops costing
        # anything once it is clearly not a typo.
        if retry := limits["auth_fail"].exhausted(ip):
            return too_many(retry)

        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        try:
            if scheme.lower() != "bearer" or not token.strip():
                raise AuthError("missing bearer token")
            claims = verify_token(settings, token.strip())
        except AuthError as exc:
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
            return JSONResponse(
                {"error": str(exc)},
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

        result = await run_in_threadpool(dispatcher.handle_payload, payload, actor)
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
    async def admin_home(request: Request, edit: str | None = None, m: str | None = None):
        session = session_for(request)
        if session is None:
            return HTMLResponse(views.login_page())
        return await run_in_threadpool(render_dashboard, session, edit_name=edit, flash_code=m)

    def render_dashboard(session, *, edit_name=None, flash_code=None, error=None,
                         edit_override=None, status_code=200) -> HTMLResponse:
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
        )
        return HTMLResponse(html, status_code=status_code)

    async def dashboard_error(session, error: str, **kwargs) -> HTMLResponse:
        return await run_in_threadpool(
            render_dashboard, session, error=error, status_code=400, **kwargs
        )

    @app.post("/admin", response_class=HTMLResponse)
    async def admin_login(request: Request):
        allowed, retry = limits["login"].hit(client_ip(request))
        if not allowed:
            return HTMLResponse(
                views.login_page(f"Too many attempts. Try again in {retry}s."),
                status_code=429, headers={"Retry-After": str(retry)},
            )
        form = await request.form()
        supplied = str(form.get("password") or "")
        ok = password_matches(settings.admin_password, supplied)
        await run_in_threadpool(runtime.record_login, admin_actor(request), success=ok)
        if not ok:
            return HTMLResponse(views.login_page("Wrong password."), status_code=401)
        sid, _ = sessions.create(client_ip(request))
        response = RedirectResponse("/admin", status_code=303)
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
                    "execute_method_allowlist", "forbidden_methods", "sensitive_fields"):
            changes[key] = str(form.get(key) or "")
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
        return HTMLResponse(views.token_page(csrf=session.csrf, token=tokens.current(),
                                             mcp_url=mcp_url(request)))

    @app.post("/admin/token/regenerate")
    async def token_regenerate(request: Request):
        session, form = await admin_form(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        if form is None:
            return back("csrf", "/token")
        actor = str(form.get("actor") or "claude").strip()
        if not ACTOR_NAME.match(actor) or form.get("confirm") != "yes":
            return back("csrf", "/token")
        with runtime.admin_action(admin_actor(request), "admin.token.regenerate", detail=actor):
            tokens.regenerate(actor)
        return back("token_regenerated", "/token")

    # -- admin: audit ------------------------------------------------------

    @app.get("/admin/logs", response_class=HTMLResponse)
    async def audit_view(request: Request, actor: str = "", tool: str = "", decision: str = "",
                         outcome: str = "", q: str = "", limit: int = 200, m: str | None = None):
        session = session_for(request)
        if session is None:
            return RedirectResponse("/admin", status_code=303)
        decision = decision if decision in {d.value for d in Decision} else ""
        outcome = outcome if outcome in {o.value for o in Outcome} else ""
        events = await run_in_threadpool(
            runtime.audit.store.search,
            actor=actor or None, tool_prefix=tool or None, decision=decision or None,
            outcome=outcome or None, text=q or None, limit=max(1, min(limit, 2000)),
        )
        actors = await run_in_threadpool(_actor_risk, runtime)
        flash, _ = FLASH.get(m or "", (None, "ok"))
        return HTMLResponse(views.audit_page(
            csrf=session.csrf, events=events, chain=chain_status(force=bool(m)),
            keyed=runtime.audit.keyed, actors=actors,
            filters={"actor": actor, "tool": tool, "decision": decision, "q": q,
                     "limit": str(limit)},
            flash=flash,
        ))

    @app.get("/admin/changes", response_class=HTMLResponse)
    async def changes_view(request: Request, model: str = "", record_id: str = "",
                           limit: int = 200):
        if session_for(request) is None:
            return RedirectResponse("/admin", status_code=303)
        rid = int(record_id) if record_id.isdigit() else None
        journal = runtime.journal
        entries = [] if journal is None else await run_in_threadpool(
            journal.search, model=model or None, record_id=rid, limit=max(1, min(limit, 2000))
        )
        return HTMLResponse(views.changes_page(
            entries=entries, enabled=journal is not None,
            filters={"model": model, "record_id": record_id, "limit": str(limit)},
        ))

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
