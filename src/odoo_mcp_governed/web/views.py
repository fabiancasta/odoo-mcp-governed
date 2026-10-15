"""Server-rendered admin pages. No JavaScript, anywhere.

Every value is passed through :func:`esc` on its way into the page, and the
Content-Security-Policy sent with these pages allows no scripts at all. The
two layers back each other up: escaping keeps markup out, and if something
ever slipped past escaping, the browser still would not run it. Confirmation
for destructive actions uses a required checkbox, which HTML enforces without
a line of script.

Secrets never reach these templates — the profile data they receive comes
from :meth:`Profile.public`, which has no secret fields to leak.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import timezone
from html import escape
from typing import Any

from ..governance import AuditEvent, ChainStatus, Decision, Outcome

STYLE = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1d2330;--mute:#5d6678;--line:#dfe3ea;--acc:#2f5bd3;
--ok:#1f7a4a;--warn:#9a6400;--bad:#b42318;--chip:#eef1f6}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1a1f27;--ink:#e6e9ef;--mute:#98a1b3;
--line:#2b323e;--acc:#7d9cf0;--ok:#4cc38a;--warn:#e0a63a;--bad:#f07167;--chip:#242b36}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{display:flex;gap:16px;align-items:center;justify-content:space-between;padding:14px 24px;
border-bottom:1px solid var(--line);background:var(--card)}
header b{font-size:15px}nav a{margin-right:14px;color:var(--acc);text-decoration:none}
main{max-width:1180px;margin:0 auto;padding:20px 16px 48px}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px;margin:0 0 18px}
h2{font-size:15px;margin:0 0 12px}h3{font-size:13px;margin:14px 0 6px;color:var(--mute)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.stat{border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.stat small{display:block;color:var(--mute)}.stat strong{font-size:16px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:7px 8px;
border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mute);font-weight:600}
.wrap{overflow-x:auto}code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
input[type=text],input[type=password],input[type=url],input[type=number],textarea,select{width:100%;
padding:7px 9px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink);font:inherit}
textarea{min-height:64px;font-family:ui-monospace,monospace;font-size:12px}
label{display:block;margin:8px 0 3px;color:var(--mute);font-size:12px}
button{padding:7px 13px;border-radius:6px;border:1px solid var(--acc);background:var(--acc);color:#fff;
font:inherit;cursor:pointer}button.ghost{background:transparent;color:var(--acc)}
button.danger{border-color:var(--bad);background:transparent;color:var(--bad)}
.inline{display:inline-flex;gap:6px;align-items:center;margin:0}
.chip{display:inline-block;padding:1px 8px;border-radius:99px;background:var(--chip);font-size:12px}
.chip.bad{color:var(--bad);font-weight:600}.chip.warn{color:var(--warn)}.chip.ok{color:var(--ok)}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
.msg{padding:9px 12px;border-radius:8px;margin:0 0 14px;border:1px solid var(--line)}
.msg.bad{border-color:var(--bad)}.msg.ok{border-color:var(--ok)}
.tools{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:2px 12px}
.tools label{display:flex;gap:6px;align-items:center;color:var(--ink);margin:3px 0}
.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
tr.deny td{background:color-mix(in srgb,var(--bad) 8%,transparent)}
tr.flag td{background:color-mix(in srgb,var(--warn) 8%,transparent)}
.login{max-width:360px;margin:12vh auto}
"""


def esc(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


def page(title: str, body: str, *, nav: bool = True) -> str:
    links = (
        '<nav><a href="/admin">Dashboard</a><a href="/admin/logs">Audit log</a>'
        '<a href="/token">Token</a></nav>'
        if nav
        else ""
    )
    logout = (
        "" if not nav else
        '<form method="post" action="/admin/logout" class="inline">'
        '<button class="ghost" type="submit">Log out</button></form>'
    )
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        f"<title>{esc(title)} · odoo-mcp-governed</title><style>{STYLE}</style></head><body>"
        f"<header><div><b>odoo-mcp-governed</b></div>{links}{logout}</header>"
        f"<main>{body}</main></body></html>"
    )


def csrf_field(csrf: str) -> str:
    return f'<input type="hidden" name="csrf" value="{esc(csrf)}">'


def message(text: str | None, kind: str = "ok") -> str:
    return f'<div class="msg {esc(kind)}">{esc(text)}</div>' if text else ""


def login_page(error: str | None = None) -> str:
    body = (
        '<section class="login"><h2>Administrator login</h2>'
        f"{message(error, 'bad')}"
        '<form method="post" action="/admin">'
        '<label for=p>Password</label>'
        '<input id=p type="password" name="password" autocomplete="current-password" required autofocus>'
        '<p><button type="submit">Log in</button></p></form></section>'
    )
    return page("Login", body, nav=False)


def _chain_badge(status: ChainStatus) -> str:
    if status.intact:
        return f'<strong class="ok">intact</strong> <small>{status.events_checked} events</small>'
    return f'<strong class="bad">BROKEN at seq {esc(status.broken_at)}</strong>'


def dashboard(
    *,
    csrf: str,
    profiles: list[dict[str, Any]],
    active: str | None,
    odoo_ok: bool | None,
    chain: ChainStatus,
    keyed: bool,
    policy: dict[str, Any],
    policy_source: str,
    tool_names: Iterable[str],
    warnings: list[str],
    edit: dict[str, Any] | None,
    flash: str | None,
    flash_kind: str,
) -> str:
    odoo_badge = (
        '<strong class="ok">reachable</strong>' if odoo_ok
        else '<strong class="bad">unreachable</strong>' if odoo_ok is False
        else '<strong class="warn">no profile</strong>'
    )
    status = (
        '<section><h2>Status</h2><div class="grid">'
        f'<div class="stat"><small>Active profile</small><strong>{esc(active or "—")}</strong></div>'
        f'<div class="stat"><small>Odoo</small>{odoo_badge}</div>'
        f'<div class="stat"><small>Audit chain</small>{_chain_badge(chain)}</div>'
        f'<div class="stat"><small>Chain sealing</small><strong class="{"ok" if keyed else "warn"}">'
        f'{"HMAC" if keyed else "unkeyed SHA-256"}</strong></div>'
        "</div>"
        + "".join(f'<p class="warn">⚠ {esc(w)}</p>' for w in warnings)
        + "</section>"
    )

    rows = []
    for p in profiles:
        cred = "API key" if p["has_api_key"] else "password" if p["has_password"] else "—"
        actions = ""
        if not p["active"] and not p.get("protected"):
            actions += (
                '<form method="post" action="/admin/profile/activate" class="inline">'
                f'{csrf_field(csrf)}<input type="hidden" name="name" value="{esc(p["name"])}">'
                '<button type="submit">Activate</button></form> '
            )
        actions += f'<a href="/admin?edit={esc(p["name"])}">Edit</a>'
        if not p["active"]:
            actions += (
                ' <form method="post" action="/admin/profile/delete" class="inline">'
                f'{csrf_field(csrf)}<input type="hidden" name="name" value="{esc(p["name"])}">'
                '<label class="inline"><input type="checkbox" name="confirm" value="yes" required>'
                'confirm</label><button class="danger" type="submit">Delete</button></form>'
            )
        if p.get("protected"):
            env_badge = '<span class="chip bad">PROTECTED HOST — cannot activate</span>'
        elif p["environment"] == "production":
            env_badge = (
                '<span class="chip bad">PRODUCTION · writes ALLOWED</span>' if p["allow_writes"]
                else '<span class="chip warn">production · read-only</span>'
            )
        else:
            env_badge = f'<span class="chip ok">{esc(p["environment"])}</span>'
        rows.append(
            f'<tr><td>{"● " if p["active"] else ""}<b>{esc(p["name"])}</b></td>'
            f"<td>{env_badge}</td>"
            f'<td class="mono">{esc(p["url"])}</td><td>{esc(p["database"])}</td>'
            f'<td>{esc(p["username"])}</td><td>{esc(cred)}</td>'
            f'<td>{"yes" if p["ssl_verify"] else "<span class=warn>off</span>"}</td>'
            f"<td>{actions}</td></tr>"
        )
    e = edit or {}
    editing = bool(edit)
    profile_form = (
        f'<h3>{"Edit profile " + esc(e.get("name")) if editing else "Add profile"}</h3>'
        f'<form method="post" action="/admin/profile/save">{csrf_field(csrf)}<div class="row">'
        f'<div><label>Name (A-Z a-z 0-9 _ . -)</label><input type="text" name="name" '
        f'value="{esc(e.get("name"))}" pattern="[A-Za-z0-9_.\\-]{{1,64}}" required '
        f'{"readonly" if editing else ""}></div>'
        f'<div><label>URL</label><input type="url" name="url" value="{esc(e.get("url"))}" required></div>'
        f'<div><label>Database</label><input type="text" name="database" '
        f'value="{esc(e.get("database"))}" required></div>'
        f'<div><label>Username</label><input type="text" name="username" '
        f'value="{esc(e.get("username"))}" required></div>'
        '<div><label>API key (leave empty to keep the stored one)</label>'
        '<input type="password" name="api_key" autocomplete="off"></div>'
        '<div><label>Password (optional; needed only for get_report)</label>'
        '<input type="password" name="password" autocomplete="off"></div>'
        f'<div><label>Timeout (s)</label><input type="number" name="timeout" min="1" max="600" '
        f'value="{esc(e.get("timeout", 30))}"></div>'
        '<div><label>TLS</label><label class="inline"><input type="checkbox" name="ssl_verify" value="1" '
        f'{"checked" if e.get("ssl_verify", True) else ""}> verify certificate</label></div>'
        '<div><label>Environment (unlabelled profiles are treated as production)</label>'
        '<select name="environment">'
        + "".join(
            f'<option value="{v}" {"selected" if e.get("environment", "production") == v else ""}>'
            f"{v}</option>"
            for v in ("production", "staging", "development")
        )
        + '</select><label class="inline"><input type="checkbox" name="allow_writes" value="1" '
        f'{"checked" if e.get("allow_writes") else ""}> allow writes on production '
        "<small class=bad>(lifts read-only)</small></label></div>"
        '</div><p><button type="submit">Save profile</button> '
        f'{"<a href=/admin>cancel</a>" if editing else ""}</p></form>'
    )
    profiles_section = (
        '<section><h2>Odoo profiles</h2><div class="wrap"><table><tr><th>Name</th><th>Environment</th><th>URL</th>'
        "<th>Database</th><th>User</th><th>Credential</th><th>TLS verify</th><th></th></tr>"
        + ("".join(rows) or '<tr><td colspan=8>No profiles yet.</td></tr>')
        + f"</table></div>{profile_form}</section>"
    )

    disabled = set(policy["disabled_tools"])
    tools = "".join(
        f'<label><input type="checkbox" name="enabled_tools" value="{esc(t)}" '
        f'{"" if t in disabled else "checked"}> <code>{esc(t)}</code></label>'
        for t in tool_names
    )

    def area(name: str, label: str, hint: str) -> str:
        return (
            f'<div><label>{esc(label)} <small>({esc(hint)})</small></label>'
            f'<textarea name="{esc(name)}">{esc(chr(10).join(policy[name]))}</textarea></div>'
        )

    policy_section = (
        '<section><h2>Access policy</h2>'
        f'<p><small>Applied to the next call, no restart. Current source: '
        f'<span class="chip">{esc(policy_source)}</span></small></p>'
        f'<form method="post" action="/admin/policy">{csrf_field(csrf)}'
        f'<h3>Enabled tools</h3><div class="tools">{tools}</div>'
        '<h3>Models — one per line, <code>*</code> for all. The denylist always wins.</h3>'
        '<div class="row">'
        + area("allowed_models", "Readable", "ALLOWED_MODELS")
        + area("writable_models", "Writable", "WRITABLE_MODELS")
        + area("deletable_models", "Deletable", "DELETABLE_MODELS")
        + area("denied_models", "Denied — never reachable", "DENIED_MODELS")
        + "</div><h3>execute_method</h3><div class=\"row\">"
        + '<div><label class="inline"><input type="checkbox" name="allow_execute_method" value="1" '
        + f'{"checked" if policy["allow_execute_method"] else ""}> enable execute_method</label>'
        + '<label>Max records per call</label><input type="number" name="max_records_per_call" '
        + f'min="1" max="100000" value="{esc(policy["max_records_per_call"])}"></div>'
        + area("execute_method_allowlist", "Allowed methods", "empty = any non-blocked")
        + area("forbidden_methods", "Extra forbidden methods", "on top of the built-in list")
        + '</div><p><button type="submit">Apply policy</button></p></form></section>'
    )
    return page(
        "Dashboard",
        message(flash, flash_kind) + status + profiles_section + policy_section,
    )


def token_page(*, csrf: str, token: dict[str, Any] | None, mcp_url: str) -> str:
    if token:
        body = (
            '<section><h2>MCP access token</h2>'
            f'<p>Actor: <b>{esc(token["actor"])}</b> · expires {esc(token["expires_at"][:10])}</p>'
            f'<label>Bearer token</label><textarea readonly class="mono">{esc(token["token"])}</textarea>'
            f'<label>MCP endpoint</label><input type="text" readonly value="{esc(mcp_url)}">'
            '<p><small>Every request made with this token is attributed to this actor in the '
            "audit log. Give each agent its own token if you want the detectors to tell them "
            "apart. Rotating <code>JWT_SECRET</code> revokes every token at once.</small></p>"
        )
    else:
        body = '<section><h2>MCP access token</h2><p>No valid token. Generate one below.</p>'
    body += (
        '<form method="post" action="/admin/token/regenerate">'
        f"{csrf_field(csrf)}<div class=row><div><label>Actor name</label>"
        '<input type="text" name="actor" value="claude" pattern="[A-Za-z0-9_.@\\-]{1,64}" required>'
        "</div></div><p>"
        '<label class="inline"><input type="checkbox" name="confirm" value="yes" required> '
        "I understand the stored token will be replaced</label> "
        '<button type="submit">Generate new token</button></p></form></section>'
    )
    return page("Token", body)


def _event_row(e: AuditEvent) -> str:
    cls = "deny" if e.decision is Decision.DENY else (
        "flag" if e.decision in (Decision.ALLOW_FLAGGED, Decision.THROTTLE) else ""
    )
    decision_cls = {"deny": "bad", "flag": "warn"}.get(cls, "ok")
    outcome_cls = "bad" if e.outcome is Outcome.ERROR else ""
    target = esc(e.model or "")
    if e.method:
        target += f"<small>.{esc(e.method)}</small>"
    signals = ", ".join(f"{s.name}({s.weight})" for s in e.signals)
    notes = "; ".join(r for r in e.reasons)
    if e.error_type:
        notes = (notes + "; " if notes else "") + f"error: {e.error_type}"
    return (
        f'<tr class="{cls}"><td class="mono">{e.seq}</td>'
        f'<td class="mono">{esc(e.ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))}</td>'
        f"<td>{esc(e.actor)}</td><td>{esc(e.profile)}</td><td><code>{esc(e.tool)}</code></td>"
        f"<td>{target}</td><td class=\"{decision_cls}\">{esc(e.decision.value)}</td>"
        f'<td class="{outcome_cls}">{esc(e.outcome.value)}</td>'
        f"<td>{esc(e.affected_count if e.affected_count is not None else '')}</td>"
        f"<td>{esc(e.risk_score or '')}</td><td>{esc(signals)}</td>"
        f"<td><small>{esc(notes)}</small></td></tr>"
    )


def audit_page(
    *,
    csrf: str,
    events: list[AuditEvent],
    chain: ChainStatus,
    keyed: bool,
    actors: list[tuple[str, int, int]],
    filters: dict[str, str],
    flash: str | None,
) -> str:
    f = filters
    shortcuts = " ".join(
        f'<a class="chip" href="/admin/logs?{q}">{esc(label)}</a>'
        for label, q in (
            ("all", ""),
            ("denied", "decision=deny"),
            ("flagged", "decision=allow_flagged"),
            ("throttled", "decision=throttle"),
            ("errors", "outcome=error"),
            ("admin actions", "tool=admin."),
            ("logins", "tool=admin.login"),
            ("deletes", "tool=delete_record"),
        )
    )
    options = "".join(
        f'<option value="{esc(v)}" {"selected" if f.get("decision") == v else ""}>{esc(v or "any")}</option>'
        for v in ("", "allow", "allow_flagged", "throttle", "deny")
    )
    risk_rows = "".join(
        f'<tr><td>{esc(a)}</td><td class="{"bad" if r >= 70 else "warn" if r >= 40 else "ok"}">'
        f'<b>{r}</b></td><td>{n}</td><td><a href="/admin/logs?actor={esc(a)}">events</a></td></tr>'
        for a, r, n in actors
    )
    header = (
        '<section><h2>Governance</h2><div class="grid">'
        f'<div class="stat"><small>Audit chain</small>{_chain_badge(chain)}</div>'
        f'<div class="stat"><small>Head</small><span class="mono">{esc(chain.head_hash[:24])}…</span></div>'
        f'<div class="stat"><small>Sealing</small><strong>{"HMAC" if keyed else "SHA-256"}</strong></div>'
        "</div>"
        + (f'<p class="bad">{esc(chain.reason)}</p>' if not chain.intact else "")
        + '<form method="post" action="/admin/audit/anchor" class="inline">'
        f"{csrf_field(csrf)}<button class=ghost type=submit>Write anchor</button></form> "
        "<small>Appends the current head to anchors.log — copy that file off this host.</small>"
        "<h3>Actors by current risk (decayed, last hour)</h3><div class=wrap><table>"
        "<tr><th>Actor</th><th>Risk</th><th>Events (1h)</th><th></th></tr>"
        f'{risk_rows or "<tr><td colspan=4>No activity in the last hour.</td></tr>"}'
        "</table></div></section>"
    )
    form = (
        f'<section><h2>Audit log</h2><p>{shortcuts}</p>'
        '<form method="get" action="/admin/logs"><div class="row">'
        f'<div><label>Actor</label><input type="text" name="actor" value="{esc(f.get("actor"))}"></div>'
        f'<div><label>Tool (prefix)</label><input type="text" name="tool" value="{esc(f.get("tool"))}"></div>'
        f'<div><label>Decision</label><select name="decision">{options}</select></div>'
        f'<div><label>Text</label><input type="text" name="q" value="{esc(f.get("q"))}"></div>'
        f'<div><label>Rows</label><input type="number" name="limit" min="1" max="2000" '
        f'value="{esc(f.get("limit") or 200)}"></div>'
        '</div><p><button type="submit">Filter</button></p></form>'
        '<div class="wrap"><table><tr><th>#</th><th>Time (UTC)</th><th>Actor</th><th>Profile</th>'
        "<th>Tool</th><th>Model</th><th>Decision</th><th>Outcome</th><th>Records</th><th>Risk</th>"
        "<th>Signals</th><th>Reasons</th></tr>"
        + ("".join(_event_row(e) for e in events) or "<tr><td colspan=12>No events.</td></tr>")
        + "</table></div></section>"
    )
    return page("Audit log", message(flash) + header + form)
