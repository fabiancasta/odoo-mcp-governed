"""One agent as a tree: what it can actually do, and where to add more.

The panel holds three separate things that together decide what an agent
may do — the server policy (default or per profile), the profile's
environment, and the agent's own rule. Read one at a time, nobody can say
what a given agent ends up with. This page works it out and draws it:

    🤖 agent ── rule (read-only, quota, pinned profile)
       ├── 🗄️ each profile it can reach
       │     ├── 👁️ read    ├── ✏️ change    └── 🗑️ delete
       ├── 🧩 model limit   ├── 🛠️ tools   ├── 🔐 record scope
       └── 🔑 tokens        └── 📈 activity

Every leaf is the *effective* permission: the policy narrowed by the
environment and by the rule. The ``+`` next to a leaf says where it adds:
on a profile's gates it widens that profile for every agent on it; on the
agent's model limit it only ever narrows.
"""

from __future__ import annotations

from typing import Any

from ..governance.agents import AgentRule
from ..governance.policy import ALWAYS_DENIED, WILDCARD, PolicyConfig
from .views import ENV_ICON, GATE_ICON, avatar, csrf_field, esc, message, page

TREE_STYLE = """
<style>
.tree,.tree ul{list-style:none;margin:0;padding:0}.tree ul{margin-left:22px;
border-left:2px solid var(--line)}.tree li{position:relative;padding:5px 0 5px 18px}
.tree ul>li::before{content:"";position:absolute;left:-2px;top:22px;width:16px;
border-top:2px solid var(--line)}.node{display:inline-flex;flex-wrap:wrap;gap:6px;
align-items:center;padding:6px 10px;border:1px solid var(--line);border-radius:10px;
background:var(--bg)}.node.root{border-color:var(--acc);padding:10px 14px}
.node.off{opacity:.55}.node b{font-size:13px}.tree details>summary{list-style:none;cursor:pointer}
.tree details>summary::-webkit-details-marker{display:none}
.tree details>summary .node::after{content:"▾";color:var(--mute);margin-left:4px}
.tree details:not([open])>summary .node::after{content:"▸"}
.quick{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.quick input[type=number]{width:90px}
.quick select{width:auto}.sum{display:flex;gap:10px;flex-wrap:wrap;margin:6px 0}
.sum span{font-size:12px;padding:2px 8px;border-radius:99px;background:var(--chip)}
.hub{display:grid;grid-template-columns:240px minmax(0,1fr);gap:18px;align-items:start}
.roster{position:sticky;top:12px;display:flex;flex-direction:column;gap:4px;background:var(--card);
border:1px solid var(--line);border-radius:12px;padding:10px;max-height:calc(100vh - 40px);
overflow-y:auto}.roster a{display:flex;gap:10px;align-items:center;padding:6px 8px;
border-radius:8px;color:var(--ink);text-decoration:none}.roster a:hover{background:var(--chip)}
.roster a.on{background:color-mix(in srgb,var(--acc) 14%,transparent);outline:1px solid var(--acc)}
.roster small{display:block;color:var(--mute);font-size:11px}.roster .new{justify-content:center;
border:1px dashed var(--acc);color:var(--acc);font-weight:600}.roster .all{color:var(--mute);
justify-content:center;font-size:12px}.detail{min-width:0}
details.card-like{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:14px 18px;margin:0 0 18px}details.card-like>summary{cursor:pointer}
@media (max-width:900px){.hub{grid-template-columns:1fr}.roster{position:static;
flex-direction:row;overflow-x:auto;max-height:none}.roster a{flex:none}}
.tree .plus{max-width:380px}.plus button{white-space:nowrap}
</style>
"""


def narrow(models: set[str], limit: set[str] | frozenset[str]) -> set[str]:
    """``models`` held to ``limit``, with ``*`` meaning every business model."""
    limit = set(limit)
    if WILDCARD in models and WILDCARD in limit:
        return {WILDCARD}
    if WILDCARD in models:
        return limit
    if WILDCARD in limit:
        return set(models)
    return models & limit


def effective(policy: PolicyConfig, rule: AgentRule | None, profile: str,
              read_only_profiles: frozenset[str]) -> dict[str, Any]:
    """What ``rule``'s agent can read, change and delete on ``profile``."""
    cfg = policy.for_profile(profile)
    notes: list[str] = []
    if profile in cfg.configurator_profiles:
        read = write = delete = {WILDCARD}
        notes.append("configurator — the whole system, module and code changes need approval")
    elif profile in cfg.sandbox_profiles:
        read = write = delete = {WILDCARD}
        notes.append("sandbox — model lists off, risk only observed")
    else:
        read, write, delete = (set(cfg.allowed_models), set(cfg.writable_models),
                               set(cfg.deletable_models))
        notes.append("own permissions" if profile in policy.profile_lists
                     else "default permissions")
    write, delete = narrow(write, read), narrow(delete, read)
    reachable = True
    if rule is not None:
        if rule.profile and rule.profile != profile:
            reachable = False
        for limit in (rule.models, frozenset(rule.scope)):
            if limit:
                read, write, delete = (narrow(read, limit), narrow(write, limit),
                                       narrow(delete, limit))
        if rule.read_only:
            write, delete = set(), set()
            notes.append("agent is read-only")
    if profile in read_only_profiles:
        write, delete = set(), set()
        notes.append("production without writes — read only")
    floor = set(cfg.denied_models) | set(ALWAYS_DENIED)
    if profile in cfg.configurator_profiles:
        floor = set(ALWAYS_DENIED)
    if not reachable:
        read, write, delete = set(), set(), set()
    return {"read": read - floor, "write": write - floor, "delete": delete - floor,
            "reachable": reachable, "notes": notes}


def counts(perms: dict[str, Any]) -> str:
    def n(models: set[str]) -> str:
        return "all" if WILDCARD in models else str(len(models))
    return (f'<span>👁️ {n(perms["read"])}</span><span>✏️ {n(perms["write"])}</span>'
            f'<span>🗑️ {n(perms["delete"])}</span>')


def _models(models: set[str]) -> str:
    if WILDCARD in models:
        return '<span class="pill">✱ every business model</span>'
    return "".join(f'<span class="pill">{esc(m)}</span>' for m in sorted(models)) or (
        "<small>none</small>")


def _plus(csrf: str, action: str, hidden: dict[str, str], placeholder: str,
          datalist: str = "") -> str:
    fields = "".join(f'<input type="hidden" name="{esc(k)}" value="{esc(v)}">'
                     for k, v in hidden.items())
    listed = f' list="{datalist}"' if datalist else ""
    return (f'<form method="post" action="{action}" class="plus">{csrf_field(csrf)}{fields}'
            f'<input type="text" name="model" placeholder="{esc(placeholder)}"{listed} required>'
            '<button name="action" value="add" type="submit" title="Add">+</button></form>')


def _remove(csrf: str, action: str, hidden: dict[str, str], label: str) -> str:
    fields = "".join(f'<input type="hidden" name="{esc(k)}" value="{esc(v)}">'
                     for k, v in hidden.items())
    return (f'<span class="pill">{esc(label)}<form method="post" action="{action}">'
            f'{csrf_field(csrf)}{fields}<button name="action" value="remove" type="submit" '
            'title="Remove">×</button></form></span>')


def _danger_zone(csrf: str, name: str, archived: str | None, has_rule: bool) -> str:
    hidden = f'{csrf_field(csrf)}<input type="hidden" name="name" value="{esc(name)}">'
    if archived:
        return (
            '<details class="card-like danger-zone" open><summary><b>🗄️ Archived</b></summary>'
            f'<form method="post" action="/admin/agents/archive">{hidden}'
            '<button name="action" value="restore" type="submit">↺ Restore this agent</button> '
            "<small>unblocks it; it then needs a new token.</small></form></details>"
        )
    return (
        '<details class="card-like danger-zone"><summary><b>⚠️ Archive or delete this agent'
        "</b></summary><p><small><b>Archive</b>: revokes every token, blocks the agent and "
        "hides it from the lists; restore it any time. <b>Delete</b>: the same, and its rule "
        "is removed. Either way the audit log keeps its history — it cannot be erased."
        "</small></p>"
        f'<form method="post" action="/admin/agents/archive">{hidden}'
        '<label class="inline"><input type="checkbox" name="confirm" value="yes" required> '
        f"confirm for {esc(name)}</label> "
        '<button class="danger" name="action" value="archive" type="submit">🗄️ Archive</button> '
        + ('<button class="danger" name="action" value="delete" type="submit">🗑️ Delete</button>'
           if has_rule else "")
        + "</form></details>"
    )


def describe_domain(domain: Any) -> str:
    parts = []
    for item in domain:
        if isinstance(item, (list, tuple)) and len(item) == 3:
            parts.append(f"{item[0]} {item[1]} {item[2]}")
        else:
            parts.append({"|": "or", "&": "and", "!": "not"}.get(str(item), str(item)))
    return " · ".join(parts) or "every record"


def tree_page(*, csrf: str, name: str, rule: AgentRule | None, policy: PolicyConfig,
              profiles: list[dict[str, Any]], active: str | None,
              read_only_profiles: frozenset[str], tokens: list[dict[str, Any]],
              stats: tuple[int, int, str] | None, tools: list[str], blocked: bool,
              flash: str | None = None, flash_kind: str = "ok",
              agents_list: list[tuple[str, str]] = (), issued: dict | None = None,
              edit_form: str = "", archived: str | None = None) -> str:
    back = f"/admin/agents/view?name={name}"
    has_rule = rule is not None
    r = rule or AgentRule(name=name)
    badges = []
    if blocked:
        badges.append('<span class="chip bad">⛔ blocked</span>')
    badges.append('<span class="chip">📋 own rule</span>' if has_rule else
                  '<span class="chip">🌐 follows the server policy</span>')
    if r.read_only:
        badges.append('<span class="chip warn">👁️ read-only</span>')
    if r.daily_quota:
        badges.append(f'<span class="chip">⏱️ {esc(r.daily_quota)}/day</span>')
    if r.profile:
        badges.append(f'<span class="chip">📌 {esc(r.profile)}</span>')
    if r.scope:
        badges.append('<span class="chip">🔐 own records only</span>')

    profile_options = '<option value="">any (token or active)</option>' + "".join(
        f'<option value="{esc(p["name"])}"{" selected" if r.profile == p["name"] else ""}>'
        f'{esc(p["name"])}</option>' for p in profiles)
    quick = (
        f'<form method="post" action="/admin/agents/quick" class="quick">{csrf_field(csrf)}'
        f'<input type="hidden" name="name" value="{esc(name)}">'
        f'<label class="inline"><input type="checkbox" name="read_only" value="yes"'
        f'{" checked" if r.read_only else ""}> read-only</label>'
        f'<label class="inline">calls/day <input type="number" name="daily_quota" min="0" '
        f'value="{esc(r.daily_quota)}"></label>'
        f'<label class="inline">profile <select name="profile">{profile_options}</select></label>'
        f'<button type="submit">{"Save" if has_rule else "＋ Create rule"}</button></form>'
    )
    calls = (f"{stats[0]} calls in 24 h · {stats[1]} in total · last "
             f"{esc(stats[2][:16].replace('T', ' '))} UTC" if stats else "no calls yet")
    root = (f'<div class="node root"><div class="who">{avatar(name, 54)}<div><b>{esc(name)}</b>'
            f'<br><small>{esc(r.note) or calls}</small><div class="sum">{" ".join(badges)}'
            f'</div></div></div>{quick}</div>')

    # -- profiles ----------------------------------------------------------
    reach = [p for p in profiles if not r.profile or p["name"] == r.profile]
    profile_nodes = []
    for p in reach:
        pname = p["name"]
        perms = effective(policy, rule, pname, read_only_profiles)
        where = ("★ active — tokens that are not pinned land here" if pname == active
                 else "only with a token pinned to it")
        if r.profile:
            where = "📌 the agent always works here"
        gates = []
        for key, gate in (("r", "read"), ("w", "write"), ("d", "delete")):
            icon, title = GATE_ICON[key]
            add = _plus(csrf, "/admin/permissions/chip",
                        {"profile": pname if pname in policy.profile_lists else "",
                         "gate": key, "back": back},
                        "add for every agent on "
                        + ("this profile…" if pname in policy.profile_lists
                           else "the default profiles…"))
            gates.append(f'<li><div class="node"><span>{icon}</span><b>{title}</b>'
                         f'{_models(perms[gate])}</div>{add}</li>')
        profile_nodes.append(
            f'<li><details open><summary><div class="node">'
            f'{ENV_ICON.get(p.get("environment", ""), "🗄️")} <b>{esc(pname)}</b>'
            f'<small>{esc(p.get("environment", ""))} · {esc(where)}</small>'
            f'<span class="sum">{counts(perms)}</span></div></summary>'
            f'<p><small>{esc(" · ".join(perms["notes"]))} · '
            f'<a href="/admin/permissions?profile={esc(pname)}">edit this profile’s '
            f"permissions</a></small></p><ul>{''.join(gates)}</ul></details></li>"
        )
    if not reach:
        profile_nodes.append(f'<li><div class="node off">📌 pinned to {esc(r.profile)}, '
                             "which no longer exists: every call is refused</div></li>")

    # -- the agent's own limits -------------------------------------------
    hidden = {"name": name, "back": back}
    limit = "".join(_remove(csrf, "/admin/agents/model", hidden | {"model": m}, m)
                    for m in sorted(r.models)) or (
        "<small>none — every model the profile allows</small>")
    tool_pills = "".join(_remove(csrf, "/admin/agents/model",
                                 hidden | {"model": t, "kind": "tool"}, t)
                         for t in sorted(r.tools)) or "<small>all tools</small>"
    tool_add = (
        f'<form method="post" action="/admin/agents/model" class="plus">{csrf_field(csrf)}'
        f'<input type="hidden" name="name" value="{esc(name)}">'
        f'<input type="hidden" name="back" value="{esc(back)}">'
        '<input type="hidden" name="kind" value="tool"><select name="model">'
        + "".join(f'<option value="{esc(t)}">{esc(t)}</option>' for t in tools if t not in r.tools)
        + '</select><button name="action" value="add" type="submit" title="Only these tools">'
        "+</button></form>"
    )
    scope = "".join(
        f'<li><div class="node"><code>{esc(m)}</code><small>{esc(describe_domain(d))}</small>'
        "</div></li>" for m, d in sorted(r.scope.items())
    ) or '<li><div class="node off"><small>no scope — every record the models allow'
    scope = scope if r.scope else scope + "</small></div></li>"

    # -- tokens and activity ------------------------------------------------
    token_nodes = "".join(
        f'<li><div class="node{" off" if t.get("revoked_at") else ""}">🔑 '
        f'<code>{esc(t["jti"][:8])}</code> {esc(t.get("label") or "")} '
        f'<small>expires {esc(t["expires_at"][:10])}'
        f'{" · pinned " + esc(t["profile"]) if t.get("profile") else ""}'
        f'{" · revoked" if t.get("revoked_at") else ""}</small>'
        + ("" if t.get("revoked_at") else
           f'<form method="post" action="/admin/agents/revoke" class="inline">{csrf_field(csrf)}'
           f'<input type="hidden" name="jti" value="{esc(t["jti"])}">'
           '<button class="danger" type="submit">Revoke</button></form>')
        + "</div></li>" for t in tokens
    )
    if stats and not any(not t.get("revoked_at") for t in tokens):
        token_nodes += (
            '<li><div class="node"><span class="chip warn">⚠ may be using a token that is not '
            "registered</span><small>issued before the registry. Issue a registered one, switch "
            "the agent to it, then revoke the old ones:</small>"
            f'<form method="post" action="/admin/agents/revoke" class="inline">{csrf_field(csrf)}'
            f'<input type="hidden" name="name" value="{esc(name)}">'
            '<input type="hidden" name="kind" value="unregistered">'
            '<button class="danger" type="submit">Revoke unregistered tokens</button></form>'
            "</div></li>")
    token_nodes += (
        f'<li><form method="post" action="/admin/agents/token" class="plus">{csrf_field(csrf)}'
        f'<input type="hidden" name="name" value="{esc(name)}">'
        '<input type="hidden" name="from_tree" value="1">'
        '<input type="text" name="label" placeholder="label, e.g. laptop">'
        '<button type="submit" title="Issue a registered token">+ token</button></form></li>'
        f'<li><form method="post" action="/admin/agents/revoke" class="inline">{csrf_field(csrf)}'
        f'<input type="hidden" name="name" value="{esc(name)}">'
        '<label class="inline"><input type="checkbox" name="confirm" value="yes" required> '
        "confirm</label> "
        '<button class="danger" type="submit">Revoke every token of this agent</button></form>'
        "</li>"
    )

    tree = (
        f'<ul class="tree"><li>{root}<ul>'
        f'<li><details open><summary><div class="node">🗄️ <b>Profiles</b>'
        f"<small>what it can do on each Odoo</small></div></summary>"
        f'<ul>{"".join(profile_nodes)}</ul></details></li>'
        f'<li><div class="node">🧩 <b>Model limit</b>{limit}</div>'
        f'{_plus(csrf, "/admin/agents/model", hidden, "only these models…")}</li>'
        f'<li><div class="node">🛠️ <b>Tools</b>{tool_pills}</div>{tool_add}</li>'
        f'<li><details{" open" if r.scope else ""}><summary><div class="node">🔐 <b>Record scope'
        f'</b></div></summary><ul>{scope}</ul><p><small><a href="/admin/agents?edit={esc(name)}">'
        "edit the scope</a></small></p></details></li>"
        f'<li><details open><summary><div class="node">🔑 <b>Tokens</b></div></summary>'
        f"<ul>{token_nodes}</ul></details></li>"
        f'<li><div class="node">📈 <b>Activity</b><small>{calls}</small>'
        f'<a href="/admin/logs?actor={esc(name)}">audit log</a></div></li>'
        "</ul></li></ul>"
    )
    shown = ""
    if issued:
        shown = (
            '<section class="issued"><h2>🔑 New token for '
            f'{esc(issued["actor"])}</h2><p class="msg warn">Copy it now: it is shown only once. '
            f'Expires {esc(issued["expires_at"][:16].replace("T", " "))} UTC.</p>'
            f'<textarea readonly class="mono" rows="3">{esc(issued["token"])}</textarea></section>'
        )
    roster = "".join(
        f'<a href="/admin/agents/view?name={esc(n)}"{" class=on" if n == name else ""}>'
        f'{avatar(n, 30)}<span><b>{esc(n)}</b><small>{sub}</small></span></a>'
        for n, sub in agents_list
    )
    detail = (
        message(flash, flash_kind) + shown
        + "<section><h2>What this agent can do</h2><p><small>Every leaf is what the agent can "
        "really do: the profile’s permissions, narrowed by its environment and by its own "
        "rule. A + on a profile widens that profile for every agent on it; a + on the model "
        "limit only narrows this agent.</small></p>"
        f"{tree}</section>"
        + (f'<details class="card-like"><summary><b>✎ Advanced: edit the whole rule</b>'
           f"</summary>{edit_form}</details>" if edit_form else "")
        + _danger_zone(csrf, name, archived, has_rule)
    )
    if archived:
        detail = (f'<p class="msg warn">🗄️ This agent was archived on {esc(archived[:10])}: '
                  "its tokens are revoked and it is blocked.</p>") + detail
    body = (
        TREE_STYLE
        + '<div class="hub"><aside class="roster"><a class="new" href="/admin/agents?new=1">'
        f'＋ New agent</a>{roster}<a class="all" href="/admin/agents">All agents ›</a></aside>'
        f'<div class="detail">{detail}</div></div>'
    )
    return page(f"Agent {name}", body, active="agents")
