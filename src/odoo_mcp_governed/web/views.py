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

import json
from collections.abc import Callable, Iterable
from contextvars import ContextVar
from datetime import datetime, timezone
from html import escape
from typing import Any

from ..governance import AuditEvent, ChainStatus, Decision, Outcome
from ..governance.agents import AgentRule
from ..governance.approvals import CODE_MODELS, GRANT_MINUTES, MODULE_MODELS
from ..governance.policy import WILDCARD, is_system_model

STYLE = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1d2330;--mute:#5d6678;--line:#dfe3ea;--acc:#2f5bd3;
--ok:#1f7a4a;--warn:#9a6400;--bad:#b42318;--chip:#eef1f6}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1a1f27;--ink:#e6e9ef;--mute:#98a1b3;
--line:#2b323e;--acc:#7d9cf0;--ok:#4cc38a;--warn:#e0a63a;--bad:#f07167;--chip:#242b36}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header.bare{padding:14px 24px;border-bottom:1px solid var(--line);background:var(--card)}
.shell{display:grid;grid-template-columns:236px minmax(0,1fr);min-height:100vh}
.side{position:sticky;top:0;height:100vh;overflow-y:auto;background:var(--card);
border-right:1px solid var(--line);padding:16px 12px;display:flex;flex-direction:column;gap:10px}
.brand{font-size:16px;color:var(--ink);text-decoration:none;padding:4px 10px}
.side nav{display:flex;flex-direction:column;gap:14px;flex:1}
.group{display:flex;flex-direction:column;gap:2px}.group small{color:var(--mute);
text-transform:uppercase;letter-spacing:.06em;font-size:11px;padding:0 10px 4px}
.group a{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:8px;
color:var(--ink);text-decoration:none}.group a:hover{background:var(--chip)}
.group a.on{background:var(--acc);color:#fff}.ico{width:20px;text-align:center}
.badge{margin-left:auto;background:var(--bad);color:#fff;border-radius:99px;padding:0 7px;
font-size:11px;font-weight:700}.panic-chip{display:block;background:var(--bad);color:#fff;
padding:8px 10px;border-radius:8px;text-decoration:none;font-weight:700;text-align:center}
.logout button{width:100%}.content{min-width:0}
header.top{padding:18px 28px 0}header.top h1{font-size:20px;margin:0}
main{max-width:1240px;padding:16px 28px 48px}
@media (max-width:900px){.shell{grid-template-columns:1fr}.side{position:static;height:auto;
flex-direction:row;flex-wrap:wrap;align-items:center;border-right:0;border-bottom:1px solid var(--line)}
.side nav{flex-direction:row;overflow-x:auto;flex:1 1 100%;gap:8px}.group{flex-direction:row}
.group small{display:none}.group a{white-space:nowrap}.logout{margin-left:auto}
header.top{padding:14px 16px 0}main{padding:12px 16px 40px}}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px;margin:0 0 18px}
h2{font-size:15px;margin:0 0 12px}h3{font-size:13px;margin:14px 0 6px;color:var(--mute)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.stat{border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.stat small{display:block;color:var(--mute)}.stat strong{font-size:16px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:7px 8px;
border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mute);font-weight:600}
.wrap{overflow-x:auto}code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
input[type=text],input[type=password],input[type=url],input[type=number],input[type=search],textarea,select{width:100%;
padding:7px 9px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink);font:inherit}
textarea{min-height:64px;font-family:ui-monospace,monospace;font-size:12px}
label{display:block;margin:8px 0 3px;color:var(--mute);font-size:12px}
button{padding:7px 13px;border-radius:6px;border:1px solid var(--acc);background:var(--acc);color:#fff;
font:inherit;cursor:pointer}button.ghost{background:transparent;color:var(--acc)}
button.danger{border-color:var(--bad);background:transparent;color:var(--bad)}
.inline{display:inline-flex;gap:6px;align-items:center;margin:0}
.chip{display:inline-block;padding:1px 8px;border-radius:99px;background:var(--chip);font-size:12px}
a.stat.link{display:block;color:inherit;text-decoration:none}a.stat.link:hover,
a.hbar:hover{border-color:var(--acc);background:color-mix(in srgb,var(--acc) 7%,transparent)}
a.hbar{color:inherit;text-decoration:none;border:1px solid transparent;border-radius:6px}
svg.chart a rect:hover{opacity:.75;cursor:pointer}
a.button{display:inline-block;padding:7px 13px;border-radius:6px;background:var(--acc);
color:#fff;text-decoration:none}.spread{display:flex;justify-content:space-between;
align-items:center;gap:12px;flex-wrap:wrap}
.sum{display:flex;gap:8px;flex-wrap:wrap;margin:6px 0}
.sum span{font-size:12px;padding:2px 8px;border-radius:99px;background:var(--chip)}
a.card.agent{display:block;color:var(--ink);text-decoration:none;transition:border-color .15s}
a.card.agent:hover{border-color:var(--acc)}a.card.agent small{display:block;color:var(--mute)}
a.card.agent .open{color:var(--acc);font-weight:600;font-size:13px}
.apps{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}
.app{border:1px solid var(--line);border-radius:12px;padding:12px 14px;background:var(--bg)}
.app h3{margin:0;color:var(--ink);font-size:14px}.app details summary{cursor:pointer;
color:var(--acc);font-size:13px;margin-top:6px}
.levels{display:flex;margin:8px 0 2px;border:1px solid var(--line);border-radius:8px;
overflow:hidden}.levels button{flex:1;border:0;border-right:1px solid var(--line);border-radius:0;
background:var(--card);color:var(--ink);padding:7px 2px;font-size:12px;white-space:nowrap}
.levels button:last-child{border-right:0}.levels button.on{background:var(--acc);color:#fff}
.levels button:hover{background:var(--chip)}.levels button.on:hover{background:var(--acc)}
#perm-filter{max-width:320px}table.compact select{width:auto}
.layers{display:grid;grid-template-columns:1fr 1fr;gap:18px}.layer h2{font-size:15px}
.mirror td,.mirror th{text-align:center}.mirror td:first-child,.mirror th:first-child{text-align:left}
.brakes{display:flex;flex-direction:column;gap:10px;margin:6px 0 12px}
.brake{display:flex;justify-content:space-between;align-items:center;gap:12px;
border:1px solid var(--line);border-radius:10px;padding:10px 12px;background:var(--bg)}
.brake small{display:block;color:var(--mute)}.brake.on{border-color:var(--ok)}
.toggle{min-width:64px;font-weight:700;background:var(--chip);color:var(--mute);border-color:var(--line)}
.brake.on .toggle{background:var(--ok);border-color:var(--ok);color:#fff}
.never{background:var(--chip);border-radius:8px;padding:8px 10px;font-size:13px}
.mute{color:var(--mute)}
@media (max-width:900px){.layers{grid-template-columns:1fr}}
.tabs{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 14px}.tabs a{padding:7px 14px;border-radius:99px;
border:1px solid var(--line);background:var(--card);color:var(--ink);text-decoration:none}
.tabs a.on{background:var(--acc);border-color:var(--acc);color:#fff}.tabs small{opacity:.75}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}
.card{border:1px solid var(--line);border-radius:12px;padding:14px;background:var(--bg)}
.card h3{margin:10px 0 6px;color:var(--ink);font-size:14px;display:flex;align-items:center;gap:8px}
.card .gate{font-size:22px}.who{display:flex;gap:12px;align-items:center}.who svg{flex:none}
.pill{display:inline-flex;align-items:center;gap:2px;margin:2px;padding:1px 2px 1px 9px;
border-radius:99px;background:var(--chip);font-size:12px}.pill form{display:inline}
.pill button,.plus button{padding:0 7px;border:0;background:transparent;color:var(--mute);font-size:14px}
.pill button:hover{color:var(--bad)}.plus{display:flex;gap:4px;margin-top:8px}
.plus input{padding:4px 7px}.plus button{border:1px solid var(--acc);color:var(--acc);font-weight:700}
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
.spread{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}
.panic{border-color:var(--bad)}.panic p{margin:4px 0}
.panic.on{background:color-mix(in srgb,var(--bad) 12%,var(--card))}
.panic-btn{background:var(--bad);border-color:var(--bad);font-weight:600;padding:10px 18px}
.meter{display:inline-block;width:90px;height:8px;border-radius:4px;background:var(--chip);
vertical-align:middle;overflow:hidden}.meter span{display:block;height:100%}
.meter .ok{background:var(--ok)}.meter .warn{background:var(--warn)}.meter .bad{background:var(--bad)}
.charts{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(0,1fr);gap:18px;margin-top:12px}
@media (max-width:820px){.charts{grid-template-columns:1fr}}
.chart{width:100%;height:auto}.chart text{font-size:10px;fill:var(--mute)}
.chart rect.ok{fill:var(--ok)}.chart rect.warn{fill:var(--warn)}.chart rect.bad{fill:var(--bad)}
.hbar{display:grid;grid-template-columns:92px 1fr 36px;gap:8px;align-items:center;margin:4px 0;font-size:12px}
.hbar .track{height:10px;background:var(--chip);border-radius:5px;overflow:hidden}
.hbar .track span{display:block;height:100%}.hbar b{text-align:right}
table.compact td{padding:3px 6px}
details{border-top:1px solid var(--line);padding:8px 0}summary{cursor:pointer;padding:4px 0}
.apptoggles{margin:4px 0 6px;display:flex;gap:14px;align-items:center}
details table{table-layout:fixed}details th:nth-child(1){width:30%}details th:nth-child(2){width:30%}
details th:nth-child(3),details th:nth-child(4),details th:nth-child(5){width:9%;text-align:center}
details td:nth-child(3),details td:nth-child(4),details td:nth-child(5){text-align:center}
.console{display:flex;gap:10px;flex-wrap:wrap;justify-content:space-around;padding:12px 4px;
background:var(--chip);border-radius:10px}
.fader{display:flex;flex-direction:column;align-items:center;gap:6px;width:96px;text-align:center}
.fader input{writing-mode:vertical-lr;direction:rtl;height:150px;width:26px;accent-color:var(--acc)}
.fader output{font-size:18px;font-weight:600;font-variant-numeric:tabular-nums}
.fader b{font-size:12px}.fader small{color:var(--mute);font-size:11px}
"""


# The panel's only script, served from /static/panel.js under
# ``script-src 'self'``. It is a convenience layer: it refreshes the live
# charts and shows fader values as they move. Every control is a plain form
# and works without it — above all the panic switch.
PANEL_JS = """(function () {
  "use strict";
  function bindFaders(root) {
    root.querySelectorAll("input[type=range][data-out]").forEach(function (fader) {
      var out = document.getElementById(fader.getAttribute("data-out"));
      if (!out) return;
      fader.addEventListener("input", function () { out.textContent = fader.value; });
    });
  }
  function bindGroups(root) {
    root.querySelectorAll("input[data-app-toggle]").forEach(function (box) {
      box.addEventListener("change", function () {
        var sel = "input[data-app='" + box.getAttribute("data-app-toggle") +
          "'][data-gate='" + box.getAttribute("data-gate") + "']";
        root.querySelectorAll(sel).forEach(function (b) { if (!b.disabled) b.checked = box.checked; });
      });
    });
  }
  function bindFilter(root) {
    var box = root.getElementById ? root.getElementById("perm-filter") : null;
    if (!box) return;
    var apply = function () {
      var q = box.value.trim().toLowerCase();
      root.querySelectorAll(".app[data-search]").forEach(function (card) {
        card.hidden = q !== "" && card.getAttribute("data-search").indexOf(q) === -1;
      });
    };
    box.addEventListener("input", apply);
    apply();
  }
  document.addEventListener("DOMContentLoaded", function () {
    bindFaders(document);
    bindFilter(document);
    bindGroups(document);
    var live = document.getElementById("live");
    if (!live) return;
    var stamp = document.getElementById("live-stamp");
    setInterval(function () {
      fetch("/admin/live", { credentials: "same-origin", cache: "no-store" })
        .then(function (r) { return r.ok ? r.text() : null; })
        .then(function (html) {
          if (html === null) return;
          live.innerHTML = html;
          if (stamp) stamp.textContent = "updated " + new Date().toLocaleTimeString();
        })
        .catch(function () {});
    }, 10000);
  });
})();
"""

CATEGORY_COLORS = {
    "denylist": "#d0453a", "sensitive": "#8a5cd1", "risk": "#c27d0e", "operator": "#b42318",
    "production": "#2f5bd3", "methods": "#c2410c", "not allowed": "#64748b", "auth": "#0e7490",
    "volume": "#a16207", "other": "#94a3b8",
}


def _hourly_chart(hours: list[dict[str, Any]]) -> str:
    width, height, pad = 720, 150, 22
    peak = max((h["allowed"] + h["flagged"] + h["denied"] for h in hours), default=0) or 1
    slot = (width - 8) / max(len(hours), 1)
    bars, labels = [], []
    for i, h in enumerate(hours):
        x = 4 + i * slot
        y = height - pad
        for key, cls in (("allowed", "ok"), ("flagged", "warn"), ("denied", "bad")):
            size = (h[key] / peak) * (height - pad - 8)
            if size <= 0:
                continue
            y -= size
            show = {"allowed": "allow", "flagged": "flagged", "denied": "deny"}[key]
            bars.append(
                f'<a href="/admin/logs?agents=1&amp;decision={show}&amp;hour='
                f'{esc(h["start"].strftime("%Y-%m-%dT%H"))}">'
                f'<rect class="{cls}" x="{x + 1:.1f}" y="{y:.1f}" width="{slot - 2:.1f}" '
                f'height="{size:.1f}" rx="2"><title>{esc(h["start"].strftime("%H:00"))} · '
                f'{esc(key)} {h[key]} — click to see them</title></rect></a>'
            )
        if i % 3 == 0:
            labels.append(
                f'<text x="{x + slot / 2:.1f}" y="{height - 6}" text-anchor="middle">'
                f'{esc(h["start"].strftime("%H"))}</text>'
            )
    return (
        f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" '
        'aria-label="Agent calls per hour, last 24 hours">'
        + "".join(bars) + "".join(labels) + "</svg>"
    )


def charts_fragment(summary: dict[str, Any], *, max_risk: int) -> str:
    """The part of the dashboard the script refreshes every ten seconds."""
    categories = summary["by_category"]
    top = max(categories.values(), default=0) or 1
    category_rows = "".join(
        f'<a class="hbar" href="/admin/logs?agents=1&amp;hours=24&amp;decision=deny&amp;'
        f'kind={esc(name)}" title="See these refusals"><span class="lbl">{esc(name)}</span>'
        '<span class="track">'
        f'<span style="width:{count / top * 100:.0f}%;background:{CATEGORY_COLORS.get(name, "#94a3b8")}">'
        f'</span></span><b>{count}</b></a>'
        for name, count in categories.items()
    ) or '<p><small class="ok">No blocked attempts in the last 24 hours.</small></p>'
    models = "".join(
        f'<tr><td><a href="/admin/logs?agents=1&amp;hours=24&amp;model={esc(m)}">'
        f"<code>{esc(m)}</code></a></td><td>{n}</td></tr>" for m, n in summary["top_models"]
    ) or "<tr><td colspan=2><small>No activity.</small></td></tr>"
    risk_cls = "bad" if max_risk >= 70 else "warn" if max_risk >= 40 else "ok"
    return (
        '<div class="grid">'
        '<a class="stat link" href="/admin/logs?agents=1&amp;hours=24">'
        f'<small>Agent calls (24h) ›</small><strong>{summary["total"]}</strong></a>'
        '<a class="stat link" href="/admin/logs?agents=1&amp;hours=24&amp;decision=deny">'
        f'<small>Blocked (24h) ›</small><strong class="{"bad" if summary["denied"] else "ok"}">'
        f'{summary["denied"]}</strong></a>'
        '<a class="stat link" href="/admin/logs?agents=1&amp;hours=24&amp;decision=flagged">'
        f'<small>Flagged or throttled ›</small><strong class="{"warn" if summary["flagged"] else "ok"}">'
        f'{summary["flagged"]}</strong></a>'
        '<a class="stat link" href="/admin/logs">'
        f'<small>Highest agent risk now ›</small><strong class="{risk_cls}">{max_risk}</strong></a>'
        "</div>"
        '<div class="charts"><div><h3>Calls per hour — <span class="ok">allowed</span> · '
        '<span class="warn">flagged</span> · <span class="bad">blocked</span></h3>'
        f"{_hourly_chart(summary['hours'])}</div>"
        f"<div><h3>Blocked attempts by kind</h3>{category_rows}"
        f'<h3>Most used models</h3><table class="compact">{models}</table></div></div>'
    )


KEY_APPS = (
    ("👥", "Contacts", "res.partner"), ("📦", "Products", "product.template"),
    ("💼", "Sales", "sale.order"), ("🎯", "CRM", "crm.lead"),
    ("🧾", "Invoices", "account.move"), ("💳", "Payments", "account.payment"),
    ("🏬", "Inventory", "stock.picking"), ("🛒", "Purchases", "purchase.order"),
    ("🧑‍💼", "Point of Sale", "pos.order"), ("📋", "Projects", "project.task"),
    ("🪪", "Employees", "hr.employee"), ("📅", "Calendar", "calendar.event"),
)
"""The apps a business agent works with, each by its main model. The mirror
shows what the profile's own Odoo user may do with them."""


def follow_mode(lists: dict[str, set[str]]) -> tuple[bool, bool, bool]:
    """``(following_odoo, changes, deletes)``: governed only adds brakes on top
    of Odoo's own rights when every business model is open to read."""
    star = {WILDCARD}
    following = lists["allowed_models"] == star and lists["writable_models"] in (set(), star) \
        and lists["deletable_models"] in (set(), star)
    return following, lists["writable_models"] == star, lists["deletable_models"] == star


def brakes_section(*, csrf: str, profile: str, user: str, mirror: list[dict] | None,
                   settings_access: bool | None, lists: dict[str, set[str]],
                   approvals: frozenset[str], read_only: bool, production: bool) -> str:
    """Two layers, in the order a person thinks about them: what Odoo allows
    this profile's user, then the brakes governed puts on every agent."""
    hidden = f'{csrf_field(csrf)}<input type="hidden" name="profile" value="{esc(profile)}">'
    tick = {True: '<span class="ok">✔</span>', False: '<span class="bad">✘</span>',
            None: '<span class="mute">?</span>'}
    if mirror is None:
        table = ('<p class="msg bad">Odoo could not be asked what this user may do (is it '
                 "reachable?).</p>")
    else:
        rows = "".join(
            f'<tr><td>{icon} {esc(title)} <small><code>{esc(model)}</code></small></td>'
            + "".join(f"<td>{tick[r[op]]}</td>" for op in ("read", "create", "write", "unlink"))
            + "</tr>"
            for icon, title, model, r in ((m["icon"], m["title"], m["model"], m)
                                          for m in mirror)
        ) or "<tr><td colspan=5>None of the usual business apps is installed.</td></tr>"
        table = (
            '<div class="wrap"><table class="compact mirror"><tr><th>App</th><th>👁️ See</th>'
            f"<th>➕ Create</th><th>✏️ Change</th><th>🗑️ Delete</th></tr>{rows}</table></div>")
    if settings_access:
        who = (f'<p class="msg bad">⚠️ <b>{esc(user)}</b> has Settings access: Odoo will not '
               "stop an agent that uses it. "
               + ("On production governed refuses “follow Odoo” for such a user. " if production
                  else "")
               + "Connect this profile with a least-privilege user such as "
               "<code>mcp_agent</code> instead.</p>")
    elif settings_access is False:
        who = (f'<p class="msg ok">✔ <b>{esc(user)}</b> is a least-privilege user: Odoo itself '
               "enforces the table below, whatever happens in governed.</p>")
    else:
        who = ""
    following, changes, deletes = follow_mode(lists)

    def switch(name: str, on: bool, icon: str, title: str, hint: str,
               action: str = "/admin/permissions/brakes") -> str:
        return (
            f'<form method="post" action="{action}" class="brake{" on" if on else ""}">'
            f'{hidden}<input type="hidden" name="switch" value="{name}">'
            f'<input type="hidden" name="value" value="{"off" if on else "on"}">'
            f'<div><b>{icon} {esc(title)}</b><small>{esc(hint)}</small></div>'
            f'<button type="submit" class="toggle" aria-pressed="{"true" if on else "false"}">'
            f'{"ON" if on else "OFF"}</button></form>'
        )

    if read_only:
        brakes = ('<p class="msg warn">🏭 This profile is production without “allow writes”: '
                  "agents only read, whatever these switches say.</p>")
    else:
        brakes = ""
    approvals_on = {"delete", "bulk"} <= set(approvals)
    brakes += (
        '<div class="brakes">'
        + switch("changes", changes, "✏️", "Agents may change records",
                 "create and edit what the Odoo user may — never more")
        + switch("deletes", deletes, "🗑️", "Agents may delete records",
                 "off is the safe default: deleting is rarely an agent's job")
        + switch("approvals", approvals_on, "✋", "A person approves deletes and bulk changes",
                 "every profile: the agent waits, you approve in Approvals")
        + "</div>"
    )
    custom = "" if following else (
        '<p class="msg warn">This profile uses custom model lists (see “Advanced” below), so '
        "the switches above are not in charge. "
        f'<form method="post" action="/admin/permissions/brakes" class="inline">{hidden}'
        '<input type="hidden" name="switch" value="follow"><input type="hidden" name="value" '
        'value="on"><button type="submit">Follow Odoo’s rights again</button></form></p>')
    return (
        '<section class="layers"><div class="layer"><h2>1 · What Odoo lets '
        f'<code>{esc(user)}</code> do</h2>{who}{table}<p><small>To change this, change the '
        f"user’s groups in Odoo (Settings → Users → {esc(user)}). It is the strongest layer: "
        "Odoo enforces it even if governed were bypassed.</small></p></div>"
        '<div class="layer"><h2>2 · Brakes on every agent here</h2>'
        f"{brakes}{custom}"
        '<p class="never">🔒 <b>Never, whatever the switches:</b> passwords, API keys, '
        "certificates and keys, modules, code, users and settings.</p></div></section>"
    )


def permissions_page(
    *, csrf: str, groups: list[tuple[str, str, list[dict]]], policy: dict[str, Any],
    denied: frozenset[str], seen: set[str], query: str, error: str | None,
    flash: str | None, flash_kind: str = "ok", profiles: Iterable = (),
    profile: str = "", own: bool = False, read_only: bool = False, top: str = "",
    following: bool = False,
) -> str:
    """Permissions as apps with one level each, not hundreds of checkboxes.

    Every app gets a four-step control — none, read, change, delete — that
    sets all its models at once; "fine-tune" opens one selector per model.
    Odoo's system models sit apart, folded, reachable only one by one.
    """
    lists = {k: set(policy[k]) for k in ("allowed_models", "writable_models",
                                          "deletable_models")}
    every_model = sorted({m["model"] for _, _, ms in groups for m in ms} - set(denied))
    hidden = (f'{csrf_field(csrf)}<input type="hidden" name="profile" value="{esc(profile)}">')

    def level(model: str) -> str:
        return model_level(model, lists)

    def selector(model: str, current: str, locked: bool = False) -> str:
        if locked:
            return '<span class="chip bad">🔒 always blocked</span>'
        return (f'<select name="lvl:{esc(model)}" aria-label="Access to {esc(model)}">'
                + "".join(f'<option value="{key}"{" selected" if key == current else ""}>'
                          f"{icon} {label}</option>" for key, icon, label in LEVELS)
                + "</select>")

    def fine_tune(app: str, models: list[dict], warn: str = "") -> str:
        rows = "".join(
            f'<tr><td><code>{esc(m["model"])}</code><br><small>{esc(m["name"])}</small></td>'
            f'<td>{selector(m["model"], level(m["model"]), m["model"] in denied)}</td>'
            f'<td>{new_chip(m["model"])}</td></tr>'
            for m in models
        )
        return (
            f'<form method="post" action="/admin/permissions/models">{hidden}'
            f'<input type="hidden" name="app" value="{esc(app)}">{warn}'
            f'<div class="wrap"><table class="compact">{rows}</table></div>'
            '<p><button type="submit">Save these models</button></p></form>'
        )

    def new_chip(model: str) -> str:
        if model in denied or model in seen or level(model) != "none":
            return ""
        return '<span class="chip warn">new — not reviewed</span>'

    cards, system_models, new_total = [], [], 0
    for app, title, models in groups:
        business = [m for m in models if not is_system_model(m["model"])]
        system_models += [m for m in models if is_system_model(m["model"])]
        if not business:
            continue
        open_models = [m for m in business if m["model"] not in denied]
        levels = [level(m["model"]) for m in open_models]
        news = sum(bool(new_chip(m["model"])) for m in business)
        new_total += news
        uniform = levels[0] if levels and len(set(levels)) == 1 else ("custom" if levels else "")
        counts = " ".join(f'<span title="{label}">{icon} {levels.count(key)}</span>'
                          for key, icon, label in LEVELS[1:] if levels.count(key))
        buttons = "".join(
            f'<button type="submit" name="level" value="{key}" title="{label} — every model '
            f'of this app"{" class=on" if key == uniform else ""}>{icon} {label}</button>'
            for key, icon, label in LEVELS
        )
        search = " ".join([app, title] + [m["model"] + " " + m["name"] for m in business])
        cards.append(
            f'<div class="app" id="app-{esc(app)}" data-search="{esc(search.lower())}">'
            f'<div class="spread"><h3>{esc(title)}</h3><small>{len(business)} models'
            + (" · custom" if uniform == "custom" else "") + "</small></div>"
            f'<form method="post" action="/admin/permissions/app" class="levels">{hidden}'
            f'<input type="hidden" name="app" value="{esc(app)}">{buttons}</form>'
            f'<div class="sum">{counts}'
            + (f'<span class="warn">🆕 {news} new — not reviewed</span>' if news else "")
            + "</div>"
            f"<details><summary>Fine-tune each model</summary>{fine_tune(app, business)}"
            "</details></div>"
        )

    star = [label for key, label in (("allowed_models", "read"), ("writable_models", "change"),
                                     ("deletable_models", "delete")) if WILDCARD in lists[key]]
    star_note = (
        f'<p class="msg warn">✱ Every business model can be {esc(" / ".join(star))} '
        "(“allow every model” is on under Advanced): the levels below cannot take models "
        "away from that until you turn it off.</p>" if star else "")
    banner = (
        f'<p class="msg bad">{esc(new_total)} model(s) are new and not reviewed: they stay '
        "blocked until you give their app or them a level.</p>" if new_total else "")
    odoo_note = f'<p class="msg bad">{esc(error)}</p>' if error else ""
    system = ""
    if system_models:
        system = (
            '<details class="card-like"><summary><b>🔧 Odoo system models</b> '
            f"<small>({len(system_models)}) — users, settings, technical records. Only "
            "reachable one by one, never through an app or “*”.</small></summary>"
            + fine_tune("_system", sorted(system_models, key=lambda m: m["model"]),
                        '<p class="msg warn">Giving an agent a system model lets it see or '
                        "change how Odoo itself works. Only for a configurator agent on a test "
                        "database.</p>")
            + "</details>"
        )
    switches = "".join(
        f'<label class="inline"><input type="checkbox" name="all_{key}" value="1" '
        f'{"checked" if WILDCARD in lists[name] else ""}> <b>{label}: allow every business '
        "model</b> <small class=\"warn\">(* — includes models installed later)</small></label><br>"
        for key, name, label in (("r", "allowed_models", "Read"), ("w", "writable_models",
                                                                   "Change"),
                                 ("d", "deletable_models", "Delete"))
    )
    locked = "".join(f"<code>{esc(m)}</code> " for m in sorted(denied))
    advanced = (
        '<details class="card-like"><summary><b>⚙️ Advanced</b> <small>exact lists, '
        "“allow every model”, the denylist</small></summary>"
        + _quick_permissions(csrf, policy, profile, every_model)
        + f'<form method="post" action="/admin/permissions">{hidden}<div class="msg">{switches}'
        '</div><p><button type="submit">Apply</button></p></form>'
        f'<h3>🔒 Always blocked (denylist)</h3><p>{locked}</p>'
        "<p><small>These run code, hold credentials or control access: always blocked, "
        "whatever the levels say.</small></p></details>"
    )
    legend = " ".join(f"<span>{icon} {label}</span>" for _, icon, label in LEVELS)
    body = (
        _profile_tabs(list(profiles), profile, own, csrf, read_only) + top
        + f'<details class="card-like limit"{"" if following else " open"}><summary><b>⚙️ '
        "Advanced: limit agents to some apps or models</b> <small>only if you need less than "
        "the Odoo user may do</small></summary>"
        + odoo_note + banner + star_note
        + '<section><div class="spread"><h2>Apps</h2><input type="search" id="perm-filter" '
        f'placeholder="Find an app or model…" value="{esc(query)}" aria-label="Filter apps">'
        f'</div><p class="sum">{legend} <small>— each level includes the ones before it. One '
        "click sets every model of the app.</small></p>"
        f'<div class="apps">{"".join(cards) or "<p>No models to show.</p>"}</div></section>'
        + system + advanced + "</details>"
    )
    return page("Permissions", message(flash, flash_kind) + body)


LEVELS = (("none", "⛔", "None"), ("read", "👁️", "Read"), ("write", "✏️", "Change"),
          ("delete", "🗑️", "Delete"))


def model_level(model: str, lists: dict[str, set[str]]) -> str:
    """The highest gate a model is in; ``*`` covers business models only."""
    def has(key: str) -> bool:
        return model in lists[key] or (WILDCARD in lists[key] and not is_system_model(model))
    if has("deletable_models"):
        return "delete"
    if has("writable_models"):
        return "write"
    if has("allowed_models"):
        return "read"
    return "none"


def set_level(lists: dict[str, set[str]], model: str, level: str) -> None:
    """Put ``model`` at ``level``: each level includes the ones before it."""
    gates = {"none": (), "read": ("allowed_models",),
             "write": ("allowed_models", "writable_models"),
             "delete": ("allowed_models", "writable_models", "deletable_models")}[level]
    for key in ("allowed_models", "writable_models", "deletable_models"):
        lists[key].discard(model)
        if key in gates:
            lists[key].add(model)

ENV_ICON = {"production": "🏭", "staging": "🧪", "development": "🛠️"}
GATE_ICON = {"r": ("👁️", "Can read"), "w": ("✏️", "Can change"), "d": ("🗑️", "Can delete")}


def _profile_tabs(profiles: list, profile: str, own: bool, csrf: str,
                  read_only: bool = False) -> str:
    if not profiles:
        return ""
    tabs = [f'<a href="/admin/permissions"{" class=on" if not profile else ""}>'
            "🌐 Default <small>(every profile)</small></a>"]
    for name, env, has_own in profiles:
        on = " class=on" if name == profile else ""
        tabs.append(
            f'<a href="/admin/permissions?profile={esc(name)}"{on}>'
            f'{ENV_ICON.get(env, "🗄️")} {esc(name)} '
            f'<small>{"own" if has_own else "default"}</small></a>')
    if not profile:
        note = ("<small>These lists apply to every profile that has no permissions of its own. "
                "Pick a profile above to give it its own.</small>")
    elif own:
        note = (
            f"<small>Profile <b>{esc(profile)}</b> has its own permissions; the default lists do "
            "not apply to it.</small> "
            '<form method="post" action="/admin/permissions/reset" class="inline">'
            f'{csrf_field(csrf)}<input type="hidden" name="profile" value="{esc(profile)}">'
            '<button class="ghost" type="submit">↺ Use the default again</button></form>')
    else:
        note = (f"<small>Profile <b>{esc(profile)}</b> uses the default permissions shown "
                "below. Any change made here gives it its own, starting from these.</small>")
    if read_only:
        note += ('<p class="msg warn">🏭 This profile is production without “allow writes”: '
                 "agents can only read it. Change and delete below take effect only if you "
                 "turn writes on in the profile.</p>")
    return f'<div class="tabs">{"".join(tabs)}</div><p>{note}</p>'


def _quick_permissions(csrf: str, policy: dict, profile: str, models: list[str]) -> str:
    """The three gates as cards of chips: × takes a model out, + puts one in."""
    datalist = ('<datalist id="models">'
                + "".join(f'<option value="{esc(m)}">' for m in models) + "</datalist>")
    hidden = (f'{csrf_field(csrf)}<input type="hidden" name="profile" value="{esc(profile)}">')
    cards = []
    for key, field_name in (("r", "allowed_models"), ("w", "writable_models"),
                            ("d", "deletable_models")):
        icon, title = GATE_ICON[key]
        pills = "".join(
            f'<span class="pill">{"✱ every model" if m == "*" else esc(m)}'
            f'<form method="post" action="/admin/permissions/chip">{hidden}'
            f'<input type="hidden" name="gate" value="{key}">'
            f'<input type="hidden" name="model" value="{esc(m)}">'
            f'<button name="action" value="remove" title="Remove {esc(m)}" type="submit">×</button>'
            "</form></span>" for m in sorted(policy[field_name])
        ) or "<small>nothing yet</small>"
        cards.append(
            f'<div class="card"><h3><span class="gate">{icon}</span>{title}</h3>{pills}'
            f'<form method="post" action="/admin/permissions/chip" class="plus">{hidden}'
            f'<input type="hidden" name="gate" value="{key}">'
            '<input type="text" name="model" list="models" placeholder="add a model…" required>'
            '<button name="action" value="add" type="submit" title="Add">+</button></form></div>'
        )
    return ("<section><h2>Quick view</h2><p><small>Change and delete include read; removing "
            "read removes change and delete too. The denylist always wins.</small></p>"
            f'<div class="cards">{"".join(cards)}</div>{datalist}</section>')


def avatar(name: str, size: int = 46) -> str:
    """A small robot drawn from the agent's name, so each agent looks like itself."""
    h = sum(ord(c) * (i + 7) for i, c in enumerate(name)) % 360
    mouth = ("M15 31 q9 6 18 0" if h % 3 == 0 else "M15 31 h18" if h % 3 == 1
             else "M15 33 q9 -5 18 0")
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 48 48" aria-hidden="true">'
        f'<line x1="24" y1="3" x2="24" y2="10" stroke="hsl({h} 55% 45%)" stroke-width="2"/>'
        f'<circle cx="24" cy="4" r="3" fill="hsl({(h + 40) % 360} 75% 55%)"/>'
        f'<rect x="6" y="10" width="36" height="30" rx="9" fill="hsl({h} 60% 52%)"/>'
        f'<rect x="2" y="20" width="4" height="10" rx="2" fill="hsl({h} 55% 40%)"/>'
        f'<rect x="42" y="20" width="4" height="10" rx="2" fill="hsl({h} 55% 40%)"/>'
        '<circle cx="17" cy="22" r="4.5" fill="#fff"/><circle cx="31" cy="22" r="4.5" '
        'fill="#fff"/><circle cx="18" cy="23" r="2" fill="#1d2330"/>'
        '<circle cx="32" cy="23" r="2" fill="#1d2330"/>'
        f'<path d="{mouth}" stroke="#fff" stroke-width="2.4" fill="none" '
        'stroke-linecap="round"/></svg>'
    )


def _status_cls(r: dict) -> str:
    return "bad" if r.get("status") == "denied" else "ok"


def approvals_page(*, csrf: str, pending: list[dict], recent: list[dict], enabled: bool,
                   notifier: bool, ttl_minutes: int, flash: str | None,
                   flash_kind: str = "ok", grants: list[dict] | None = None) -> str:
    kinds: dict[tuple, int] = {}
    for r in pending:
        key = (r["actor"], r["profile"], r["tool"], r.get("model"))
        kinds[key] = kinds.get(key, 0) + 1

    def target(r: dict) -> str:
        count = f" · {esc(r['record_count'])} records" if r.get("record_count") else ""
        return f"<code>{esc(r['tool'])}</code> on <code>{esc(r.get('model') or '-')}</code>{count}"

    rows = "".join(
        f'<tr class="flag"><td class="mono">#{esc(r["id"])}</td>'
        f'<td class="mono">{esc(r["created_at"][:19].replace("T", " "))}</td>'
        f'<td><code>{esc(r["actor"])}</code></td><td>{esc(r["profile"])}</td><td>{target(r)}</td>'
        f'<td><form method="post" action="/admin/approvals/decide" class="inline">'
        f'{csrf_field(csrf)}<input type="hidden" name="id" value="{esc(r["id"])}">'
        '<button name="decision" value="approve" type="submit">Approve</button> '
        '<button class="danger" name="decision" value="deny" type="submit">Deny</button>'
        f'{_similar(r, kinds)}'
        "</form></td></tr>"
        for r in pending
    ) or "<tr><td colspan=6>Nothing is waiting for you.</td></tr>"
    standing = "".join(
        f'<tr><td><code>{esc(g["actor"])}</code></td><td>{esc(g["profile"])}</td>'
        f'<td><code>{esc(g["tool"])}</code> on <code>{esc(g.get("model") or "-")}</code></td>'
        f'<td class="mono">{esc(g["until"][:16].replace("T", " "))}</td>'
        f'<td>{esc(g["uses"])}/{esc(g["max_uses"])}</td>'
        f'<td><form method="post" action="/admin/approvals/grant/revoke" class="inline">'
        f'{csrf_field(csrf)}<input type="hidden" name="id" value="{esc(g["id"])}">'
        '<button class="danger" type="submit">Withdraw</button></form></td></tr>'
        for g in grants or []
    )
    standing = (
        "<section><h2>Standing approvals</h2><p><small>Calls of these kinds go through "
        "without asking until the time or the uses run out.</small></p><div class=\"wrap\">"
        "<table><tr><th>Agent</th><th>Profile</th><th>Calls</th><th>Until (UTC)</th>"
        f"<th>Used</th><th></th></tr>{standing}</table></div></section>" if standing else ""
    )
    history = "".join(
        f'<tr><td class="mono">#{esc(r["id"])}</td><td><code>{esc(r["actor"])}</code></td>'
        f"<td>{target(r)}</td><td><span class='chip {_status_cls(r)}'>"
        f'{esc(r["status"])}</span></td><td>{esc(r.get("decided_by") or "")}</td></tr>'
        for r in recent
    ) or "<tr><td colspan=5>No decisions yet.</td></tr>"
    state = (
        "<p class=\"msg warn\">Approvals are off. Turn them on under <a href=\"/admin\">Access "
        "policy</a> → Human approval.</p>" if not enabled else ""
    )
    channel = (
        "" if notifier else
        "<p><small>No notification channel is configured: set APPROVAL_WEBHOOK_URL or "
        "TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to be told when an agent is waiting."
        "</small></p>"
    )
    body = (
        f"<section><h2>Waiting for approval</h2>{state}{channel}<p><small>Approving lets the "
        f"agent repeat that exact call once within {ttl_minutes} minutes. Decisions are sealed "
        "into the audit log.</small></p>"
        '<div class="wrap"><table><tr><th>#</th><th>Requested (UTC)</th><th>Agent</th>'
        f"<th>Profile</th><th>Wants to</th><th></th></tr>{rows}</table></div></section>"
        "<section><h2>Recent decisions</h2><div class=\"wrap\"><table><tr><th>#</th>"
        f"<th>Agent</th><th>Call</th><th>Status</th><th>By</th></tr>{history}</table></div>"
        "</section>"
    )
    return page("Approvals", message(flash, flash_kind) + body.replace(
        "<section><h2>Recent decisions", standing + "<section><h2>Recent decisions", 1))


def _similar(r: dict, kinds: dict[tuple, int]) -> str:
    """Ways to decide many at once — the cure for approval fatigue."""
    same = kinds.get((r["actor"], r["profile"], r["tool"], r.get("model")), 1)
    group = (
        f' <button name="decision" value="approve_group" type="submit">Approve all {same}</button>'
        f' <button class="danger" name="decision" value="deny_group" type="submit">'
        f"Deny all {same}</button>" if same > 1 else ""
    )
    if r.get("model") in CODE_MODELS | MODULE_MODELS:
        return group  # modules and code: every one is read, never a standing grant
    options = "".join(f'<option value="{m}">{m // 60}h</option>' if m >= 60
                      else f'<option value="{m}">{m} min</option>' for m in GRANT_MINUTES)
    return (
        f'{group}<br><small>or approve this and similar calls (same agent, tool and '
        f'model) for</small> <select name="minutes">{options}</select> '
        '<button name="decision" value="approve_similar" type="submit">Approve similar</button>'
    )


REPORT_STYLE = """
@media print{header,nav,.noprint{display:none!important}body{background:#fff;color:#000}
section{break-inside:avoid;border-color:#bbb}main{max-width:none;padding:0}}
.kpi strong{font-size:22px}.lead{font-size:15px;margin:4px 0 0}
"""


def report_html(r: dict[str, Any], profiles: list[str] | None = None) -> str:
    """A self-contained, printable activity report. Counts only, no values."""
    def fmt(d: datetime) -> str:
        return d.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    kpis = (
        ("Agent calls", r["total_calls"], ""), ("Refused", r["total_refused"],
                                                 "bad" if r["total_refused"] else "ok"),
        ("Records changed", r["changes"]["total"], ""),
        ("Undone", r["changes"]["undone"], ""),
        ("Peak risk", r["peak_risk"], "bad" if r["peak_risk"] >= 70 else
         "warn" if r["peak_risk"] >= 40 else "ok"),
        ("Audit chain", "intact" if r["chain_intact"] else "BROKEN",
         "ok" if r["chain_intact"] else "bad"),
    )
    kpi_html = "".join(
        f'<div class="stat kpi"><small>{esc(label)}</small><strong class="{cls}">{esc(value)}'
        "</strong></div>" for label, value, cls in kpis
    )
    agent_rows = "".join(
        f"<tr><td><code>{esc(a)}</code></td><td>{c.get('calls', 0)}</td>"
        f"<td>{c.get('records_read', 0)}</td><td>{c.get('records_written', 0)}</td>"
        f"<td>{c.get('records_deleted', 0)}</td><td>{c.get('refused', 0)}</td>"
        f"<td>{c.get('errors', 0)}</td></tr>"
        for a, c in r["agents"]
    ) or "<tr><td colspan=7>No agent activity in this period.</td></tr>"
    model_rows = "".join(
        f"<tr><td><code>{esc(m)}</code></td><td>{n}</td></tr>" for m, n in r["models"]
    ) or "<tr><td colspan=2>—</td></tr>"
    refusal_rows = "".join(
        f"<tr><td>{esc(k)}</td><td>{v}</td></tr>" for k, v in r["refusals"].items()
    ) or "<tr><td colspan=2 class=ok>Nothing was refused.</td></tr>"
    change_rows = "".join(
        f'<tr><td class="mono">{esc(c["ts"][:16].replace("T", " "))}</td>'
        f'<td><code>{esc(c["actor"])}</code></td><td>{esc(c["operation"])}</td>'
        f'<td><code>{esc(c["model"])}</code></td><td class="mono">{esc(c["record_id"])}</td>'
        f'<td>{"undone" if c.get("undone_at") else ""}</td></tr>'
        for c in r["changes"]["latest"]
    ) or "<tr><td colspan=6>No changes.</td></tr>"
    ops = ", ".join(f"{k} {v}" for k, v in r["changes"]["by_operation"].items()) or "none"
    appr = ", ".join(f"{k} {v}" for k, v in r["approvals"].items()) or "none"
    body = (
        "<section><h2>AI activity report</h2>"
        f'<p class="lead">Odoo <b>{esc(r["database"])}</b> · profile <b>{esc(r["profile"])}</b> '
        f'({esc(r["environment"])})</p><p><small>{esc(fmt(r["start"]))} → '
        f'{esc(fmt(r["generated_at"]))} · {r["days"]} days · counts and metadata only, no record '
        "values</small></p>"
        f'<div class="grid">{kpi_html}</div>'
        '<p class="noprint"><small>Print this page and choose "Save as PDF" to send it. '
        "Per client: "
        + " · ".join(f'<a href="/admin/report?profile={esc(p)}">{esc(p)}</a>'
                     for p in profiles or [])
        + "</small></p>"
        "</section>"
        "<section><h2>What each agent did</h2><div class=\"wrap\"><table><tr><th>Agent</th>"
        "<th>Calls</th><th>Records read</th><th>Records created or changed</th>"
        f"<th>Records deleted</th><th>Refused</th><th>Errors</th></tr>{agent_rows}</table></div>"
        "</section>"
        '<section><div class="row"><div><h2>Most used models</h2>'
        f"<table>{model_rows}</table></div><div><h2>What governance refused</h2>"
        f"<table>{refusal_rows}</table><p><small>Approvals: {esc(appr)}. Panic stops: "
        f'{r["panic_events"]}. Agents blocked: {r["blocks"]}.</small></p></div></div></section>'
        f"<section><h2>Changes to records</h2><p><small>{esc(ops)}. Every change can be "
        "reverted from the panel's Changes page.</small></p><div class=\"wrap\"><table><tr>"
        "<th>When (UTC)</th><th>Agent</th><th>Operation</th><th>Model</th><th>Record</th><th></th>"
        f"</tr>{change_rows}</table></div></section>"
        f'<section><h2>Integrity</h2><p class="{"ok" if r["chain_intact"] else "bad"}">'
        f'{esc(r["chain_summary"])}</p><p><small>Every agent call and every administrator '
        "action is sealed into a hash-chained audit log; any edit or deletion of a past "
        "entry breaks the chain.</small></p></section>"
    )
    html = page("AI activity report", body, active="report")
    return html.replace("</style>", REPORT_STYLE + "</style>", 1)


def console_section(*, csrf: str, tuning: dict[str, int], source: str) -> str:
    faders = (
        ("risk_throttle_threshold", "Throttle at", 5, 100, 1, "risk score"),
        ("risk_block_threshold", "Block at", 10, 100, 1, "risk score"),
        ("delete_burst_threshold", "Delete burst", 1, 20, 1, "deletes / min"),
        ("rate_threshold", "Call rate", 10, 600, 10, "calls / min"),
        ("half_life_minutes", "Memory", 1, 120, 1, "half-life, min"),
    )
    columns = "".join(
        f'<div class="fader"><output id="out-{name}">{tuning[name]}</output>'
        f'<input type="range" name="{name}" min="{low}" max="{max(high, tuning[name])}" '
        f'step="{step}" value="{tuning[name]}" data-out="out-{name}" aria-label="{esc(label)}">'
        f"<b>{esc(label)}</b><small>{esc(unit)}</small></div>"
        for name, label, low, high, step, unit in faders
    )
    return (
        "<section><h2>Threshold console</h2><p><small>Applies to the next call, survives "
        f'restarts and is sealed into the audit log. Source: <span class="chip">{esc(source)}</span>'
        "</small></p>"
        f'<form method="post" action="/admin/tuning">{csrf_field(csrf)}'
        f'<div class="console">{columns}</div>'
        '<p><button type="submit">Apply thresholds</button></p></form></section>'
    )


def esc(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


NAV_STATE: ContextVar[Callable[[], dict[str, Any]] | None] = ContextVar(
    "nav_state", default=None)
"""Set per request by the app: live numbers for the sidebar (pending
approvals, panic). Pages render without it, with no badges."""

NAV = (
    ("", (("agents", "🤖", "Agents", "/admin/agents"),
          ("summary", "📊", "Dashboard", "/admin"))),
    ("Monitor", (("approvals", "✋", "Approvals", "/admin/approvals"),
                 ("audit", "📜", "Audit log", "/admin/logs"),
                 ("changes", "↩️", "Changes", "/admin/changes"),
                 ("report", "📄", "Report", "/admin/report"))),
    ("Configure", (("permissions", "🔑", "Permissions", "/admin/permissions"),
                   ("profiles", "🗄️", "Odoo instances", "/admin?tab=profiles"),
                   ("policy", "🛡️", "Policy & thresholds", "/admin?tab=policy"),
                   ("token", "🔌", "Connect a client", "/token"))),
)
ACTIVE_BY_TITLE = {"Dashboard": "summary", "Odoo instances": "profiles",
                   "Policy & thresholds": "policy", "Audit log": "audit", "Changes": "changes",
                   "Permissions": "permissions", "Approvals": "approvals", "Agents": "agents",
                   "Report": "report", "Connect a client": "token"}


def _sidebar(active: str) -> str:
    getter = NAV_STATE.get()
    state = getter() if getter else {}
    badges = {"approvals": state.get("approvals") or 0}
    groups = []
    for label, items in NAV:
        links = "".join(
            f'<a href="{url}"{" class=on aria-current=page" if key == active else ""}>'
            f'<span class="ico">{icon}</span>{esc(text)}'
            + (f'<span class="badge">{badges[key]}</span>' if badges.get(key) else "")
            + "</a>"
            for key, icon, text, url in items
        )
        head = f"<small>{esc(label)}</small>" if label else ""
        groups.append(f'<div class="group">{head}{links}</div>')
    panic = ('<a class="panic-chip" href="/admin">⛔ Panic is ON</a>'
             if state.get("panic") else "")
    return (
        '<aside class="side"><a class="brand" href="/admin/agents">🛡️ <b>governed</b></a>'
        f'{panic}<nav aria-label="Main">{"".join(groups)}</nav>'
        '<form method="post" action="/admin/logout" class="logout">'
        '<button class="ghost" type="submit">Log out</button></form></aside>'
    )


def page(title: str, body: str, *, nav: bool = True, active: str | None = None) -> str:
    head = (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        f"<title>{esc(title)} · odoo-mcp-governed</title><style>{STYLE}</style>"
        '<script src="/static/panel.js" defer></script></head>'
    )
    if not nav:
        return (head + '<body><header class="bare"><b>🛡️ odoo-mcp-governed</b></header>'
                f"<main>{body}</main></body></html>")
    key = active or ACTIVE_BY_TITLE.get(title) or (
        "agents" if title.startswith("Agent") else "")
    return (
        head + f'<body class="shell">{_sidebar(key)}<div class="content">'
        f'<header class="top"><h1>{esc(title)}</h1></header>'
        f"<main>{body}</main></div></body></html>"
    )


def csrf_field(csrf: str) -> str:
    return f'<input type="hidden" name="csrf" value="{esc(csrf)}">'


def message(text: str | None, kind: str = "ok") -> str:
    return f'<div class="msg {esc(kind)}">{esc(text)}</div>' if text else ""


def login_page(error: str | None = None, *, totp: bool = False) -> str:
    code = (
        '<label for=t>Authenticator code</label>'
        '<input id=t type="text" name="totp" inputmode="numeric" pattern="[0-9 ]{6,7}" '
        'autocomplete="one-time-code" required>'
        if totp else ""
    )
    body = (
        '<section class="login"><h2>Administrator login</h2>'
        f"{message(error, 'bad')}"
        '<form method="post" action="/admin">'
        '<label for=p>Password</label>'
        '<input id=p type="password" name="password" autocomplete="current-password" required autofocus>'
        f'{code}<p><button type="submit">Log in</button></p></form></section>'
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
    panic: bool = False,
    agents: list[tuple[str, int, int, bool]] | None = None,
    summary: dict[str, Any] | None = None,
    max_risk: int = 0,
    tuning: dict[str, int] | None = None,
    tuning_source: str = ".env",
    tab: str = "summary",
    profile_cards: str = "",
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

    if panic:
        emergency = (
            '<section class="panic on"><h2>⛔ Every agent is stopped</h2>'
            "<p>The panic switch is engaged: every MCP call is refused, and it stays that way "
            "across restarts until you resume. Audit logging continues.</p>"
            f'<form method="post" action="/admin/resume" class="inline">{csrf_field(csrf)}'
            '<label class="inline"><input type="checkbox" name="confirm" value="yes"> confirm</label>'
            '<button type="submit">Resume service</button></form></section>'
        )
    else:
        emergency = (
            '<section class="panic"><div class="spread"><div><h2>Emergency stop</h2>'
            "<p><small>Refuses every agent call on the next request, keeps the panel and the "
            "audit log running, and survives restarts.</small></p></div>"
            f'<form method="post" action="/admin/panic" class="inline">{csrf_field(csrf)}'
            '<button class="panic-btn" type="submit">⛔ Panic: stop every agent</button>'
            "</form></div></section>"
        )

    live_section = (
        '<section><div class="spread"><h2>Live activity — last 24 hours</h2>'
        '<small id="live-stamp" class="chip">refreshes every 10 s</small></div>'
        f'<div id="live">{charts_fragment(summary, max_risk=max_risk)}</div></section>'
        if summary is not None else ""
    )
    console = console_section(csrf=csrf, tuning=tuning, source=tuning_source) if tuning else ""

    agent_rows = []
    for actor, score, count, is_blocked in agents or []:
        level = "bad" if score >= 70 else "warn" if score >= 40 else "ok"
        action = "unblock" if is_blocked else "block"
        state = '<span class="chip bad">blocked</span>' if is_blocked else (
            '<span class="chip ok">active</span>')
        agent_rows.append(
            f'<tr><td><a href="/admin/agents/view?name={esc(actor)}">🤖 <code>{esc(actor)}</code>'
            f'</a> <small><a href="/admin/logs?actor={esc(actor)}">log</a></small></td>'
            f"<td>{state}</td>"
            f'<td><span class="meter"><span class="{level}" style="width:{min(score, 100)}%">'
            f"</span></span> {esc(score)}</td><td>{esc(count)}</td>"
            f'<td><form method="post" action="/admin/actor/{action}" class="inline">'
            f'{csrf_field(csrf)}<input type="hidden" name="actor" value="{esc(actor)}">'
            f'<button class="{"ghost" if is_blocked else "danger"}" type="submit">'
            f'{"Unblock" if is_blocked else "Block agent"}</button></form></td></tr>'
        )
    agents_section = (
        "<section><h2>Agents</h2><p><small>Active in the last hour, plus every blocked agent. "
        "Blocking refuses that agent's next call; the others keep working.</small></p>"
        '<div class="wrap"><table><tr><th>Agent</th><th>State</th><th>Risk</th>'
        "<th>Calls (1h)</th><th></th></tr>"
        + ("".join(agent_rows) or "<tr><td colspan=5>No agent activity in the last hour.</td></tr>")
        + "</table></div></section>"
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
            if p.get("sandbox"):
                env_badge += ' <span class="chip warn">sandbox · unrestricted</span>'
            if p.get("configurator"):
                env_badge += ' <span class="chip bad">configurator · whole system</span>'
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
        "<small class=bad>(lifts read-only)</small></label>"
        "<label>Access level <small>(sandbox and configurator: never on production)</small>"
        "</label><select name=\"level\">"
        + "".join(
            f'<option value="{v}" {"selected" if e.get("level", "business") == v else ""}>{label}'
            "</option>"
            for v, label in (
                ("business", "business — business models only, lists apply"),
                ("sandbox", "sandbox — business models, no lists, risk only observed"),
                ("configurator", "configurator — the whole system, for setting Odoo up"),
            )
        )
        + "</select></div>"
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
        + area("transient_allowlist", "Allowed wizards", "TRANSIENT_ALLOWLIST — all others refused")
        + '</div><h3>Human approval</h3><p><small>Held calls wait in '
        + '<a href="/admin/approvals">Approvals</a>; the agent repeats the call once approved.'
        + "</small></p><div class=\"row\"><div>"
        + "".join(
            f'<label class="inline"><input type="checkbox" name="approval_required" value="{k}" '
            f'{"checked" if k in policy["approval_required"] else ""}> {label}</label><br>'
            for k, label in (("delete", "every delete"),
                             ("bulk", "bulk create, write or delete"),
                             ("execute", "every execute_method"))
        )
        + '</div><div><label>Bulk means more than (records)</label><input type="number" '
        + 'name="approval_bulk_threshold" min="1" max="100000" '
        + f'value="{esc(policy["approval_bulk_threshold"])}"></div></div>'
        + '<h3>Sensitive fields — never read, written or filtered on</h3>'
        + '<p><small>Patterns, one per line: <code>*_key</code>, <code>*iban*</code>. '
        + 'Always on, whatever this list says: <code>*password*</code> <code>*secret*</code> '
        + '<code>*token*</code> <code>*api_key*</code> <code>*apikey*</code> '
        + '<code>*private_key*</code>.</small></p><div class="row">'
        + area("sensitive_fields", "Extra patterns", "SENSITIVE_FIELDS")
        + '</div><p><button type="submit">Apply policy</button></p></form></section>'
    )
    panes = {
        "summary": ("📊 Summary", status + live_section + agents_section),
        "profiles": ("🗄️ Odoo profiles", profile_cards + profiles_section),
        "policy": ("🛡️ Policy and thresholds", policy_section + console),
    }
    tab = tab if tab in panes else "summary"
    # One page, three places in the sidebar. Every pane is in the page so a
    # link to any of them always works; only the chosen one is shown.
    body = "".join(f'<div id="pane-{key}"{"" if key == tab else " hidden"}>{html}</div>'
                   for key, (_, html) in panes.items())
    title = {"summary": "Dashboard", "profiles": "Odoo instances",
             "policy": "Policy & thresholds"}[tab]
    return page(title, message(flash, flash_kind) + (emergency if tab == "summary" else "")
                + body, active=tab)


def profile_cards(profiles: list[dict[str, Any]], *, summaries: dict[str, str],
                  own: set[str], agents_by_profile: dict[str, list[str]]) -> str:
    """One card per Odoo: environment, permissions, and who is pinned to it."""
    cards = []
    for p in profiles:
        name = p["name"]
        env = p.get("environment", "")
        level = ("🧪 sandbox" if p.get("sandbox") else "🧰 configurator" if p.get("configurator")
                 else "")
        writes = ("✏️ writes on" if env != "production" or p.get("allow_writes")
                  else "👁️ read-only")
        pinned = agents_by_profile.get(name, [])
        cards.append(
            f'<div class="card"><h3>{ENV_ICON.get(env, "🗄️")} {esc(name)}'
            + (' <span class="chip ok">★ active</span>' if p.get("active") else "") + "</h3>"
            f'<small>{esc(env)} · {esc(p.get("url", ""))}</small>'
            f'<p><span class="chip">{writes}</span> '
            + (f'<span class="chip">{level}</span> ' if level else "")
            + f'<span class="chip">{"🔑 own permissions" if name in own else "🌐 default permissions"}'
            f'</span></p><div class="sum">{summaries.get(name, "")}</div>'
            + (f'<p><small>📌 {esc(", ".join(pinned))}</small></p>' if pinned else "")
            + f'<p><a href="/admin/permissions?profile={esc(name)}">🔑 permissions</a> · '
            f'<a href="/admin?tab=profiles&amp;edit={esc(name)}">✎ edit</a></p></div>'
        )
    return ('<section><h2>Your Odoo instances</h2><div class="cards">' + "".join(cards)
            + "</div></section>") if cards else ""


def connect_page(*, csrf: str, mcp_url: str, agents: list[str], profiles: list[str],
                 issued: dict[str, Any] | None = None, legacy: dict[str, Any] | None = None,
                 flash: str | None = None, flash_kind: str = "ok") -> str:
    """Connect a client: issue a registered token and get the config to paste.

    The server keeps no copy of the token — only its id, to revoke it — so
    the snippets below carry it this once.
    """
    known = "".join(f'<option value="{esc(a)}">' for a in agents)
    profile_options = '<option value="">its rule’s profile, or the active one</option>' + "".join(
        f'<option value="{esc(p)}">pinned to {esc(p)}</option>' for p in profiles)
    form = (
        '<section><h2>1 · Issue a token</h2>'
        f'<form method="post" action="/admin/token/regenerate">{csrf_field(csrf)}'
        '<div class=row><div><label>Agent (who this client is)</label>'
        '<input type="text" name="actor" list="connect-agents" value="claude" '
        'pattern="[A-Za-z0-9_.@\\-]{1,64}" required>'
        f'<datalist id="connect-agents">{known}</datalist></div>'
        f'<div><label>Odoo profile</label><select name="profile">{profile_options}</select></div>'
        '<div><label>Label</label><input type="text" name="label" '
        'placeholder="e.g. laptop, n8n, WhatsApp bot"></div>'
        '<div><label>Hours (empty = default)</label><input type="number" name="hours" min="1">'
        "</div></div><p><small>Each client gets its own token: revoke one without touching the "
        "others. The token is shown once; the server keeps only its id.</small></p>"
        '<p><button type="submit">Issue token</button></p></form></section>'
    )
    snippets = ""
    if issued:
        token = issued["token"]
        config = json.dumps({"odoo-governed": {
            "type": "http", "url": mcp_url,
            "headers": {"Authorization": f"Bearer {token}"}}}, indent=2)
        pinned = (f" · pinned to <b>{esc(issued['profile'])}</b>" if issued.get("profile")
                  else " · follows its rule or the active profile")
        snippets = (
            f'<section class="issued"><h2>2 · Paste it into the client</h2>'
            f'<p class="msg warn">Shown only once. Agent <b>{esc(issued["actor"])}</b>{pinned} · '
            f'expires {esc(issued["expires_at"][:16].replace("T", " "))} UTC.</p>'
            "<h3>Token</h3>"
            f'<textarea readonly class="mono" rows="3">{esc(token)}</textarea>'
            "<h3>Claude Code — inside <code>mcpServers</code> of <code>~/.claude.json</code>, "
            "then <code>/mcp</code> → Reconnect</h3>"
            f'<textarea readonly class="mono" rows="9">{esc(config)}</textarea>'
            "<h3>Any HTTP client (n8n, a script, another agent)</h3>"
            f'<textarea readonly class="mono" rows="4">URL: {esc(mcp_url)}\n'
            f"Header: Authorization: Bearer {esc(token)}</textarea>"
            "<h3>Test it from a terminal</h3>"
            '<textarea readonly class="mono" rows="4">'
            f"curl -s -X POST {esc(mcp_url)} -H 'Content-Type: application/json' "
            f"-H 'Authorization: Bearer {esc(token)}' "
            "-d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}'</textarea>"
            "<p><small>A command line keeps what you type in its history: prefer pasting the "
            "token into the file over passing it as an argument.</small></p>"
            f'<p><a href="/admin/agents/view?name={esc(issued["actor"])}">'
            f'🌳 Open {esc(issued["actor"])}’s tree</a> to see or revoke its tokens.</p>'
            "</section>"
        )
    else:
        snippets = (
            "<section><h2>2 · Paste it into the client</h2><p>Issue a token above: this "
            "section then shows it, ready to paste, for Claude Code, n8n or any HTTP client. "
            f"The endpoint is <code>{esc(mcp_url)}</code>.</p></section>"
        )
    old = ""
    if legacy:
        old = (
            '<details class="card-like"><summary><b>🗄️ A token stored by the old “Panel token” '
            "page</b></summary><p><small>Older versions kept one token on disk and showed it "
            f'here every time. Agent <b>{esc(legacy.get("actor"))}</b>, expires '
            f'{esc(str(legacy.get("expires_at", ""))[:10])}. If a client still uses it, keep it '
            "until you switch that client to a new token; then forget it. Forgetting deletes "
            "the copy on disk — revoke it from the agent’s tree to stop it working.</small></p>"
            f'<textarea readonly class="mono" rows="3">{esc(legacy.get("token"))}</textarea>'
            f'<form method="post" action="/admin/token/forget">{csrf_field(csrf)}'
            '<label class="inline"><input type="checkbox" name="confirm" value="yes" required> '
            'confirm</label> <button class="danger" type="submit">Forget the stored copy</button>'
            "</form></details>"
        )
    return page("Connect a client", message(flash, flash_kind) + form + snippets + old)

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
        f"<td>{esc(e.affected_count if e.affected_count is not None else '')}"
        f"{_ids_cell(e.record_ids)}</td>"
        f"<td>{esc(e.risk_score or '')}</td><td>{esc(signals)}</td>"
        f"<td><small>{esc(notes)}</small></td></tr>"
    )


def _ids_cell(ids: tuple[int, ...]) -> str:
    if not ids:
        return ""
    shown = ", ".join(str(i) for i in ids[:10])
    more = f" +{len(ids) - 10}" if len(ids) > 10 else ""
    return f'<br><small class="mono">ids {esc(shown + more)}</small>'


def _values(value: Any) -> str:
    if value is None:
        return "<small>—</small>"
    text = json.dumps(value, ensure_ascii=False, default=str, indent=1)
    return f'<pre class="mono">{esc(text)}</pre>'


def _undo_cell(c: dict[str, Any], csrf: str) -> str:
    if c.get("undone_at"):
        return (f'<span class="chip ok">undone</span><br><small>{esc(c.get("undo_note"))}<br>'
                f'{esc(str(c["undone_at"])[:19].replace("T", " "))} · {esc(c.get("undone_by"))}'
                "</small>")
    what = {"write": "restore old values", "create": "delete the record",
            "unlink": "recreate the record"}.get(c["operation"], "undo")
    return (
        f'<form method="post" action="/admin/changes/undo" class="inline">{csrf_field(csrf)}'
        f'<input type="hidden" name="change_id" value="{esc(c["id"])}">'
        '<label class="inline"><input type="checkbox" name="confirm" value="yes" required>'
        f'<small>{esc(what)}</small></label><button class="danger" type="submit">Undo</button>'
        "</form>"
    )


def changes_page(*, entries: list[dict[str, Any]], enabled: bool,
                 filters: dict[str, str], csrf: str = "", flash: str | None = None,
                 flash_kind: str = "ok") -> str:
    """The change journal: old and new values, newest first."""
    if not enabled:
        return page("Changes", "<section><h2>Changes</h2><p>The change journal is off "
                    "(<code>CHANGE_JOURNAL=false</code>).</p></section>")
    rows = "".join(
        f'<tr><td class="mono">{esc(c["audit_seq"])}</td>'
        f'<td class="mono">{esc(c["ts"][:19].replace("T", " "))}</td>'
        f'<td>{esc(c["actor"])}</td><td>{esc(c["profile"])}</td>'
        f'<td><code>{esc(c["model"])}</code></td><td>{esc(c["operation"])}</td>'
        f'<td class="mono">{esc(c["record_id"])}</td>'
        f"<td>{_values(c['before'])}</td><td>{_values(c['after'])}</td>"
        f"<td>{_undo_cell(c, csrf)}</td></tr>"
        for c in entries
    ) or "<tr><td colspan=10>No changes recorded.</td></tr>"
    body = (
        "<section><h2>Changes</h2><p><small>Old and new values of every create, write "
        "and delete. Credential fields are never stored. <b>#</b> is the audit event "
        "that sealed the change.</small></p>"
        '<form method="get" action="/admin/changes"><div class="row">'
        f'<div><label>Model</label><input type="text" name="model" value="{esc(filters.get("model"))}"></div>'
        f'<div><label>Record id</label><input type="number" name="record_id" min="1" value="{esc(filters.get("record_id"))}"></div>'
        f'<div><label>Rows</label><input type="number" name="limit" min="1" max="2000" value="{esc(filters.get("limit") or 200)}"></div>'
        '</div><p><button type="submit">Filter</button></p></form>'
        '<div class="wrap"><table><tr><th>#</th><th>Time (UTC)</th><th>Actor</th><th>Profile</th>'
        "<th>Model</th><th>Operation</th><th>Record</th><th>Before</th><th>After</th>"
        "<th></th></tr>"
        + rows + "</table></div></section>"
    )
    return page("Changes", message(flash, flash_kind) + body)


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
        for v in ("", "allow", "allow_flagged", "throttle", "flagged", "deny")
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
    labels = {"agents": "agent calls only", "hours": "last {} h", "hour": "hour {}",
              "kind": "refusal kind: {}", "model": "model: {}"}
    active = [(k, v) for k, v in f.items() if k in labels and v]
    filtered = "" if not active else (
        '<p class="msg">Showing '
        + " · ".join(f"<b>{esc(labels[k].format(v))}</b>" for k, v in active)
        + (f' · <b>decision: {esc(f["decision"])}</b>' if f.get("decision") else "")
        + f' — {len(events)} event(s). <a href="/admin/logs">clear filters</a></p>'
    )
    form = (
        f'<section><h2>Audit log</h2><p>{shortcuts}</p>{filtered}'
        '<form method="get" action="/admin/logs"><div class="row">'
        f'<div><label>Actor</label><input type="text" name="actor" value="{esc(f.get("actor"))}"></div>'
        f'<div><label>Tool (prefix)</label><input type="text" name="tool" value="{esc(f.get("tool"))}"></div>'
        f'<div><label>Decision</label><select name="decision">{options}</select></div>'
        f'<div><label>Text</label><input type="text" name="q" value="{esc(f.get("q"))}"></div>'
        f'<div><label>Model</label><input type="text" name="model" value="{esc(f.get("model"))}">'
        "</div>"
        + "".join(f'<input type="hidden" name="{k}" value="{esc(f.get(k))}">'
                  for k in ("agents", "hours", "hour", "kind") if f.get(k)) +
        f'<div><label>Rows</label><input type="number" name="limit" min="1" max="2000" '
        f'value="{esc(f.get("limit") or 200)}"></div>'
        '</div><p><button type="submit">Filter</button></p></form>'
        '<div class="wrap"><table><tr><th>#</th><th>Time (UTC)</th><th>Actor</th><th>Profile</th>'
        "<th>Tool</th><th>Model</th><th>Decision</th><th>Outcome</th><th>Records</th><th>Risk</th>"
        "<th>Signals</th><th>Reasons</th></tr>"
        + ("".join(_event_row(e) for e in events) or "<tr><td colspan=12>No events.</td></tr>")
        + "</table></div></section>"
    )
    # Arriving from a dashboard number, the events come first.
    return page("Audit log", message(flash) + (form + header if active else header + form))


def agents_page(*, csrf: str, rules: dict, tokens: list[dict], profiles: list[str],
                tools: list[str], issued: dict | None = None, edit: Any = None,
                flash: str | None = None, flash_kind: str = "ok",
                require_registered: bool = False, selected: str = "",
                read_only_profiles: frozenset[str] = frozenset(),
                seen: dict[str, tuple[int, int, str]] | None = None,
                summaries: dict[str, str] | None = None, new_name: str = "",
                open_form: bool = False, archived: dict[str, str] | None = None) -> str:
    """The agent registry: one rule per agent, every token it holds."""
    shown = ""
    if issued:
        shown = (
            '<section><h2>New token</h2><p class="msg warn">Copy it now: it is shown only '
            f'once. Agent <b>{esc(issued["actor"])}</b> · expires '
            f'{esc(issued["expires_at"][:16].replace("T", " "))} UTC'
            + (f' · pinned to <b>{esc(issued["profile"])}</b>' if issued.get("profile") else "")
            + f'</p><textarea readonly class="mono">{esc(issued["token"])}</textarea></section>'
        )

    def chips(values, empty: str) -> str:
        return " ".join(f"<code>{esc(v)}</code>" for v in sorted(values)) or empty


    def card(name: str, r) -> str:
        """One agent, the whole card a link to its tree — where it is managed."""
        has_rule = name in rules
        stat = (seen or {}).get(name)
        activity = (f"{stat[0]} calls in 24 h · last {esc(stat[2][11:16])} UTC" if stat
                    else "no calls yet")
        if not has_rule:
            badges = '<span class="chip">🌐 follows the server policy</span>'
        else:
            badges = " ".join(b for b in (
                '<span class="chip warn">👁️ read-only</span>' if r.read_only else
                '<span class="chip warn">🏭 read-only (production)</span>'
                if r.profile in read_only_profiles else '<span class="chip ok">✏️ may write</span>',
                f'<span class="chip">⏱️ {esc(r.daily_quota)}/day</span>' if r.daily_quota else "",
                f'<span class="chip">📌 {esc(r.profile)}</span>' if r.profile else "",
                '<span class="chip">🔐 own records only</span>' if r.scope else "",
            ) if b)
        return (
            f'<a class="card agent" href="/admin/agents/view?name={esc(name)}">'
            f'<div class="who">{avatar(name)}<div><b>{esc(name)}</b>'
            f'<small>{esc(r.note) if has_rule and r.note else activity}</small></div></div>'
            f'<p>{badges}</p><div class="sum">{(summaries or {}).get(name, "")}</div>'
            '<span class="open">Open ›</span></a>'
        )

    pins = sorted({r.profile for r in rules.values() if r.profile})
    tab = (selected or "").strip()
    tabs = "" if not pins else (
        '<div class="tabs">'
        f'<a href="/admin/agents"{" class=on" if not tab else ""}>🤖 All</a>'
        + "".join(f'<a href="/admin/agents?tab={esc(p)}"{" class=on" if tab == p else ""}>'
                  f"📌 {esc(p)}</a>" for p in pins)
        + f'<a href="/admin/agents?tab=-"{" class=on" if tab == "-" else ""}>🌐 not pinned</a>'
        "</div>"
    )
    everyone = dict(rules)
    for name in sorted(set(seen or {}) | {t["actor"] for t in tokens}):
        everyone.setdefault(name, AgentRule(name=name))
    retired = archived or {}
    for name in retired:
        everyone.pop(name, None)
    shown_rules = {n: r for n, r in everyone.items()
                   if not tab or (tab == "-" and not r.profile) or r.profile == tab}
    rows = tabs + (
        '<div class="cards">' + "".join(card(n, r) for n, r in sorted(shown_rules.items()))
        + "</div>" if shown_rules
        else "<p>No agent rules here yet: these agents follow the server policy.</p>"
    )
    if retired:
        rows += (
            f'<details class="archived"><summary>🗄️ Archived agents ({len(retired)})</summary>'
            '<p><small>Tokens revoked and agent blocked; the audit log keeps their history. '
            "Restoring unblocks it — it then needs a new token.</small></p><ul>"
            + "".join(
                f'<li><code>{esc(n)}</code> <small>archived {esc(ts[:10])}</small> '
                f'<form method="post" action="/admin/agents/archive" class="inline">'
                f'{csrf_field(csrf)}<input type="hidden" name="name" value="{esc(n)}">'
                '<button class="ghost" name="action" value="restore" type="submit">↺ Restore'
                "</button></form></li>" for n, ts in sorted(retired.items()))
            + "</ul></details>"
        )

    def token_row(t: dict) -> str:
        state = (f'<span class="chip bad">revoked {esc(t["revoked_at"][:10])}</span>'
                 if t.get("revoked_at") else '<span class="chip ok">active</span>')
        action = "" if t.get("revoked_at") else (
            '<form method="post" action="/admin/agents/revoke" class="inline">'
            f'{csrf_field(csrf)}<input type="hidden" name="jti" value="{esc(t["jti"])}">'
            '<button class="danger" type="submit">Revoke</button></form>')
        variables = ", ".join(f"{esc(k)}={esc(v)}" for k, v in (t.get("vars") or {}).items())
        return (
            f'<tr><td><code>{esc(t["actor"])}</code></td><td>{esc(t.get("label") or "")}</td>'
            f'<td class="mono">{esc(t["jti"][:8])}…</td><td>{esc(t.get("profile") or "—")}</td>'
            f'<td>{variables or "—"}</td>'
            f'<td class="mono">{esc(t["issued_at"][:16].replace("T", " "))}</td>'
            f'<td class="mono">{esc(t["expires_at"][:16].replace("T", " "))}</td>'
            f"<td>{state}</td><td>{action}</td></tr>"
        )

    token_rows = "".join(token_row(t) for t in tokens) or (
        "<tr><td colspan=9>No registered tokens.</td></tr>")
    e = edit if edit is not None or not new_name else AgentRule(name=new_name)
    registered = (
        "Unregistered tokens are refused (REQUIRE_REGISTERED_TOKENS=true)."
        if require_registered else
        "Tokens issued before the registry still work; set REQUIRE_REGISTERED_TOKENS=true "
        "once every agent has a registered token, or revoke them from the agent's page."
    )
    form = rule_form(csrf=csrf, e=e, profiles=profiles, tools=tools)
    known = sorted(everyone)
    revoke_options = "".join(f'<option value="{esc(n)}">{esc(n)}</option>' for n in known)
    body = (
        message(flash, flash_kind) + shown
        + '<section><div class="spread"><h2>Your agents</h2>'
        '<a class="button" href="/admin/agents?new=1#new">＋ New agent</a></div>'
        "<p><small>Open an agent to see — and change — what it can really do. A rule only "
        "takes away: it can never reach what the server policy denies.</small></p>"
        f"{rows}</section>"
        f'<details class="card-like" id="new"{" open" if open_form else ""}><summary><b>'
        + (f"✎ Edit the rule of {esc(e.name)}" if e is not None and e.name in rules
           else "＋ New agent rule")
        + f"</b></summary>{form}</details>"
        '<details class="card-like"><summary><b>🔑 Issue a token</b></summary>'
        f'<form method="post" action="/admin/agents/token">{csrf_field(csrf)}'
        '<div class=row><div><label>Agent name</label>'
        f'<input type="text" name="name" value="{esc(e.name if e else "")}" list="known-agents" '
        'pattern="[A-Za-z0-9_.@\\-]{1,64}" required></div><div><label>Label</label>'
        '<input type="text" name="label" placeholder="e.g. laptop, n8n, customer 42"></div>'
        '<div><label>Hours (empty = default)</label><input type="number" name="hours" min="1">'
        '</div></div><label>Variables for the scope (name=value, comma-separated)</label>'
        '<input type="text" name="vars" placeholder="partner=42">'
        '<p><button type="submit">Issue token</button></p></form></details>'
        '<datalist id="known-agents">'
        + "".join(f'<option value="{esc(n)}">' for n in known) + "</datalist>"
        f'<details class="card-like"><summary><b>🗂️ All tokens ({len(tokens)})</b></summary>'
        f'<p><small>{esc(registered)}</small></p>'
        '<div class="wrap"><table><tr><th>Agent</th><th>Label</th><th>Id</th><th>Profile</th>'
        "<th>Variables</th><th>Issued (UTC)</th><th>Expires</th><th>State</th><th></th></tr>"
        f"{token_rows}</table></div>"
        f'<form method="post" action="/admin/agents/revoke">{csrf_field(csrf)}'
        '<div class=row><div><label>Revoke every token of agent (registered or not)</label>'
        f'<select name="name" required>{revoke_options}</select></div></div>'
        '<p><label class="inline"><input type="checkbox" name="confirm" value="yes" required>'
        ' confirm</label> <button class="danger" type="submit">Revoke all</button></p></form>'
        "</details>"
    )
    return page("Agents", body)


def rule_form(*, csrf: str, e: Any, profiles: list[str], tools: list[str]) -> str:
    """The full rule of one agent: models, tools, quota, profile, scope."""
    tool_boxes = "".join(
        f'<label class="inline"><input type="checkbox" name="tools" value="{esc(t)}"'
        f'{" checked" if e and t in e.tools else ""}> {esc(t)}</label> ' for t in tools)
    profile_options = '<option value="">token or active profile</option>' + "".join(
        f'<option value="{esc(p)}"{" selected" if e and e.profile == p else ""}>{esc(p)}</option>'
        for p in profiles)
    scope_json = json.dumps({m: list(d) for m, d in e.scope.items()}, indent=1) if e else ""
    existing = bool(e and e.name)
    return (
        f'<form method="post" action="/admin/agents/save">{csrf_field(csrf)}'
        '<div class=row><div><label>Agent name (token subject)</label>'
        f'<input type="text" name="name" value="{esc(e.name if e else "")}" '
        'pattern="[A-Za-z0-9_.@\\-]{1,64}" required></div>'
        '<div><label>Note</label>'
        f'<input type="text" name="note" value="{esc(e.note if e else "")}"></div></div>'
        '<label>Models (comma-separated; empty = policy)</label>'
        f'<input type="text" name="models" value="{esc(", ".join(sorted(e.models)) if e else "")}">'
        f"<label>Tools (none ticked = all)</label><div>{tool_boxes}</div>"
        '<div class=row><div><label>Calls per day (0 = no quota)</label>'
        f'<input type="number" name="daily_quota" min="0" value="{esc(e.daily_quota if e else 0)}">'
        f'</div><div><label>Pinned profile</label><select name="profile">{profile_options}'
        "</select></div></div>"
        '<label class="inline"><input type="checkbox" name="read_only" value="yes"'
        f'{" checked" if e and e.read_only else ""}> Read-only</label>'
        "<label>Record scope (JSON: model → domain). "
        '<small>Example for a WhatsApp bot: {"res.partner": [["id", "=", "{partner}"]], '
        '"sale.order": [["partner_id", "=", "{partner}"]]} — "{partner}" comes from the '
        "token’s variables. A scoped agent reaches only these models.</small></label>"
        f'<textarea name="scope" class="mono" rows="5">{esc(scope_json)}</textarea>'
        '<p><button type="submit">Save rule</button></p></form>'
        + (
            '<form method="post" action="/admin/agents/delete" class="inline">'
            f'{csrf_field(csrf)}<input type="hidden" name="name" value="{esc(e.name)}">'
            '<label class="inline"><input type="checkbox" name="confirm" value="yes" required>'
            ' confirm</label> <button class="danger" type="submit">Delete rule</button></form>'
            if existing else ""
        )
    )

