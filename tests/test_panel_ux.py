"""The panel as a place to work, not only to read.

- Every dashboard number links to the audit log filtered to the events
  behind it, and the filter reproduces the number.
- The dashboard is split in tabs; each Odoo is a card.
- Agents seen in the audit log are listed even without a rule, and each
  agent opens as a tree of what it can really do on each profile.
"""

from __future__ import annotations

import os
import re
import stat

from fastapi.testclient import TestClient

from odoo_mcp_governed.__main__ import main as cli
from odoo_mcp_governed.governance import Decision, Operation, Outcome, ToolCall
from odoo_mcp_governed.governance.agents import AgentRule
from odoo_mcp_governed.profiles import Profile
from odoo_mcp_governed.runtime import Runtime
from odoo_mcp_governed.web.agent_tree import effective, narrow
from odoo_mcp_governed.web.app import create_app

from .test_http import ADMIN, login, make_settings


def seed(runtime: Runtime) -> None:
    """Three allowed, two refused (one by denylist), one flagged — for 'claude'."""
    def rec(decision, outcome, model="res.partner", reasons=()):
        runtime.audit.record(
            ToolCall(actor="claude", profile="default", tool="search_records",
                     operation=Operation.READ, model=model),
            decision=decision, outcome=outcome, reasons=reasons)
    for _ in range(3):
        rec(Decision.ALLOW, Outcome.OK)
    rec(Decision.DENY, Outcome.DENIED, "res.users.apikeys", ("model_denied: no",))
    rec(Decision.DENY, Outcome.DENIED, "sale.order", ("model_not_allowed: no",))
    rec(Decision.ALLOW_FLAGGED, Outcome.OK)


def rows(html: str) -> int:
    return len(re.findall(r'<tr[^>]*><td class="mono">\d+</td>', html))


def app(tmp_path):
    runtime = Runtime(make_settings(tmp_path))
    seed(runtime)
    client = TestClient(create_app(runtime))
    return runtime, client, login(client)


class TestDrillDown:
    def test_every_number_links_to_its_events(self, tmp_path) -> None:
        _, client, _ = app(tmp_path)
        live = client.get("/admin/live").text
        for href in ("decision=deny", "decision=flagged", "kind=denylist",
                     "model=res.partner"):
            assert href in live, href

    def test_the_filters_reproduce_the_numbers(self, tmp_path) -> None:
        _, client, _ = app(tmp_path)
        base = "/admin/logs?agents=1&hours=24"
        assert rows(client.get(base).text) == 6
        assert rows(client.get(base + "&decision=deny").text) == 2
        assert rows(client.get(base + "&decision=flagged").text) == 1
        assert rows(client.get(base + "&decision=deny&kind=denylist").text) == 1
        assert rows(client.get(base + "&model=sale.order").text) == 1
        page = client.get(base + "&decision=deny&kind=denylist").text
        assert "refusal kind: denylist" in page and "clear filters" in page

    def test_panel_actions_are_not_agent_calls(self, tmp_path) -> None:
        runtime, client, _ = app(tmp_path)  # the login itself is an admin event
        assert rows(client.get("/admin/logs?agents=1").text) == 6
        assert rows(client.get("/admin/logs").text) > 6

    def test_bad_filter_values_are_ignored(self, tmp_path) -> None:
        _, client, _ = app(tmp_path)
        assert client.get("/admin/logs?hour=nonsense&kind=x&model=<b>").status_code == 200


class TestDashboardTabs:
    def test_tabs_and_profile_cards(self, tmp_path) -> None:
        runtime, client, _ = app(tmp_path)
        page = client.get("/admin").text
        assert "<h1>Dashboard</h1>" in page and 'id="pane-profiles" hidden' in page
        # One sidebar on every page, with this page marked.
        assert 'class=on aria-current=page><span class="ico">📊' in page
        page = client.get("/admin?tab=profiles").text
        assert 'id="pane-summary" hidden' in page and "Your Odoo instances" in page
        assert "<h1>Odoo instances</h1>" in page
        assert "/admin/permissions?profile=default" in page

    def test_editing_a_profile_opens_its_tab(self, tmp_path) -> None:
        _, client, _ = app(tmp_path)
        page = client.get("/admin?edit=default").text
        assert 'id="pane-summary" hidden' in page

    def test_agent_names_open_their_tree(self, tmp_path) -> None:
        _, client, _ = app(tmp_path)
        assert "/admin/agents/view?name=claude" in client.get("/admin").text


class TestDetectedAgents:
    def test_an_agent_without_a_rule_is_listed(self, tmp_path) -> None:
        _, client, _ = app(tmp_path)
        page = client.get("/admin/agents").text
        assert "claude" in page and "follows the server policy" in page
        assert "6 calls in 24 h" in page

    def test_create_rule_prefills_the_name(self, tmp_path) -> None:
        _, client, _ = app(tmp_path)
        assert 'name="name" value="claude"' in client.get("/admin/agents?edit=claude").text


class TestTree:
    def test_the_tree_shows_effective_permissions(self, tmp_path) -> None:
        runtime, client, _ = app(tmp_path)
        page = client.get("/admin/agents/view?name=claude").text
        assert "What this agent can do" in page and "res.partner" in page
        assert 'class="roster"' in page  # the hub: every agent on the left
        assert "not registered" in page  # it calls with a token from before the registry

    def test_quick_rule_from_the_tree(self, tmp_path) -> None:
        runtime, client, csrf = app(tmp_path)
        response = client.post("/admin/agents/quick", data={
            "csrf": csrf, "name": "claude", "read_only": "yes", "daily_quota": "40",
            "profile": ""}, follow_redirects=False)
        assert response.headers["location"].startswith("/admin/agents/view?name=claude")
        rule = runtime.agents.rule("claude")
        assert rule.read_only and rule.daily_quota == 40

    def test_plus_on_a_profile_gate_returns_to_the_tree(self, tmp_path) -> None:
        runtime, client, csrf = app(tmp_path)
        response = client.post("/admin/permissions/chip", data={
            "csrf": csrf, "profile": "", "gate": "r", "model": "sale.order", "action": "add",
            "back": "/admin/agents/view?name=claude"}, follow_redirects=False)
        assert response.headers["location"].startswith("/admin/agents/view?name=claude")
        assert "sale.order" in runtime.engine.policy.config.allowed_models

    def test_back_cannot_leave_the_panel(self, tmp_path) -> None:
        _, client, csrf = app(tmp_path)
        response = client.post("/admin/permissions/chip", data={
            "csrf": csrf, "gate": "r", "model": "sale.order", "action": "add",
            "back": "https://evil.example/"}, follow_redirects=False)
        assert response.headers["location"].startswith("/admin/permissions")

    def test_tool_limit_from_the_tree(self, tmp_path) -> None:
        runtime, client, csrf = app(tmp_path)
        client.post("/admin/agents/model", data={"csrf": csrf, "name": "claude",
                                                 "kind": "tool", "model": "search_records",
                                                 "action": "add"})
        assert runtime.agents.rule("claude").tools == {"search_records"}
        client.post("/admin/agents/model", data={"csrf": csrf, "name": "claude",
                                                 "kind": "tool", "model": "rm -rf",
                                                 "action": "add"})
        assert runtime.agents.rule("claude").tools == {"search_records"}


class TestEffective:
    def test_narrow(self) -> None:
        assert narrow({"*"}, {"a.b"}) == {"a.b"}
        assert narrow({"a.b", "c.d"}, {"*"}) == {"a.b", "c.d"}
        assert narrow({"a.b"}, {"c.d"}) == set()

    def test_rule_and_environment_narrow(self, tmp_path) -> None:
        runtime = Runtime(make_settings(tmp_path, writable_models="res.partner",
                                        odoo_environment="development"))
        runtime.save_profile(Profile(name="prod", url="http://p.invalid", database="p",
                                     username="u", api_key="k", environment="production"),
                             actor="a")
        cfg, ro = runtime.engine.policy.config, runtime.profiles.read_only_names()
        assert effective(cfg, None, "default", ro)["write"] == {"res.partner"}
        assert effective(cfg, None, "prod", ro)["write"] == set()  # production, writes off
        rule = AgentRule(name="x", read_only=True)
        assert effective(cfg, rule, "default", ro)["write"] == set()
        pinned = AgentRule(name="x", profile="prod")
        assert not effective(cfg, pinned, "default", ro)["reachable"]


def test_totp_setup_writes_a_private_file(tmp_path, monkeypatch, capsys) -> None:
    for key, value in {"DATA_DIR": str(tmp_path), "JWT_SECRET": "x" * 48,
                       "ADMIN_PASSWORD": ADMIN}.items():
        monkeypatch.setenv(key, value)
    assert cli(["totp-setup"]) == 0
    target = tmp_path / "totp-setup.txt"
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    secret = target.read_text().splitlines()[0].split("=", 1)[1]
    assert secret not in capsys.readouterr().out


class TestHub:
    def test_login_lands_on_agents(self, tmp_path) -> None:
        runtime = Runtime(make_settings(tmp_path))
        client = TestClient(create_app(runtime))
        response = client.post("/admin", data={"password": ADMIN}, follow_redirects=False)
        assert response.headers["location"] == "/admin/agents"

    def test_every_page_has_the_same_sidebar(self, tmp_path) -> None:
        _, client, _ = app(tmp_path)
        for path, active in (("/admin/agents", "🤖"), ("/admin", "📊"),
                             ("/admin/approvals", "✋"), ("/admin/logs", "📜"),
                             ("/admin/changes", "↩️"), ("/admin/permissions", "🔑"),
                             ("/admin?tab=profiles", "🗄️"), ("/admin?tab=policy", "🛡️"),
                             ("/token", "🔐"), ("/admin/agents/view?name=claude", "🤖")):
            page = client.get(path).text
            assert 'class="side"' in page, path
            assert f'aria-current=page><span class="ico">{active}' in page, path

    def test_issuing_from_the_tree_shows_the_token_there(self, tmp_path) -> None:
        runtime, client, csrf = app(tmp_path)
        page = client.post("/admin/agents/token", data={
            "csrf": csrf, "name": "claude", "label": "laptop", "from_tree": "1"}).text
        assert "shown only once" in page and 'class="roster"' in page

    def test_revoke_only_unregistered_tokens(self, tmp_path) -> None:
        from odoo_mcp_governed.web.auth import issue_token
        runtime, client, csrf = app(tmp_path)
        old = issue_token(runtime.settings, "claude")["token"]
        import time
        time.sleep(1.1)
        client.post("/admin/agents/revoke", data={"csrf": csrf, "name": "claude",
                                                  "kind": "unregistered"})
        time.sleep(1.1)
        new = runtime.issue_agent_token("claude", actor="admin")["token"]

        def status(token):
            return client.post("/mcp", headers={"Authorization": f"Bearer {token}"},
                               json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
                               ).status_code
        assert status(old) == 401 and status(new) == 200

    def test_revoke_all_offers_known_agents_only(self, tmp_path) -> None:
        _, client, _ = app(tmp_path)
        page = client.get("/admin/agents").text
        assert '<select name="name" required><option value="claude">' in page


class FakeModels:
    MODELS = [{"model": m, "name": m, "transient": False} for m in (
        "sale.order", "sale.order.line", "res.partner", "res.users", "ir.cron")]


def perm_app(tmp_path):
    runtime, client, csrf = app(tmp_path)
    runtime.cache.get_or_set(("default", "permissions", "ir.model"), lambda: FakeModels.MODELS)
    return runtime, client, csrf


class TestPermissionsByApp:
    def test_apps_with_one_level_each(self, tmp_path) -> None:
        _, client, _ = perm_app(tmp_path)
        page = client.get("/admin/permissions").text
        assert 'id="app-sale"' in page and 'name="level" value="write"' in page
        assert "Odoo system models" in page  # res.users and ir.cron, folded apart
        assert 'id="perm-filter"' in page

    def test_one_click_sets_every_model_of_the_app(self, tmp_path) -> None:
        runtime, client, csrf = perm_app(tmp_path)
        response = client.post("/admin/permissions/app", data={
            "csrf": csrf, "app": "sale", "level": "write"}, follow_redirects=False)
        assert response.headers["location"].endswith("#app-sale")
        cfg = runtime.engine.policy.config
        assert {"sale.order", "sale.order.line"} <= cfg.writable_models
        assert {"sale.order", "sale.order.line"} <= cfg.allowed_models
        client.post("/admin/permissions/app", data={"csrf": csrf, "app": "sale",
                                                    "level": "none"})
        cfg = runtime.engine.policy.config
        assert not {"sale.order", "sale.order.line"} & (cfg.allowed_models | cfg.writable_models)

    def test_an_app_level_never_reaches_system_models(self, tmp_path) -> None:
        runtime, client, csrf = perm_app(tmp_path)
        client.post("/admin/permissions/app", data={"csrf": csrf, "app": "res",
                                                    "level": "delete"})
        cfg = runtime.engine.policy.config
        assert "res.partner" in cfg.deletable_models and "res.users" not in cfg.allowed_models

    def test_fine_tune_one_selector_per_model(self, tmp_path) -> None:
        runtime, client, csrf = perm_app(tmp_path)
        client.post("/admin/permissions/models", data={
            "csrf": csrf, "app": "sale", "lvl:sale.order": "delete",
            "lvl:sale.order.line": "read", "lvl:ir.cron": "write"})
        cfg = runtime.engine.policy.config
        assert "sale.order" in cfg.deletable_models
        assert "sale.order.line" in cfg.allowed_models
        assert "sale.order.line" not in cfg.writable_models
        assert "ir.cron" not in cfg.allowed_models  # on the denylist: ignored

    def test_on_a_profile_it_gives_the_profile_its_own_lists(self, tmp_path) -> None:
        runtime, client, csrf = perm_app(tmp_path)
        runtime.save_profile(Profile(name="co", url="http://co.invalid", database="co",
                                     username="u", api_key="k", environment="development"),
                             actor="a")
        runtime.cache.get_or_set(("co", "permissions", "ir.model"), lambda: FakeModels.MODELS)
        client.post("/admin/permissions/app", data={"csrf": csrf, "profile": "co",
                                                    "app": "sale", "level": "read"})
        cfg = runtime.engine.policy.config
        assert "sale.order" in cfg.profile_lists["co"]["allowed_models"]
        assert "sale.order" not in cfg.allowed_models


class TestArchive:
    def test_archive_hides_revokes_and_blocks(self, tmp_path) -> None:
        runtime, client, csrf = app(tmp_path)
        token = runtime.issue_agent_token("claude", actor="a")["token"]
        client.post("/admin/agents/archive", data={"csrf": csrf, "name": "claude",
                                                   "action": "archive", "confirm": "yes"})
        assert "claude" in runtime.engine.policy.config.blocked_actors
        assert client.post("/mcp", headers={"Authorization": f"Bearer {token}"},
                           json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
                           ).status_code == 401
        page = client.get("/admin/agents").text
        assert "Archived agents (1)" in page
        assert 'href="/admin/agents/view?name=claude"' not in page.split("Archived agents")[0]

    def test_restore_unblocks(self, tmp_path) -> None:
        runtime, client, csrf = app(tmp_path)
        runtime.archive_agent("claude", actor="a")
        client.post("/admin/agents/archive", data={"csrf": csrf, "name": "claude",
                                                   "action": "restore"})
        assert "claude" not in runtime.engine.policy.config.blocked_actors
        assert "claude" not in runtime.agents.archived()

    def test_delete_removes_the_rule_but_not_the_history(self, tmp_path) -> None:
        runtime, client, csrf = app(tmp_path)
        runtime.save_agent(AgentRule(name="claude", read_only=True), actor="a")
        before = runtime.audit.store.count_for_actor("claude")
        client.post("/admin/agents/archive", data={"csrf": csrf, "name": "claude",
                                                   "action": "delete", "confirm": "yes"})
        assert runtime.agents.rule("claude") is None
        assert runtime.audit.store.count_for_actor("claude") == before
        assert runtime.audit.verify().intact

    def test_archive_needs_confirmation(self, tmp_path) -> None:
        runtime, client, csrf = app(tmp_path)
        client.post("/admin/agents/archive", data={"csrf": csrf, "name": "claude",
                                                   "action": "archive"})
        assert "claude" not in runtime.agents.archived()
