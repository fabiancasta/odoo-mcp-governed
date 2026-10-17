"""Sandbox profiles and the visual permissions table.

A sandbox profile is for test databases and controlled activities: model
lists and the execute_method allowlist stop applying, and risk is observed
but never throttles or blocks. The safety floor stays — denylist, credential
fields, attachment content, the panic switch, blocked agents and the audit
log — because a sandbox database is usually a copy of production and holds
the same secrets. Production profiles can never be sandboxes.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from odoo_mcp_governed.governance import (
    Decision,
    DetectorConfig,
    GovernanceEngine,
    Operation,
    PolicyConfig,
    PolicyEngine,
    RiskConfig,
)
from odoo_mcp_governed.profiles import Profile, ProfileError
from odoo_mcp_governed.runtime import Runtime, Snapshot
from odoo_mcp_governed.web.app import create_app

from .conftest import FakeClock, make_call
from .test_http import login, make_settings
from .test_tools import FakeOdoo

SANDBOX = PolicyConfig(sandbox_profiles=frozenset({"lab"}))


class TestSandboxPolicy:
    def test_model_lists_do_not_apply(self, clock: FakeClock) -> None:
        engine = PolicyEngine(SANDBOX)
        for op in (Operation.READ, Operation.WRITE, Operation.DELETE):
            assert engine.evaluate(make_call(clock, operation=op, profile="lab")).allowed, op
        assert not engine.evaluate(make_call(clock, profile="other")).allowed

    def test_execute_method_is_open_except_the_blocked_methods(self, clock: FakeClock) -> None:
        engine = PolicyEngine(SANDBOX)
        assert engine.evaluate(make_call(clock, operation=Operation.EXECUTE,
                                         method="action_post", profile="lab")).allowed
        assert not engine.evaluate(make_call(clock, operation=Operation.EXECUTE,
                                             method="unlink", profile="lab")).allowed

    @pytest.mark.parametrize("call_kwargs, code", [
        ({"model": "ir.cron"}, "model_denied"),
        ({"fields": ("password",)}, "sensitive_field"),
        ({"model": "ir.attachment", "fields": ("datas",)}, "attachment_content"),
    ])
    def test_the_floor_stays(self, clock: FakeClock, call_kwargs, code) -> None:
        verdict = PolicyEngine(SANDBOX).evaluate(make_call(clock, profile="lab", **call_kwargs))
        assert code in verdict.codes

    def test_panic_and_blocked_agents_still_win(self, clock: FakeClock) -> None:
        engine = PolicyEngine(replace(SANDBOX, panic=True))
        assert engine.evaluate(make_call(clock, profile="lab")).codes == ("panic_stop",)
        engine = PolicyEngine(replace(SANDBOX, blocked_actors=frozenset({"agent-a"})))
        assert engine.evaluate(make_call(clock, profile="lab")).codes == ("actor_blocked",)

    def test_risk_is_observed_but_never_enforced(self, audit, clock: FakeClock) -> None:
        engine = GovernanceEngine(
            audit=audit, policy=PolicyEngine(SANDBOX),
            detector_config=DetectorConfig(business_timezone="UTC"),
            risk_config=RiskConfig(throttle_seconds=0), now_fn=clock,
        )
        decisions = []
        for _ in range(8):
            call = make_call(clock, tool="delete_record", operation=Operation.DELETE,
                             model="res.partner", profile="lab")
            with engine.guard(call) as g:
                g.affected(1)
            decisions.append(engine.audit.tail(1)[0].decision)
            clock.advance(seconds=2)
        assert Decision.DENY not in decisions and Decision.THROTTLE not in decisions
        assert Decision.ALLOW_FLAGGED in decisions
        assert any("sandbox" in r for r in engine.audit.tail(1)[0].reasons)


class TestSandboxProfiles:
    def test_production_can_never_be_a_sandbox(self) -> None:
        with pytest.raises(ProfileError, match="sandbox"):
            Profile(name="p", url="http://x", database="d", username="u", api_key="k",
                    environment="production", sandbox=True).validate()

    def test_runtime_derives_sandbox_profiles(self, tmp_path) -> None:
        runtime = Runtime(make_settings(tmp_path, odoo_environment="development"))
        runtime.save_profile(replace(runtime.profiles.active(), sandbox=True), actor="admin")
        assert "default" in runtime.engine.policy.config.sandbox_profiles
        runtime.save_profile(replace(runtime.profiles.active(), sandbox=False), actor="admin")
        assert "default" not in runtime.engine.policy.config.sandbox_profiles


MODELS = [
    {"model": "res.partner", "name": "Contact", "transient": False},
    {"model": "product.template", "name": "Product", "transient": False},
    {"model": "pos.order", "name": "Point of Sale Orders", "transient": False},
    {"model": "ir.cron", "name": "Scheduled Actions", "transient": False},
    {"model": "pos.make.invoice", "name": "Wizard", "transient": True},
]


@pytest.fixture
def panel(tmp_path):
    runtime = Runtime(make_settings(tmp_path, odoo_environment="development",
                                    allowed_models="res.partner"))
    fake = FakeOdoo()
    fake.responses[("ir.model", "search_read")] = MODELS
    runtime._snapshot = Snapshot(runtime.profiles.active(), fake)
    client = TestClient(create_app(runtime))
    return runtime, client, login(client)


class TestPermissionsTable:
    def test_models_are_grouped_by_app_with_the_denylist_locked(self, panel) -> None:
        _, client, _ = panel
        page = client.get("/admin/permissions").text
        assert "Point of Sale" in page and "Products" in page
        assert "pos.make.invoice" not in page, "wizards are hidden"
        assert "ir.cron" in page and "always blocked" in page
        assert "new — not reviewed" in page

    def test_saving_writes_explicit_lists_and_implies_read(self, panel) -> None:
        runtime, client, csrf = panel
        client.post("/admin/permissions", data={
            "csrf": csrf, "shown": ["res.partner", "product.template", "pos.order"],
            "r": ["res.partner"], "w": ["pos.order"], "d": [],
        }, follow_redirects=False)
        cfg = runtime.engine.policy.config
        assert cfg.allowed_models == frozenset({"res.partner", "pos.order"})
        assert cfg.writable_models == frozenset({"pos.order"})
        assert any(e.tool == "admin.policy.update" for e in runtime.audit.store.iter_all())
        assert "new — not reviewed" not in client.get("/admin/permissions").text

    def test_a_filtered_save_leaves_unseen_models_alone(self, panel) -> None:
        runtime, client, csrf = panel
        client.post("/admin/permissions", data={
            "csrf": csrf, "shown": ["pos.order"], "r": ["pos.order"],
        }, follow_redirects=False)
        assert runtime.engine.policy.config.allowed_models == frozenset(
            {"res.partner", "pos.order"})

    def test_whole_app_and_allow_all_switches(self, panel) -> None:
        runtime, client, csrf = panel
        client.post("/admin/permissions", data={
            "csrf": csrf, "shown": ["res.partner", "product.template", "pos.order"],
            "app_r": ["pos"], "all_w": "1",
        }, follow_redirects=False)
        cfg = runtime.engine.policy.config
        assert "pos.order" in cfg.allowed_models
        assert cfg.writable_models == frozenset({"*"})
