"""Phase 1: access levels, system models out of ``*``, attachments by owner.

Three levels, chosen per profile:

- business (default): ``*`` means every *business* model — never Odoo's
  system models (``ir.*``, users, groups, settings, modules, payment
  providers…). A system model is reachable only by naming it exactly, and the
  hard denylist never.
- sandbox: business models without lists, risk observed only.
- configurator: the whole system, for a consulting agent setting Odoo up —
  modules, settings, users, views, automations — on a non-production profile
  only. Secrets stay hidden and installing modules or adding code waits for a
  human.

``ir.attachment`` is never reachable through the generic tools: files are
listed per record with list_attachments and fetched with get_attachment, both
checked against the record they belong to — and never when the file is a
certificate or key.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from odoo_mcp_governed.config import Settings
from odoo_mcp_governed.governance import Operation, PolicyConfig, PolicyEngine
from odoo_mcp_governed.governance.policy import is_system_model
from odoo_mcp_governed.profiles import Profile, ProfileError
from odoo_mcp_governed.protocol import Dispatcher
from odoo_mcp_governed.runtime import Runtime, Snapshot

from .conftest import FakeClock, make_call
from .test_tools import FakeOdoo, call

WIDE = PolicyConfig(allowed_models=frozenset({"*"}), writable_models=frozenset({"*"}),
                    deletable_models=frozenset({"*"}), allow_execute_method=True)


class TestSystemModels:
    @pytest.mark.parametrize("model", [
        "ir.ui.view", "ir.model", "ir.actions.act_window", "res.users", "res.users.log",
        "res.groups", "res.config.settings", "base.language.install", "payment.provider",
        "iap.account", "bus.bus", "res.lang",
    ])
    def test_are_system(self, model) -> None:
        assert is_system_model(model)

    @pytest.mark.parametrize("model", [
        "res.partner", "product.template", "sale.order", "account.move", "stock.picking",
        "pos.order", "res.company", "res.country", "res.currency", "mail.activity",
    ])
    def test_business_models_are_not(self, model) -> None:
        assert not is_system_model(model)

    def test_wildcard_does_not_reach_system_models(self, clock: FakeClock) -> None:
        verdict = PolicyEngine(WIDE).evaluate(make_call(clock, model="res.users"))
        assert "system_model" in verdict.codes
        assert PolicyEngine(WIDE).evaluate(make_call(clock, model="res.partner")).allowed

    def test_naming_a_system_model_exactly_lets_it_in(self, clock: FakeClock) -> None:
        config = replace(WIDE, allowed_models=frozenset({"*", "res.users"}))
        assert PolicyEngine(config).evaluate(make_call(clock, model="res.users")).allowed

    def test_naming_does_not_lift_the_hard_denylist(self, clock: FakeClock) -> None:
        config = replace(WIDE, allowed_models=frozenset({"*", "ir.config_parameter"}))
        verdict = PolicyEngine(config).evaluate(make_call(clock, model="ir.config_parameter"))
        assert "model_denied" in verdict.codes

    def test_sandbox_does_not_reach_system_models_either(self, clock: FakeClock) -> None:
        config = replace(WIDE, sandbox_profiles=frozenset({"lab"}))
        verdict = PolicyEngine(config).evaluate(make_call(clock, model="res.users",
                                                          profile="lab"))
        assert "system_model" in verdict.codes


class TestConfigurator:
    def config(self) -> PolicyConfig:
        return replace(WIDE, configurator_profiles=frozenset({"dev"}))

    @pytest.mark.parametrize("model, operation, method", [
        ("res.config.settings", Operation.EXECUTE, "execute"),
        ("res.users", Operation.WRITE, None),
        ("res.groups", Operation.CREATE, None),
        ("ir.ui.view", Operation.WRITE, None),
        ("ir.cron", Operation.CREATE, None),
        ("base.automation", Operation.CREATE, None),
        ("ir.config_parameter", Operation.WRITE, None),
    ])
    def test_reaches_the_whole_system(self, clock, model, operation, method) -> None:
        call_ = make_call(clock, model=model, operation=operation, method=method,
                          profile="dev")
        assert PolicyEngine(self.config()).evaluate(call_).allowed, model

    def test_still_never_reads_api_keys_attachments_or_secret_fields(self, clock) -> None:
        engine = PolicyEngine(self.config())
        assert "model_denied" in engine.evaluate(
            make_call(clock, model="res.users.apikeys", profile="dev")).codes
        assert "model_denied" in engine.evaluate(
            make_call(clock, model="ir.attachment", profile="dev")).codes
        assert "sensitive_field" in engine.evaluate(
            make_call(clock, model="res.users", fields=("password",), profile="dev")).codes

    def test_other_profiles_are_unaffected(self, clock) -> None:
        verdict = PolicyEngine(self.config()).evaluate(make_call(clock, model="res.users",
                                                                 profile="prod"))
        assert "system_model" in verdict.codes

    def test_production_can_never_be_a_configurator(self) -> None:
        with pytest.raises(ProfileError, match="configurator"):
            Profile(name="p", url="http://x", database="d", username="u", api_key="k",
                    environment="production", configurator=True).validate()

    def test_a_profile_is_one_level_only(self) -> None:
        with pytest.raises(ProfileError, match="one"):
            Profile(name="p", url="http://x", database="d", username="u", api_key="k",
                    environment="development", sandbox=True, configurator=True).validate()


@pytest.fixture
def server(tmp_path):
    def build(*, configurator: bool = False, **extra):
        runtime = Runtime(Settings(
            _env_file=None, data_dir=tmp_path, odoo_url="http://fake.invalid", odoo_db="d",
            odoo_username="u", odoo_api_key="k", allowed_models="*", writable_models="*",
            deletable_models="*", allow_execute_method=True, business_timezone="UTC",
            business_hours="00:00-23:59", business_days="mon,tue,wed,thu,fri,sat,sun",
            risk_throttle_seconds=0, odoo_environment="development", **extra,
        ))
        if configurator:
            runtime.save_profile(replace(runtime.profiles.active(), configurator=True),
                                 actor="admin")
        fake = FakeOdoo()
        runtime._snapshot = Snapshot(runtime.profiles.active(), fake)
        return runtime, fake, Dispatcher(runtime)
    return build


class TestConfiguratorAtTheServer:
    def test_config_parameter_values_that_look_secret_are_hidden(self, server) -> None:
        _, fake, d = server(configurator=True)
        fake.responses[("ir.config_parameter", "search_read")] = [
            {"id": 1, "key": "web.base.url", "value": "https://erp.example.com"},
            {"id": 2, "key": "database.secret", "value": "s3cr3t"},
            {"id": 3, "key": "unsplash.access_key", "value": "abc"},
        ]
        is_error, body = call(d, "search_records", model="ir.config_parameter")
        assert not is_error
        values = {r["key"]: r.get("value") for r in body["records"]}
        assert values["web.base.url"] == "https://erp.example.com"
        assert values["database.secret"] is None and values["unsplash.access_key"] is None

    def test_installing_a_module_waits_for_a_human(self, server) -> None:
        runtime, fake, d = server(configurator=True)
        is_error, body = call(d, "execute_method", model="ir.module.module",
                              method="button_immediate_install", args=[[7]])
        assert is_error and "approval" in body
        assert not any(m == "ir.module.module" for m, *_ in fake.calls)

    def test_adding_code_waits_for_a_human(self, server) -> None:
        _, fake, d = server(configurator=True)
        is_error, body = call(d, "create_record", model="ir.actions.server",
                              values={"name": "x", "state": "code", "code": "1"})
        assert is_error and "approval" in body

    def test_ordinary_configuration_goes_straight_through(self, server) -> None:
        _, fake, d = server(configurator=True)
        fake.responses[("res.groups", "create")] = 9
        assert not call(d, "create_record", model="res.groups", values={"name": "Ventas"})[0]


ATTACHMENTS = [
    {"id": 1, "name": "quote.pdf", "mimetype": "application/pdf", "file_size": 10,
     "res_model": "res.partner", "res_id": 3, "res_field": False},
]


class TestAttachmentsByOwner:
    def test_generic_tools_never_reach_ir_attachment(self, server) -> None:
        _, fake, d = server()
        is_error, body = call(d, "search_records", model="ir.attachment", fields=["name"])
        assert is_error and "list_attachments" in body
        assert not any(m == "ir.attachment" for m, *_ in fake.calls)

    def test_list_attachments_of_an_allowed_record(self, server) -> None:
        _, fake, d = server()
        fake.responses[("ir.attachment", "search_read")] = ATTACHMENTS
        is_error, body = call(d, "list_attachments", model="res.partner", record_id=3)
        assert not is_error and body["attachments"][0]["name"] == "quote.pdf"
        [(_, _, args, kwargs)] = [c for c in fake.calls if c[0] == "ir.attachment"]
        assert ["res_model", "=", "res.partner"] in args[0] and ["res_id", "=", 3] in args[0]
        assert "datas" not in kwargs["fields"]

    def test_list_attachments_of_a_denied_or_system_owner_is_refused(self, server) -> None:
        _, fake, d = server()
        assert call(d, "list_attachments", model="ir.cron", record_id=1)[0]
        assert call(d, "list_attachments", model="res.users", record_id=2)[0]
        assert not any(m == "ir.attachment" for m, *_ in fake.calls)

    @pytest.mark.parametrize("meta", [
        {"name": "firma.p12", "res_field": False},
        {"name": "x.bin", "res_field": "l10n_co_edi_certificate"},
        {"name": "x.bin", "res_field": "signing_key"},
        {"name": "server.pem", "res_field": False},
    ])
    def test_certificates_and_keys_are_never_downloaded(self, server, meta) -> None:
        _, fake, d = server()
        fake.responses[("ir.attachment", "read")] = [
            {"id": 5, "mimetype": "application/octet-stream", "file_size": 10,
             "res_model": "res.company", "res_id": 1, **meta}]
        is_error, body = call(d, "get_attachment", attachment_id=5)
        assert is_error and "Refused" in body
        assert not [c for c in fake.calls if c[3].get("fields") == ["datas"]]

    def test_an_ordinary_file_of_an_allowed_record_downloads(self, server) -> None:
        _, fake, d = server()
        fake.responses[("ir.attachment", "read")] = lambda args, kwargs: (
            [{"id": 1, "datas": "QUJD"}] if kwargs.get("fields") == ["datas"] else ATTACHMENTS)
        is_error, body = call(d, "get_attachment", attachment_id=1)
        assert not is_error and body["data_base64"] == "QUJD"


def test_the_tool_surface_is_nineteen(server) -> None:
    from odoo_mcp_governed.tools import TOOLS
    assert len(TOOLS) == 19 and "list_attachments" in TOOLS
