"""N1 and N2 from the 2026-10-18 review.

N1: transient models (wizards) act on *other* models — a merge wizard
rewrites and deletes partners, a payment wizard posts entries — without
going through those models' write and delete gates. Same class as the
settings-wizard bypass (H1). They are refused unless listed in
TRANSIENT_ALLOWLIST (sandbox profiles excepted).

N2: model_info returned ir.model.info, which is the Python class docstring
and on res.partner came from a phone mixin. It now describes the model by
its own name.
"""

from __future__ import annotations

import pytest

from odoo_mcp_governed.config import Settings
from odoo_mcp_governed.protocol import Dispatcher
from odoo_mcp_governed.runtime import Runtime, Snapshot

from .test_tools import FakeOdoo, call

WIZARD = "base.partner.merge.automatic.wizard"
MODELS = [
    {"model": "res.partner", "name": "Contact", "transient": False},
    {"model": WIZARD, "name": "Merge Partner Wizard", "transient": True},
    {"model": "account.payment.register", "name": "Pay", "transient": True},
]


@pytest.fixture
def wide(tmp_path):
    def build(**overrides):
        values = dict(
            _env_file=None, data_dir=tmp_path, odoo_url="http://fake.invalid", odoo_db="fake",
            odoo_username="bot", odoo_api_key="k", allowed_models="*", writable_models="*",
            deletable_models="*", allow_execute_method=True, execute_method_allowlist="",
            business_timezone="UTC", business_hours="00:00-23:59",
            business_days="mon,tue,wed,thu,fri,sat,sun", risk_throttle_seconds=0,
            odoo_environment="development",
        )
        values.update(overrides)
        runtime = Runtime(Settings(**values))
        fake = FakeOdoo()

        def ir_model(args, kwargs):
            domain = args[0] if args else []
            if domain == [["transient", "=", True]]:
                return [m for m in MODELS if m["transient"]]
            if domain and domain[0][0] == "model":
                return [{**m, "info": "Mixin for phone numbers", "modules": "base"}
                        for m in MODELS if m["model"] == domain[0][2]]
            return MODELS

        fake.responses[("ir.model", "search_read")] = ir_model
        runtime._snapshot = Snapshot(runtime.profiles.active(), fake)
        return runtime, fake, Dispatcher(runtime)
    return build


def touched(fake, model) -> bool:
    return any(m == model for m, *_ in fake.calls)


class TestWizardsAreRefused:
    def test_creating_or_running_a_wizard_is_refused(self, wide) -> None:
        _, fake, d = wide()
        is_error, body = call(d, "create_record", model=WIZARD, values={"dst_partner_id": 1})
        assert is_error and "TRANSIENT_ALLOWLIST" in body
        assert call(d, "execute_method", model=WIZARD, method="action_merge", args=[[1]])[0]
        assert not touched(fake, WIZARD)

    def test_an_allowlisted_wizard_works(self, wide) -> None:
        _, fake, d = wide(transient_allowlist="account.payment.register")
        fake.responses[("account.payment.register", "create")] = 5
        assert not call(d, "create_record", model="account.payment.register",
                        values={"amount": 1})[0]
        assert call(d, "create_record", model=WIZARD, values={"x": 1})[0]

    def test_unknown_registry_falls_back_to_the_name(self, wide) -> None:
        """If ir.model cannot be read, a *wizard* name still counts as one."""
        runtime, fake, d = wide()

        def broken(args, kwargs):
            raise RuntimeError("no access to ir.model")
        fake.responses[("ir.model", "search_read")] = broken
        assert call(d, "create_record", model="sale.advance.payment.wizard", values={"x": 1})[0]
        assert not call(d, "search_count", model="res.partner")[0]

    def test_sandbox_profiles_may_use_wizards(self, wide) -> None:
        from dataclasses import replace
        runtime, fake, d = wide()
        runtime.save_profile(replace(runtime.profiles.active(), sandbox=True), actor="admin")
        runtime._snapshot = Snapshot(runtime.profiles.active(), fake)
        # A business wizard; the partner merge wizard is base.*, a system model,
        # which a sandbox does not reach either.
        fake.responses[("account.payment.register", "create")] = 3
        assert not call(d, "create_record", model="account.payment.register",
                        values={"x": 1})[0]

    def test_list_models_does_not_offer_refused_wizards(self, wide) -> None:
        _, _, d = wide()
        names = {m["model"] for m in call(d, "list_models")[1]["models"]}
        assert "res.partner" in names and WIZARD not in names


def test_model_info_describes_the_model_not_a_mixin_docstring(wide) -> None:
    _, _, d = wide()
    body = call(d, "model_info", model="res.partner")[1]
    assert body["description"] == "Contact"
    assert "Mixin" not in str(body)
