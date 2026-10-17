"""Sensitive fields are matched by pattern, and the patterns are configurable.

Exact names missed credentials that modules add under compound names —
``stripe_secret_key``, ``unsplash_access_key``, ``signup_token`` — so a model
installed after the server was configured could leak its secrets through a
``*`` allowlist. Patterns catch those; configuration can add more, but never
remove the built-in floor.
"""

from __future__ import annotations

from odoo_mcp_governed.config import Settings
from odoo_mcp_governed.governance import Operation, PolicyConfig, PolicyEngine, ToolCall
from odoo_mcp_governed.policy_store import policy_from_settings

from .test_tools import (
    call,
    env,  # noqa: F401 - shared fixture
)


def verdict(fields: tuple[str, ...], **config):
    engine = PolicyEngine(PolicyConfig(allowed_models=frozenset({"*"}), **config))
    return engine.evaluate(
        ToolCall(
            actor="a", profile="p", tool="search_records", operation=Operation.READ,
            model="payment.provider", fields_touched=fields,
        )
    )


class TestDefaults:
    def test_compound_credential_names_are_caught(self) -> None:
        for name in ("stripe_secret_key", "unsplash_access_key", "signup_token",
                     "x_studio_password_hash", "Adyen_HMAC_Key", "smtp_pass_apikey"):
            assert "sensitive_field" in verdict((name,)).codes, name

    def test_ordinary_fields_are_untouched(self) -> None:
        for name in ("name", "email", "state", "key", "certificate", "list_price"):
            assert verdict((name,)).allowed, name


class TestConfiguration:
    def test_patterns_can_be_added(self) -> None:
        assert verdict(("acc_number",)).allowed
        assert "sensitive_field" in verdict(
            ("acc_number",), sensitive_fields=frozenset({"acc_*"})
        ).codes

    def test_the_builtin_floor_cannot_be_removed(self) -> None:
        """An empty list must not mean 'nothing is sensitive'."""
        assert "sensitive_field" in verdict(
            ("stripe_secret_key",), sensitive_fields=frozenset()
        ).codes

    def test_env_variable_feeds_the_policy(self, tmp_path) -> None:
        settings = Settings(_env_file=None, data_dir=tmp_path, sensitive_fields="*iban*, *cvv*")
        policy = policy_from_settings(settings)
        assert {"*iban*", "*cvv*"} <= policy.sensitive_fields

    def test_editable_from_the_panel(self, env) -> None:  # noqa: F811
        runtime, _, _ = env
        runtime.update_policy({"sensitive_fields": "*iban*\nacc_number"}, actor="admin")
        assert runtime.engine.policy.config.sensitive_fields == frozenset({"*iban*", "acc_number"})


class TestResults:
    def test_matching_keys_are_stripped_from_an_all_fields_read(self, env) -> None:  # noqa: F811
        _, fake, d = env
        fake.responses[("res.partner", "read")] = [
            {"id": 1, "name": "Acme", "stripe_secret_key": "sk_live_x", "signup_token": "t"}
        ]
        is_error, body = call(d, "get_record", model="res.partner", record_id=1)
        assert not is_error
        assert body["records"][0] == {"id": 1, "name": "Acme"}
