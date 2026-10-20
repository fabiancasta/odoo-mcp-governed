"""Tests for the preventive policy engine.

The theme throughout: permissions must not leak sideways. Being allowed to
read a model must not imply writing it; being allowed to write must not imply
deleting; and ``execute_method`` must not become a back door to any of them.
"""

from __future__ import annotations

import pytest

from odoo_mcp_governed.governance import Operation, PolicyConfig, PolicyEngine

from .conftest import FakeClock, make_call


def codes(engine: PolicyEngine, call) -> tuple[str, ...]:
    return engine.evaluate(call).codes


def test_reading_an_allowed_model_is_permitted(policy_config, clock: FakeClock) -> None:
    engine = PolicyEngine(policy_config)
    verdict = engine.evaluate(make_call(clock, model="res.partner"))
    assert verdict.allowed
    assert verdict.reasons == ()


def test_reading_an_unlisted_model_is_denied(policy_config, clock: FakeClock) -> None:
    engine = PolicyEngine(policy_config)
    verdict = engine.evaluate(make_call(clock, model="account.move"))
    assert not verdict.allowed
    assert "model_not_allowed" in verdict.codes
    # The reason must name the model, so the agent can stop rather than retry.
    assert "account.move" in verdict.reasons[0]


def test_read_access_does_not_imply_write_access(policy_config, clock: FakeClock) -> None:
    """product.template is readable but not writable in the fixture config."""
    engine = PolicyEngine(policy_config)
    read = engine.evaluate(make_call(clock, model="product.template"))
    assert read.allowed

    write = engine.evaluate(
        make_call(
            clock,
            tool="update_record",
            operation=Operation.WRITE,
            model="product.template",
            record_count=1,
        )
    )
    assert not write.allowed
    assert "model_not_writable" in write.codes


def test_write_access_does_not_imply_delete_access(policy_config, clock: FakeClock) -> None:
    """res.partner is writable but not deletable."""
    engine = PolicyEngine(policy_config)
    write = engine.evaluate(
        make_call(clock, tool="update_record", operation=Operation.WRITE, model="res.partner")
    )
    assert write.allowed

    delete = engine.evaluate(
        make_call(clock, tool="delete_record", operation=Operation.DELETE, model="res.partner")
    )
    assert not delete.allowed
    assert "model_not_deletable" in delete.codes


def test_delete_on_a_deletable_model_is_permitted(policy_config, clock: FakeClock) -> None:
    engine = PolicyEngine(policy_config)
    verdict = engine.evaluate(
        make_call(clock, tool="delete_record", operation=Operation.DELETE, model="mail.activity")
    )
    assert verdict.allowed


def test_empty_config_denies_everything(clock: FakeClock) -> None:
    """Default deny is the whole point — a fresh install must be inert."""
    engine = PolicyEngine(PolicyConfig())
    for operation in (Operation.READ, Operation.WRITE, Operation.CREATE, Operation.DELETE):
        verdict = engine.evaluate(make_call(clock, operation=operation, model="res.partner"))
        assert not verdict.allowed, f"{operation} should be denied by an empty config"


def test_admin_operations_need_no_model_allowlist(clock: FakeClock) -> None:
    """server_status and cache_stats touch no Odoo data, so they stay usable
    even on a locked-down install — otherwise you cannot diagnose one."""
    engine = PolicyEngine(PolicyConfig())
    verdict = engine.evaluate(
        make_call(clock, tool="server_status", operation=Operation.ADMIN, model=None)
    )
    assert verdict.allowed


def test_schema_introspection_is_gated_by_the_allowlist(policy_config, clock: FakeClock) -> None:
    """Field names map the database; that is worth protecting."""
    engine = PolicyEngine(policy_config)
    verdict = engine.evaluate(
        make_call(
            clock, tool="get_model_fields", operation=Operation.META, model="account.move"
        )
    )
    assert not verdict.allowed
    assert "model_not_allowed" in verdict.codes


def test_volume_ceiling_is_enforced(policy_config, clock: FakeClock) -> None:
    engine = PolicyEngine(policy_config)
    ok = engine.evaluate(make_call(clock, record_count=500))
    assert ok.allowed, "the limit itself must be allowed, not off by one"

    too_many = engine.evaluate(make_call(clock, record_count=501))
    assert not too_many.allowed
    assert "volume_exceeded" in too_many.codes


def test_unbounded_calls_are_not_rejected_by_the_volume_rule(
    policy_config, clock: FakeClock
) -> None:
    """record_count=None means 'not knowable yet'. Policy cannot judge it, so
    the per-call cap is applied later by the tool that knows the real count."""
    engine = PolicyEngine(policy_config)
    assert engine.evaluate(make_call(clock, record_count=None)).allowed


def test_credential_fields_are_always_refused(policy_config, clock: FakeClock) -> None:
    engine = PolicyEngine(policy_config)
    verdict = engine.evaluate(
        make_call(clock, model="res.partner", fields=("name", "password"))
    )
    assert not verdict.allowed
    assert "sensitive_field" in verdict.codes


def test_credential_field_matching_ignores_case(policy_config, clock: FakeClock) -> None:
    engine = PolicyEngine(policy_config)
    verdict = engine.evaluate(make_call(clock, model="res.partner", fields=("API_Key",)))
    assert not verdict.allowed
    assert "sensitive_field" in verdict.codes


class TestExecuteMethod:
    """execute_method is the widest surface in the API, so it gets its own set."""

    def test_disabled_by_default(self, clock: FakeClock) -> None:
        config = PolicyConfig(
            allowed_models=frozenset({"sale.order"}),
            writable_models=frozenset({"sale.order"}),
        )
        verdict = PolicyEngine(config).evaluate(
            make_call(
                clock,
                tool="execute_method",
                operation=Operation.EXECUTE,
                model="sale.order",
                method="action_confirm",
            )
        )
        assert not verdict.allowed
        assert "execute_disabled" in verdict.codes

    def test_allowlisted_method_is_permitted(self, policy_config, clock: FakeClock) -> None:
        verdict = PolicyEngine(policy_config).evaluate(
            make_call(
                clock,
                tool="execute_method",
                operation=Operation.EXECUTE,
                model="res.partner",
                method="message_post",
            )
        )
        assert verdict.allowed, verdict.reasons

    def test_method_outside_the_allowlist_is_denied(self, policy_config, clock: FakeClock) -> None:
        verdict = PolicyEngine(policy_config).evaluate(
            make_call(
                clock,
                tool="execute_method",
                operation=Operation.EXECUTE,
                model="res.partner",
                method="action_archive",
            )
        )
        assert not verdict.allowed
        assert "method_not_allowed" in verdict.codes

    def test_cannot_launder_a_delete_through_unlink(self, policy_config, clock: FakeClock) -> None:
        """The attack this gate exists for.

        res.partner is writable but NOT deletable. Calling ``unlink`` on it via
        execute_method would delete records while never touching the delete
        gate. It must be refused on the method, regardless of the allowlist.
        """
        verdict = PolicyEngine(policy_config).evaluate(
            make_call(
                clock,
                tool="execute_method",
                operation=Operation.EXECUTE,
                model="res.partner",
                method="unlink",
            )
        )
        assert not verdict.allowed
        assert "method_blocked" in verdict.codes

    def test_cannot_launder_a_write_through_write(self, policy_config, clock: FakeClock) -> None:
        verdict = PolicyEngine(policy_config).evaluate(
            make_call(
                clock,
                tool="execute_method",
                operation=Operation.EXECUTE,
                model="res.partner",
                method="write",
            )
        )
        assert not verdict.allowed
        assert "method_blocked" in verdict.codes

    def test_blocked_methods_are_refused_even_if_allowlisted(self, clock: FakeClock) -> None:
        """A misconfiguration must not be able to re-enable unlink."""
        config = PolicyConfig(
            allowed_models=frozenset({"res.partner"}),
            writable_models=frozenset({"res.partner"}),
            allow_execute_method=True,
            execute_method_allowlist=frozenset({"unlink"}),
        )
        verdict = PolicyEngine(config).evaluate(
            make_call(
                clock,
                tool="execute_method",
                operation=Operation.EXECUTE,
                model="res.partner",
                method="unlink",
            )
        )
        assert not verdict.allowed
        assert "method_blocked" in verdict.codes

    def test_private_methods_are_refused(self, policy_config, clock: FakeClock) -> None:
        verdict = PolicyEngine(policy_config).evaluate(
            make_call(
                clock,
                tool="execute_method",
                operation=Operation.EXECUTE,
                model="res.partner",
                method="_compute_display_name",
            )
        )
        assert not verdict.allowed
        assert "method_private" in verdict.codes

    def test_requires_write_permission_on_the_model(self, policy_config, clock: FakeClock) -> None:
        """sale.order is readable but not writable; an arbitrary method may write."""
        verdict = PolicyEngine(policy_config).evaluate(
            make_call(
                clock,
                tool="execute_method",
                operation=Operation.EXECUTE,
                model="sale.order",
                method="action_confirm",
            )
        )
        assert not verdict.allowed
        assert "model_not_writable" in verdict.codes


class TestConfigValidation:
    def test_flags_models_that_are_writable_but_unreachable(self) -> None:
        config = PolicyConfig(
            allowed_models=frozenset({"res.partner"}),
            writable_models=frozenset({"res.partner", "account.move"}),
        )
        warnings = config.validate()
        assert any("WRITABLE_MODELS" in w and "account.move" in w for w in warnings)

    def test_flags_an_empty_allowlist(self) -> None:
        assert any("ALLOWED_MODELS is empty" in w for w in PolicyConfig().validate())

    def test_flags_execute_method_without_an_allowlist(self) -> None:
        config = PolicyConfig(
            allowed_models=frozenset({"res.partner"}),
            allow_execute_method=True,
        )
        assert any("no method allowlist" in w for w in config.validate())

    def test_clean_config_produces_no_warnings(self) -> None:
        config = PolicyConfig(
            allowed_models=frozenset({"res.partner"}),
            writable_models=frozenset({"res.partner"}),
            deletable_models=frozenset(),
            allow_execute_method=True,
            execute_method_allowlist=frozenset({"message_post"}),
        )
        assert config.validate() == []


class TestDenylistAndWildcard:
    """The layered model: the allowlist says what an agent needs, the denylist
    says what nobody gets, and the denylist always wins."""

    def wide_open(self, **overrides) -> PolicyConfig:
        base = dict(
            allowed_models=frozenset({"*"}),
            writable_models=frozenset({"*"}),
            deletable_models=frozenset({"*"}),
            allow_execute_method=True,
        )
        base.update(overrides)
        return PolicyConfig(**base)

    def test_wildcard_allows_ordinary_models(self, clock: FakeClock) -> None:
        engine = PolicyEngine(self.wide_open())
        for model in ("res.partner", "account.move", "stock.picking"):
            assert engine.evaluate(make_call(clock, model=model)).allowed

    @pytest.mark.parametrize(
        "model",
        ["ir.cron", "ir.actions.server", "base.automation", "ir.config_parameter",
         "res.users.apikeys", "ir.rule", "ir.model.access"],
    )
    def test_wildcard_never_reaches_the_denylist(self, clock: FakeClock, model: str) -> None:
        """The whole point of the second layer. ``ALLOWED_MODELS=*`` is a
        convenience; it must not be a way to reach code execution."""
        engine = PolicyEngine(self.wide_open())
        for operation in (Operation.READ, Operation.WRITE, Operation.DELETE, Operation.META):
            verdict = engine.evaluate(make_call(clock, operation=operation, model=model))
            assert not verdict.allowed, f"{operation.value} on {model}"
            assert verdict.codes == ("model_denied",)

    def test_denylist_beats_an_explicit_allowlist_entry(self, clock: FakeClock) -> None:
        engine = PolicyEngine(
            PolicyConfig(
                allowed_models=frozenset({"ir.config_parameter"}),
                writable_models=frozenset({"ir.config_parameter"}),
            )
        )
        verdict = engine.evaluate(make_call(clock, model="ir.config_parameter"))
        assert verdict.codes == ("model_denied",)

    def test_execute_method_cannot_target_a_denied_model(self, clock: FakeClock) -> None:
        engine = PolicyEngine(self.wide_open())
        verdict = engine.evaluate(
            make_call(
                clock,
                tool="execute_method",
                operation=Operation.EXECUTE,
                model="ir.cron",
                method="method_direct_trigger",
            )
        )
        assert verdict.codes == ("model_denied",)

    def test_denylist_is_configurable(self, clock: FakeClock) -> None:
        # Lifting a denylist entry is not enough for a system model: '*' never
        # reaches those, so it has to be named exactly as well.
        engine = PolicyEngine(self.wide_open(denied_models=frozenset()))
        assert not engine.evaluate(make_call(clock, model="ir.rule")).allowed
        named = self.wide_open(denied_models=frozenset(),
                               allowed_models=frozenset({"*", "ir.rule"}))
        assert PolicyEngine(named).evaluate(make_call(clock, model="ir.rule")).allowed

    def test_lifting_critical_entries_is_warned_about(self) -> None:
        warnings = self.wide_open(denied_models=frozenset()).validate()
        assert any("code execution" in w and "ir.cron" in w for w in warnings)

    def test_wildcard_delete_is_warned_about(self) -> None:
        assert any("DELETABLE_MODELS is '*'" in w for w in self.wide_open().validate())


class TestToolAndMethodSwitches:
    def test_disabled_tool_is_refused_even_for_admin_operations(self, clock: FakeClock) -> None:
        engine = PolicyEngine(PolicyConfig(disabled_tools=frozenset({"server_status"})))
        verdict = engine.evaluate(
            make_call(clock, tool="server_status", operation=Operation.ADMIN, model=None)
        )
        assert verdict.codes == ("tool_disabled",)

    def test_forbidden_methods_extend_the_builtin_list(self, policy_config, clock) -> None:
        from dataclasses import replace

        config = replace(
            policy_config,
            execute_method_allowlist=frozenset(),
            forbidden_methods=frozenset({"action_archive"}),
        )
        verdict = PolicyEngine(config).evaluate(
            make_call(
                clock,
                tool="execute_method",
                operation=Operation.EXECUTE,
                model="res.partner",
                method="action_archive",
            )
        )
        assert "method_blocked" in verdict.codes

    @pytest.mark.parametrize("method", ["sudo", "with_user", "with_env"])
    def test_environment_switching_is_always_blocked(self, policy_config, clock, method) -> None:
        from dataclasses import replace

        config = replace(policy_config, execute_method_allowlist=frozenset({method}))
        verdict = PolicyEngine(config).evaluate(
            make_call(
                clock,
                tool="execute_method",
                operation=Operation.EXECUTE,
                model="res.partner",
                method=method,
            )
        )
        assert "method_blocked" in verdict.codes
