"""Production safeguards.

The failure being guarded against is mundane and expensive: a development
setup that turns out to be pointed at the live ERP. Two layers:

* Profiles are production unless labelled otherwise, and production is
  read-only unless explicitly unlocked per profile.
* PROTECTED_HOSTS makes chosen hosts unreachable outright.
"""

from __future__ import annotations

import json

import pytest

from odoo_mcp_governed.config import Settings
from odoo_mcp_governed.governance import Operation, PolicyConfig, PolicyEngine
from odoo_mcp_governed.profiles import Profile, ProfileError, ProfileStore, host_is_protected
from odoo_mcp_governed.protocol import Dispatcher
from odoo_mcp_governed.runtime import Runtime, Snapshot

from .conftest import FakeClock, make_call
from .test_tools import FakeOdoo, call


def profile(name="p", url="http://localhost:65010", **kw) -> Profile:
    return Profile(name=name, url=url, database="db", username="u", api_key="k", **kw)


class TestLabels:
    def test_unlabelled_profile_from_a_copied_file_is_production(self, tmp_path) -> None:
        """The realistic accident: dropping in another tool's profile file."""
        path = tmp_path / "profiles.json"
        path.write_text(json.dumps({"active": "crm", "profiles": {"crm": {
            "url": "https://erp.example.com", "database": "live", "username": "u",
            "api_key": "k"}}}))
        loaded = ProfileStore(path).get("crm")
        assert loaded.environment == "production"
        assert loaded.read_only

    def test_production_is_read_only_until_unlocked(self) -> None:
        assert profile(environment="production").read_only
        assert not profile(environment="production", allow_writes=True).read_only
        assert not profile(environment="development").read_only
        assert not profile(environment="staging").read_only

    def test_unknown_environment_is_rejected(self) -> None:
        with pytest.raises(ProfileError, match="Environment"):
            profile(environment="prod").validate()


class TestReadOnlyPolicy:
    @pytest.mark.parametrize(
        "operation", [Operation.CREATE, Operation.WRITE, Operation.DELETE, Operation.EXECUTE]
    )
    def test_mutations_are_refused_whatever_the_model_lists_say(
        self, clock: FakeClock, operation: Operation
    ) -> None:
        config = PolicyConfig(
            allowed_models=frozenset({"*"}), writable_models=frozenset({"*"}),
            deletable_models=frozenset({"*"}), allow_execute_method=True,
            read_only_profiles=frozenset({"live"}),
        )
        verdict = PolicyEngine(config).evaluate(
            make_call(clock, operation=operation, model="res.partner", method="action_confirm",
                      profile="live")
        )
        assert verdict.codes == ("profile_read_only",)

    def test_reads_still_work_on_production(self, clock: FakeClock) -> None:
        config = PolicyConfig(allowed_models=frozenset({"*"}),
                              read_only_profiles=frozenset({"live"}))
        assert PolicyEngine(config).evaluate(make_call(clock, profile="live")).allowed


@pytest.fixture
def runtime(tmp_path) -> Runtime:
    return Runtime(Settings(
        _env_file=None, data_dir=tmp_path, odoo_url="http://fake.invalid", odoo_db="d",
        odoo_username="u", odoo_api_key="k", allowed_models="*", writable_models="*",
        deletable_models="*", business_timezone="UTC", business_hours="00:00-23:59",
        business_days="mon,tue,wed,thu,fri,sat,sun",
    ))


class TestEndToEnd:
    def test_env_bootstrapped_profile_defaults_to_production(self, runtime) -> None:
        assert runtime.profiles.active().environment == "production"
        assert "default" in runtime.engine.policy.config.read_only_profiles

    def test_writes_never_reach_a_production_odoo(self, runtime) -> None:
        fake = FakeOdoo()
        runtime._snapshot = Snapshot(runtime.profiles.active(), fake)
        d = Dispatcher(runtime)
        for tool, args in (
            ("create_record", {"model": "res.partner", "values": {"name": "x"}}),
            ("update_record", {"model": "res.partner", "record_id": 1, "values": {"name": "x"}}),
            ("delete_record", {"model": "res.partner", "record_id": 1}),
        ):
            is_error, body = call(d, tool, **args)
            assert is_error and "read-only" in body, tool
        # Only the read-only Settings-access check may reach Odoo; no write may.
        # Only metadata lookups — Settings access, the wizard registry — may
        # reach Odoo; no write may.
        assert not [c for c in fake.calls if c[1] in ("create", "write", "unlink")]
        assert call(d, "search_count", model="res.partner")[0] is False

    def test_relabelling_takes_effect_on_the_next_call(self, runtime) -> None:
        current = runtime.profiles.active()
        from dataclasses import replace

        runtime.save_profile(replace(current, environment="development"), actor="admin")
        assert "default" not in runtime.engine.policy.config.read_only_profiles
        runtime.save_profile(replace(current, environment="production"), actor="admin")
        assert "default" in runtime.engine.policy.config.read_only_profiles


class TestProtectedHosts:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://erp.example.com", True),
            ("https://crm.erp.example.com:8443/web", True),
            ("https://ERP.EXAMPLE.COM.", True),
            ("https://notERP.example.com", False),
            ("https://erp.example.com.evil.net", False),
            ("http://203.0.113.7:8069", True),
            ("http://203.0.113.70:8069", False),
            ("http://localhost:65010", False),
        ],
    )
    def test_matching(self, url: str, expected: bool) -> None:
        assert host_is_protected(url, ["erp.example.com", "203.0.113.7"]) is expected

    def test_cannot_save_or_activate(self, tmp_path) -> None:
        store = ProfileStore(tmp_path / "p.json", ["erp.example.com"])
        with pytest.raises(ProfileError, match="PROTECTED_HOSTS"):
            store.save(profile(name="live", url="https://erp.example.com"))

    def test_protected_active_profile_is_dropped_on_load(self, tmp_path) -> None:
        path = tmp_path / "p.json"
        path.write_text(json.dumps({"active": "live", "profiles": {"live": {
            "url": "https://erp.example.com", "database": "d", "username": "u",
            "api_key": "k"}}}))
        store = ProfileStore(path, ["erp.example.com"])
        assert store.active() is None
        assert store.public()[0]["protected"] is True

    def test_server_starts_with_no_profile_rather_than_reaching_a_protected_host(
        self, tmp_path
    ) -> None:
        runtime = Runtime(Settings(
            _env_file=None, data_dir=tmp_path, odoo_url="https://erp.example.com",
            odoo_db="d", odoo_username="u", odoo_api_key="k",
            protected_hosts="erp.example.com",
        ))
        assert runtime.profiles.active() is None
        is_error, body = call(Dispatcher(runtime), "server_status")
        assert is_error and "No Odoo profile" in body
