"""Findings from the staff review of the audit branch (2026-10-17).

1. server_status showed ``allow_writes: false`` next to ``read_only: false`` on
   a development profile that could write. ``allow_writes`` only lifts the
   production default; the status must say what is actually in effect.
2. The denylist must not be the only barrier. A production profile whose Odoo
   user has Settings access, combined with a ``*`` allowlist, leaves nothing
   behind the policy if a rule is missing: such calls are refused, and
   server_status warns about the privileged user on any profile.
"""

from __future__ import annotations

from dataclasses import replace

from odoo_mcp_governed.config import Settings
from odoo_mcp_governed.protocol import Dispatcher
from odoo_mcp_governed.runtime import Runtime, Snapshot

from .test_tools import FakeOdoo, call


def runtime_for(tmp_path, environment: str, allowed: str = "*", **profile) -> tuple:
    runtime = Runtime(Settings(
        _env_file=None, data_dir=tmp_path, odoo_url="http://fake.invalid", odoo_db="d",
        odoo_username="u", odoo_api_key="k", allowed_models=allowed, writable_models="*",
        business_timezone="UTC", business_hours="00:00-23:59",
        business_days="mon,tue,wed,thu,fri,sat,sun", odoo_environment=environment,
        risk_throttle_seconds=0,
    ))
    if profile:
        runtime.save_profile(replace(runtime.profiles.active(), **profile), actor="admin")
    fake = FakeOdoo()
    runtime._snapshot = Snapshot(runtime.profiles.active(), fake)
    return runtime, fake, Dispatcher(runtime)


def settings_access(fake: FakeOdoo, value) -> None:
    def has_group(args, kwargs):
        if isinstance(value, Exception):
            raise value
        return value
    fake.responses[("res.users", "has_group")] = has_group


class TestWritesStatus:
    def test_development_profile_reports_writes_enabled(self, tmp_path) -> None:
        _, _, d = runtime_for(tmp_path, "development")
        body = call(d, "server_status")[1]
        assert body["profile"]["writes_enabled"] is True
        assert "allow_writes" not in body["profile"]
        assert "production_writes_override" not in body["profile"]

    def test_production_profile_reports_writes_blocked_and_why(self, tmp_path) -> None:
        _, _, d = runtime_for(tmp_path, "production")
        profile = call(d, "server_status")[1]["profile"]
        assert profile["writes_enabled"] is False
        assert profile["production_writes_override"] is False
        assert "read-only" in profile["writes_note"]
        is_error, body = call(d, "update_record", model="res.partner", record_id=1,
                              values={"name": "x"})
        assert is_error and "read-only" in body

    def test_production_override_is_reported(self, tmp_path) -> None:
        _, _, d = runtime_for(tmp_path, "production", allow_writes=True)
        profile = call(d, "server_status")[1]["profile"]
        assert profile["writes_enabled"] is True
        assert profile["production_writes_override"] is True


class TestPrivilegedUser:
    def test_wildcard_on_production_with_a_settings_user_is_refused(self, tmp_path) -> None:
        _, fake, d = runtime_for(tmp_path, "production")
        settings_access(fake, True)
        is_error, body = call(d, "search_count", model="res.partner")
        assert is_error
        assert "Settings" in body and "least-privilege" in body
        assert not any(m == "res.partner" for m, *_ in fake.calls)

    def test_unverifiable_access_on_production_counts_as_privileged(self, tmp_path) -> None:
        _, fake, d = runtime_for(tmp_path, "production")
        settings_access(fake, RuntimeError("has_group not allowed"))
        assert call(d, "search_count", model="res.partner")[0]

    def test_a_least_privilege_user_may_use_wildcards_on_production(self, tmp_path) -> None:
        _, fake, d = runtime_for(tmp_path, "production")
        settings_access(fake, False)
        assert not call(d, "search_count", model="res.partner")[0]

    def test_explicit_lists_work_with_a_privileged_user(self, tmp_path) -> None:
        _, fake, d = runtime_for(tmp_path, "production", allowed="res.partner")
        settings_access(fake, True)
        assert not call(d, "search_count", model="res.partner")[0]

    def test_development_is_not_refused_but_warned(self, tmp_path) -> None:
        _, fake, d = runtime_for(tmp_path, "development")
        settings_access(fake, True)
        assert not call(d, "search_count", model="res.partner")[0]
        body = call(d, "server_status")[1]
        assert body["odoo"]["settings_access"] is True
        assert any("Settings" in w for w in body["governance"]["warnings"])


def test_get_record_cannot_name_attachment_content(tmp_path) -> None:
    """The other route to H2, checked separately at the reviewer's request."""
    _, fake, d = runtime_for(tmp_path, "development")
    is_error, body = call(d, "get_record", model="ir.attachment", record_id=1,
                          fields=["name", "datas"])
    assert is_error and "get_attachment" in body
    assert not any(m == "ir.attachment" for m, *_ in fake.calls)
