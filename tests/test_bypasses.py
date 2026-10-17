"""Regression tests for the bypasses found in the October 2026 security audit.

Each test reproduces an attack that worked against a live server with the
owner's permissive local setup (``*`` everywhere, execute_method on, no
method allowlist). That is the configuration where the denylist is the only
thing standing between an agent and the system's secrets, so it is the one
these must hold under.
"""

from __future__ import annotations

import pytest

from odoo_mcp_governed.config import Settings
from odoo_mcp_governed.protocol import Dispatcher
from odoo_mcp_governed.runtime import Runtime, Snapshot

from .test_tools import FakeOdoo, call


@pytest.fixture
def wide_open(tmp_path):
    settings = Settings(
        _env_file=None,
        data_dir=tmp_path,
        odoo_url="http://fake.invalid",
        odoo_db="fake",
        odoo_username="bot",
        odoo_api_key="k",
        allowed_models="*",
        writable_models="*",
        deletable_models="*",
        allow_execute_method=True,
        execute_method_allowlist="",
        max_records_per_call=50,
        business_timezone="UTC",
        business_hours="00:00-23:59",
        business_days="mon,tue,wed,thu,fri,sat,sun",
        risk_throttle_seconds=0,
        odoo_environment="development",
    )
    runtime = Runtime(settings)
    fake = FakeOdoo()
    runtime._snapshot = Snapshot(runtime.profiles.active(), fake)
    return runtime, fake, Dispatcher(runtime)


def odoo_saw(fake: FakeOdoo, model: str) -> bool:
    return any(m == model for m, *_ in fake.calls)


class TestSettingsWizardBypass:
    """H1: res.config.settings reads and writes ir.config_parameter for you,
    so denying ir.config_parameter alone was not enough."""

    def test_default_get_cannot_read_system_parameters(self, wide_open) -> None:
        _, fake, d = wide_open
        is_error, body = call(
            d, "execute_method", model="res.config.settings", method="default_get",
            args=[["unsplash_access_key"]],
        )
        assert is_error
        assert "res.config.settings" in body
        assert not odoo_saw(fake, "res.config.settings")

    def test_settings_cannot_be_created_or_applied(self, wide_open) -> None:
        _, fake, d = wide_open
        assert call(d, "create_record", model="res.config.settings", values={"x": 1})[0]
        assert call(
            d, "execute_method", model="res.config.settings", method="execute", args=[[1]]
        )[0]
        assert not odoo_saw(fake, "res.config.settings")

    def test_modules_cannot_be_installed_or_uninstalled(self, wide_open) -> None:
        """Installing a module runs its code; uninstalling drops its tables."""
        _, fake, d = wide_open
        assert call(
            d, "execute_method", model="ir.module.module",
            method="button_immediate_uninstall", args=[[1]],
        )[0]
        assert not odoo_saw(fake, "ir.module.module")


class TestAttachmentContentBypass:
    """H2: the generic read tools returned ``datas`` for any attachment,
    skipping the owner-model check that get_attachment does."""

    def test_naming_the_content_field_is_refused(self, wide_open) -> None:
        _, fake, d = wide_open
        is_error, body = call(
            d, "search_records", model="ir.attachment", fields=["name", "datas"]
        )
        assert is_error
        assert "get_attachment" in body
        assert not odoo_saw(fake, "ir.attachment")

    def test_filtering_on_content_is_refused(self, wide_open) -> None:
        _, fake, d = wide_open
        assert call(
            d, "search_records", model="ir.attachment", domain=[["db_datas", "!=", False]]
        )[0]
        assert not odoo_saw(fake, "ir.attachment")

    def test_all_fields_read_comes_back_without_content(self, wide_open) -> None:
        _, fake, d = wide_open
        row = {"id": 7, "name": "secret.pdf", "res_model": "res.users", "datas": "QUJD",
               "raw": "ABC", "db_datas": "QUJD", "store_fname": "ab/abcdef"}
        fake.responses[("ir.attachment", "read")] = [dict(row)]
        fake.responses[("ir.attachment", "search_read")] = [dict(row)]

        is_error, body = call(d, "get_record", model="ir.attachment", record_id=7)
        assert not is_error
        assert body["records"][0]["name"] == "secret.pdf"
        assert not {"datas", "raw", "db_datas", "store_fname"} & set(body["records"][0])

        is_error, body = call(d, "search_records", model="ir.attachment")
        assert not is_error
        assert not {"datas", "raw", "db_datas", "store_fname"} & set(body["records"][0])

    def test_execute_method_read_is_covered_too(self, wide_open) -> None:
        _, fake, d = wide_open
        assert call(
            d, "execute_method", model="ir.attachment", method="read",
            args=[[7]], kwargs={"fields": ["datas"]},
        )[0]
        assert not odoo_saw(fake, "ir.attachment")

        fake.responses[("ir.attachment", "read")] = [{"id": 7, "datas": "QUJD"}]
        is_error, body = call(
            d, "execute_method", model="ir.attachment", method="read", args=[[7]]
        )
        assert not is_error
        assert "datas" not in body["result"][0]

    def test_content_cannot_be_planted_through_create(self, wide_open) -> None:
        """Writing an attachment goes through upload_attachment, which checks
        the owner model is writable."""
        _, fake, d = wide_open
        assert call(
            d, "create_record", model="ir.attachment",
            values={"name": "x", "datas": "QUJD", "res_model": "ir.cron"},
        )[0]
        assert not odoo_saw(fake, "ir.attachment")


class TestExecuteMethodFieldNames:
    def test_field_lists_in_arguments_are_checked(self, wide_open) -> None:
        """read(ids, ['password']) names the field in a list, not a dict, and
        used to slip past the sensitive-field rule."""
        _, fake, d = wide_open
        assert call(
            d, "execute_method", model="res.partner", method="read", args=[[1], ["password"]]
        )[0]
        assert call(
            d, "execute_method", model="res.partner", method="read",
            args=[[1]], kwargs={"fields": ["api_key"]},
        )[0]
        assert not odoo_saw(fake, "res.partner")
