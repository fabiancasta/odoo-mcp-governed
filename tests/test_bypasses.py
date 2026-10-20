"""Regression tests for the bypasses found in the October 2026 security audit.

Each test reproduces an attack that worked against a live server with the
owner's permissive local setup (``*`` everywhere, execute_method on, no
method allowlist). That is the configuration where the denylist is the only
thing standing between an agent and the system's secrets, so it is the one
these must hold under.
"""

from __future__ import annotations

import json

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
        """Since phase 1, ir.attachment is not reachable through the generic
        tools at all — not even its metadata; list_attachments is the way."""
        _, fake, d = wide_open
        for tool, args in (("get_record", {"record_id": 7}), ("search_records", {})):
            is_error, body = call(d, tool, model="ir.attachment", **args)
            assert is_error and "list_attachments" in body
        assert not odoo_saw(fake, "ir.attachment")

    def test_execute_method_read_is_covered_too(self, wide_open) -> None:
        _, fake, d = wide_open
        assert call(
            d, "execute_method", model="ir.attachment", method="read",
            args=[[7]], kwargs={"fields": ["datas"]},
        )[0]
        assert not odoo_saw(fake, "ir.attachment")

        # Since the re-parenting finding, no method runs on ir.attachment at
        # all through execute_method — not even read; use search_records.
        assert call(d, "execute_method", model="ir.attachment", method="read", args=[[7]])[0]
        assert not odoo_saw(fake, "ir.attachment")

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


def test_all_fields_on_attachments_never_asks_odoo_for_the_content(wide_open) -> None:
    _, fake, d = wide_open
    assert call(d, "search_records", model="ir.attachment")[0]
    assert call(d, "get_record", model="ir.attachment", record_id=1)[0]
    assert not odoo_saw(fake, "ir.attachment")

def test_unnamed_binary_fields_are_not_fetched_on_any_model(wide_open) -> None:
    """A contact read with no field list used to return ten base64 copies of
    its photo. Asked for by name, they still come back."""
    _, fake, d = wide_open
    fake.responses[("res.partner", "fields_get")] = {
        "name": {"type": "char"}, "image_1920": {"type": "binary"},
        "avatar_128": {"type": "binary"},
    }
    call(d, "get_record", model="res.partner", record_id=3)
    call(d, "get_record", model="res.partner", record_id=3, fields=["image_1920"])
    reads = [kw for m, meth, _a, kw in fake.calls if m == "res.partner" and meth == "read"]
    assert reads[0]["fields"] == ["name"]
    assert reads[1]["fields"] == ["image_1920"]


class TestNestedStructures:
    """Found in the 2026-10-18 self-review: field names were collected from
    the top level of execute_method and onchange arguments only, and results
    were redacted only at the top level, so nested specifications (Odoo's
    web_search_read / web_read / onchange) reached and returned credential
    fields of related records. Sorting by a field was not checked at all."""

    def test_nested_specification_naming_a_secret_is_refused(self, wide_open) -> None:
        _, fake, d = wide_open
        spec = {"name": {}, "user_ids": {"fields": {"login": {}, "password": {}}}}
        assert call(d, "execute_method", model="res.partner", method="web_search_read",
                    kwargs={"domain": [], "specification": spec})[0]
        assert not odoo_saw(fake, "res.partner")

    def test_nested_onchange_spec_naming_a_secret_is_refused(self, wide_open) -> None:
        _, fake, d = wide_open
        assert call(d, "call_onchange", model="res.partner", values={"name": "x"},
                    fields_spec={"user_ids": {"fields": {"api_key": {}}}})[0]
        assert not odoo_saw(fake, "res.partner")

    def test_nested_results_are_redacted(self, wide_open) -> None:
        _, fake, d = wide_open
        fake.responses[("res.partner", "web_search_read")] = {"records": [
            {"id": 1, "name": "Acme", "user_ids": [{"id": 2, "login": "a", "signup_token": "t"}]}
        ]}
        is_error, body = call(d, "execute_method", model="res.partner",
                              method="web_search_read", kwargs={"domain": []})
        assert not is_error
        assert "signup_token" not in json.dumps(body)

    def test_sorting_by_a_secret_is_refused(self, wide_open) -> None:
        _, fake, d = wide_open
        assert call(d, "search_records", model="res.users", order="password desc")[0]
        assert not odoo_saw(fake, "res.users")


class TestIndexedContent:
    """Found by the red-team canaries: ir.attachment.index_content holds the
    extracted text of a file for Odoo's search, so an all-fields read returned
    the content of an attachment whose owner model was denied, and a domain
    on it was a content oracle."""

    def test_naming_or_filtering_on_index_content_is_refused(self, wide_open) -> None:
        _, fake, d = wide_open
        assert call(d, "search_records", model="ir.attachment", fields=["index_content"])[0]
        assert call(d, "search_count", model="ir.attachment",
                    domain=[["index_content", "ilike", "CANARY"]])[0]
        assert not odoo_saw(fake, "ir.attachment")

    def test_all_fields_read_leaves_index_content_out(self, wide_open) -> None:
        _, fake, d = wide_open
        assert call(d, "search_records", model="ir.attachment")[0]
        assert not odoo_saw(fake, "ir.attachment")

class TestAttachmentReparenting:
    """Found by the LLM red-team agent (run 3, turn 13): get_attachment checks
    the model an attachment belongs to, but with a wide policy ir.attachment
    itself was writable, so an agent could move a denied model's file onto an
    allowed record (res_model / res_id) and then download it — or delete it.
    Attachments are now changed only through upload_attachment, which checks
    the owner; the generic tools may still read their metadata."""

    def test_moving_an_attachment_to_another_owner_is_refused(self, wide_open) -> None:
        _, fake, d = wide_open
        is_error, body = call(d, "update_record", model="ir.attachment", record_id=7,
                              values={"res_model": "res.partner", "res_id": 3})
        assert is_error and "upload_attachment" in body
        assert not odoo_saw(fake, "ir.attachment")

    def test_attachments_cannot_be_created_deleted_or_driven_generically(self, wide_open) -> None:
        _, fake, d = wide_open
        assert call(d, "create_record", model="ir.attachment",
                    values={"name": "x", "res_model": "res.partner"})[0]
        assert call(d, "delete_record", model="ir.attachment", record_id=7)[0]
        assert call(d, "execute_method", model="ir.attachment", method="action_x",
                    args=[[7]])[0]
        assert not odoo_saw(fake, "ir.attachment")

    def test_metadata_is_listed_per_record_only(self, wide_open) -> None:
        _, fake, d = wide_open
        assert call(d, "search_records", model="ir.attachment", fields=["name"])[0]
        fake.responses[("ir.attachment", "search_read")] = [{"id": 7, "name": "a.pdf"}]
        assert not call(d, "list_attachments", model="res.partner", record_id=3)[0]

