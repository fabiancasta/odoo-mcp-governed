"""Tool-level tests against a fake Odoo that records every call.

The strongest statement a governance test can make is not "the call was
refused" but "Odoo never saw it". The fake client makes that checkable: a
denied tool call must leave its call log empty.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from odoo_mcp_governed.config import Settings
from odoo_mcp_governed.governance import Decision
from odoo_mcp_governed.protocol import Dispatcher
from odoo_mcp_governed.runtime import Runtime, Snapshot
from odoo_mcp_governed.tools import domain_fields


class FakeOdoo:
    database = "fake"

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, list, dict]] = []
        self.responses: dict[tuple[str, str], Any] = {}

    def execute(self, model, method, args=None, kwargs=None):
        self.calls.append((model, method, args or [], kwargs or {}))
        response = self.responses.get((model, method), [])
        return response(args, kwargs) if callable(response) else response

    def version(self):
        return {"server_version": "19.0-fake"}

    @property
    def uid(self):
        return 2


def data_calls(fake: FakeOdoo) -> list:
    """Calls that touched data. The registry lookup that tells wizards apart
    (``ir.model`` search for transient models) is metadata, not data."""
    return [c for c in fake.calls
            if not (c[0] == "ir.model" and c[2] == [[["transient", "=", True]]])]


@pytest.fixture
def env(tmp_path):
    settings = Settings(
        _env_file=None,
        data_dir=tmp_path,
        odoo_url="http://fake.invalid",
        odoo_db="fake",
        odoo_username="bot",
        odoo_api_key="k",
        allowed_models="res.partner,product.template,ir.attachment",
        writable_models="res.partner",
        deletable_models="res.partner",
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


def call(dispatcher: Dispatcher, _tool: str, actor: str = "agent", **arguments):
    response = dispatcher.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": _tool, "arguments": arguments}}, actor,
    )["result"]
    text = response["content"][0]["text"]
    try:
        body = json.loads(text)
    except ValueError:
        body = text
    return response["isError"], body


class TestDomainFields:
    def test_simple_and_dotted_paths(self) -> None:
        assert domain_fields([["user_ids.password", "=", "x"]]) == {
            "user_ids.password", "user_ids", "password"}

    def test_operators_and_nesting(self) -> None:
        domain = ["|", ["name", "ilike", "a"], "&", ["email", "=", "b"], ["vat", "!=", False]]
        assert domain_fields(domain) == {"name", "email", "vat"}

    def test_tolerates_garbage(self) -> None:
        assert domain_fields("not a domain") == set()
        assert domain_fields([1, None, ["x"]]) == set()


class TestNeverReachesOdoo:
    """Each of these must be refused before a single request goes out."""

    def test_password_oracle_through_a_domain(self, env) -> None:
        runtime, fake, d = env
        is_error, body = call(d, "search_count", model="res.partner",
                              domain=[["user_ids.password", "=", "hunter2"]])
        assert is_error and "credential" in body
        assert data_calls(fake) == []

    def test_password_oracle_through_name_search(self, env) -> None:
        _, fake, d = env
        is_error, _ = call(d, "name_search", model="res.partner", name="a",
                           domain=[["api_key", "!=", False]])
        assert is_error and data_calls(fake) == []

    def test_denylisted_model(self, env) -> None:
        _, fake, d = env
        is_error, body = call(d, "search_records", model="ir.config_parameter")
        assert is_error and "denylist" in body and data_calls(fake) == []

    def test_limit_above_the_ceiling_is_refused_not_truncated(self, env) -> None:
        """Silently capping to 50 would let the agent believe it saw
        everything. Refusing tells it to paginate."""
        _, fake, d = env
        is_error, body = call(d, "search_records", model="res.partner", limit=51)
        assert is_error and "limit is 50" in body and data_calls(fake) == []

    def test_write_to_read_only_model(self, env) -> None:
        _, fake, d = env
        is_error, _ = call(d, "update_record", model="product.template", record_id=1,
                           values={"name": "x"})
        assert is_error and data_calls(fake) == []

    def test_execute_method_is_off_by_default(self, env) -> None:
        _, fake, d = env
        is_error, body = call(d, "execute_method", model="res.partner", method="action_archive",
                              args=[[1]])
        assert is_error and "disabled" in body and data_calls(fake) == []

    def test_upload_to_a_read_only_model(self, env) -> None:
        _, fake, d = env
        is_error, _ = call(d, "upload_attachment", model="product.template", record_id=1,
                           filename="a.txt", data_base64=base64.b64encode(b"x").decode())
        assert is_error and data_calls(fake) == []


class TestToolBehaviour:
    def test_search_defaults_to_the_ceiling_when_lower(self, env) -> None:
        _, fake, d = env
        call(d, "search_records", model="res.partner")
        [search] = [c for c in data_calls(fake) if c[1] == "search_read"]
        assert search[3]["limit"] == 50

    def test_sensitive_keys_are_stripped_from_results(self, env) -> None:
        _, fake, d = env
        fake.responses[("res.partner", "search_read")] = [
            {"id": 1, "name": "A", "api_key": "LEAK", "Password": "LEAK"}]
        is_error, body = call(d, "search_records", model="res.partner")
        assert not is_error
        assert "LEAK" not in json.dumps(body)
        assert body["records"] == [{"id": 1, "name": "A"}]

    def test_create_accepts_a_list_or_an_int_from_odoo(self, env) -> None:
        _, fake, d = env
        fake.responses[("res.partner", "create")] = [42]
        assert call(d, "create_record", model="res.partner", values={"name": "x"})[1]["id"] == 42
        fake.responses[("res.partner", "create")] = 43
        assert call(d, "create_record", model="res.partner", values={"name": "y"})[1]["id"] == 43

    def test_get_record_reports_missing_ids(self, env) -> None:
        _, fake, d = env
        fake.responses[("res.partner", "read")] = [{"id": 1, "name": "A"}]
        _, body = call(d, "get_record", model="res.partner", ids=[1, 2])
        assert body["missing_ids"] == [2]

    def test_affected_count_reaches_the_audit_log(self, env) -> None:
        runtime, fake, d = env
        fake.responses[("res.partner", "search_read")] = [{"id": i} for i in range(7)]
        call(d, "search_records", model="res.partner")
        assert runtime.audit.tail(1)[0].affected_count == 7

    def test_attachment_is_governed_by_its_owning_model(self, env) -> None:
        """A file attached to a denied model must not leak via ir.attachment."""
        runtime, fake, d = env
        fake.responses[("ir.attachment", "read")] = [
            {"id": 9, "name": "salary.pdf", "mimetype": "application/pdf",
             "file_size": 10, "res_model": "hr.employee", "res_id": 1}]
        is_error, body = call(d, "get_attachment", attachment_id=9)
        assert is_error and "hr.employee" in body
        # Only the metadata lookup happened — never the file content.
        assert [c[3].get("fields") for c in data_calls(fake)] == [
            ["name", "mimetype", "file_size", "res_model", "res_id"]]

    def test_list_models_hides_unreachable_models(self, env) -> None:
        _, fake, d = env
        fake.responses[("ir.model", "search_read")] = [
            {"id": 1, "model": "res.partner", "name": "Contact", "transient": False},
            {"id": 2, "model": "ir.cron", "name": "Cron", "transient": False},
            {"id": 3, "model": "account.move", "name": "Entry", "transient": False}]
        _, body = call(d, "list_models")
        assert [m["model"] for m in body["models"]] == ["res.partner"]

    def test_attachment_size_limit(self, env) -> None:
        runtime, fake, d = env
        too_big = base64.b64encode(b"x" * (11 * 1024 * 1024)).decode()
        is_error, body = call(d, "upload_attachment", model="res.partner", record_id=1,
                              filename="big.bin", data_base64=too_big)
        assert is_error and "MB limit" in body and data_calls(fake) == []

    def test_invalid_base64_is_rejected(self, env) -> None:
        _, fake, d = env
        is_error, body = call(d, "upload_attachment", model="res.partner", record_id=1,
                              filename="a", data_base64="@@@not base64@@@")
        assert is_error and "base64" in body and data_calls(fake) == []

    def test_argument_errors_are_audited(self, env) -> None:
        """Malformed calls feed the repeated-errors detector, so they must be
        recorded even though they never reached the guard."""
        runtime, fake, d = env
        call(d, "get_record", model="res.partner")
        event = runtime.audit.tail(1)[0]
        assert event.error_type == "ToolInputError" and event.decision is Decision.ALLOW

    def test_agent_is_not_told_why_risk_blocked_it(self, env) -> None:
        """Policy reasons are explained; detector signals are not. An injected
        agent that learns '3 deletes in 60s' will do two."""
        runtime, fake, d = env
        fake.responses[("res.partner", "unlink")] = True
        texts = [call(d, "delete_record", model="res.partner", record_id=i)[1]
                 for i in range(1, 10)]
        refused = [t for t in texts if isinstance(t, str)]
        assert refused, "the burst should have been stopped"
        for text in refused:
            assert "delete_burst" not in text and "threshold" not in text
            assert "unusual" in text
