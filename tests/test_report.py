"""The activity report: counts and metadata a business owner can read."""

from __future__ import annotations

from fastapi.testclient import TestClient

from odoo_mcp_governed.__main__ import main
from odoo_mcp_governed.runtime import Runtime, Snapshot
from odoo_mcp_governed.web.app import create_app

from .test_http import bearer, login, make_settings, rpc
from .test_tools import FakeOdoo


def busy_runtime(tmp_path):
    runtime = Runtime(make_settings(tmp_path, odoo_environment="development",
                                    allowed_models="res.partner", writable_models="res.partner"))
    fake = FakeOdoo()
    fake.responses[("res.partner", "read")] = [{"id": 16, "city": "Medellín"}]
    runtime._snapshot = Snapshot(runtime.profiles.active(), fake)
    client = TestClient(create_app(runtime))
    headers = bearer(runtime, "claude")
    for name, args in (
        ("search_count", {"model": "res.partner"}),
        ("update_record", {"model": "res.partner", "record_id": 16,
                           "values": {"city": "Cocorná"}}),
        ("search_count", {"model": "ir.cron"}),
    ):
        client.post("/mcp", headers=headers, json=rpc("tools/call",
                                                      {"name": name, "arguments": args}))
    return runtime, client


def test_report_page_counts_without_values(tmp_path) -> None:
    runtime, client = busy_runtime(tmp_path)
    assert client.get("/admin/report", follow_redirects=False).status_code == 303
    login(client)
    page = client.get("/admin/report").text
    assert "AI activity report" in page and "claude" in page
    assert "denylist" in page, "the ir.cron attempt is reported as refused"
    assert "res.partner" in page and "write" in page
    assert "Cocorná" not in page and "Medellín" not in page, "no record values"
    assert "intact" in page


def test_report_command_writes_a_private_file(tmp_path, monkeypatch) -> None:
    busy_runtime(tmp_path)
    env = {"DATA_DIR": str(tmp_path), "ODOO_URL": "", "BUSINESS_TIMEZONE": "UTC"}
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "report.html"
    assert main(["report", "--days", "7", "--out", str(out)]) == 0
    assert "AI activity report" in out.read_text()
    assert oct(out.stat().st_mode & 0o777) == "0o600"
