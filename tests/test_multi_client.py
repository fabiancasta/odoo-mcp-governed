"""Several clients on one installation.

A token can be pinned to a profile: that agent always works on that Odoo,
whatever profile the panel has active, and switching the active profile can
never point it at another client's database. The activity report can be
produced per profile, so each client gets its own.
"""

from __future__ import annotations

from dataclasses import replace

from fastapi.testclient import TestClient

from odoo_mcp_governed.runtime import Runtime, Snapshot
from odoo_mcp_governed.web.app import create_app
from odoo_mcp_governed.web.auth import issue_token, verify_token

from .test_http import login, make_settings, rpc
from .test_tools import FakeOdoo


def two_clients(tmp_path):
    runtime = Runtime(make_settings(tmp_path, odoo_environment="development",
                                    allowed_models="res.partner"))
    default = runtime.profiles.active()
    runtime.save_profile(replace(default, name="cliente-b", database="db_b"), actor="admin")
    fakes = {"default": FakeOdoo(), "cliente-b": FakeOdoo()}
    for name, fake in fakes.items():
        fake.responses[("res.partner", "search_count")] = 1 if name == "default" else 2
    runtime._snapshot_factory = lambda profile: Snapshot(profile, fakes[profile.name])
    runtime._snapshot = Snapshot(runtime.profiles.active(), fakes["default"])
    return runtime, fakes


def count_with(client, runtime, profile=None):
    token = issue_token(runtime.settings, "agent", profile=profile)["token"]
    response = client.post("/mcp", headers={"Authorization": f"Bearer {token}"}, json=rpc(
        "tools/call", {"name": "search_count", "arguments": {"model": "res.partner"}}))
    return response.json()["result"]


def test_pinned_tokens_carry_their_profile(tmp_path) -> None:
    runtime, _ = two_clients(tmp_path)
    claims = verify_token(runtime.settings, issue_token(runtime.settings, "a",
                                                        profile="cliente-b")["token"])
    assert claims["profile"] == "cliente-b"


def test_a_pinned_agent_stays_on_its_odoo_whatever_is_active(tmp_path) -> None:
    runtime, fakes = two_clients(tmp_path)
    client = TestClient(create_app(runtime))
    assert '"count": 2' in count_with(client, runtime, "cliente-b")["content"][0]["text"]
    assert '"count": 1' in count_with(client, runtime)["content"][0]["text"]
    assert fakes["cliente-b"].calls and fakes["default"].calls
    events = runtime.audit.store.tail(2)
    assert {e.profile for e in events} == {"default", "cliente-b"}


def test_a_pin_to_a_deleted_profile_is_refused_not_rerouted(tmp_path) -> None:
    runtime, fakes = two_clients(tmp_path)
    client = TestClient(create_app(runtime))
    token = issue_token(runtime.settings, "agent", profile="gone")["token"]
    result = client.post("/mcp", headers={"Authorization": f"Bearer {token}"}, json=rpc(
        "tools/call", {"name": "search_count", "arguments": {"model": "res.partner"}}
    )).json()["result"]
    assert result["isError"] and "gone" in result["content"][0]["text"]
    assert not fakes["default"].calls


def test_panel_issues_pinned_tokens_and_per_client_reports(tmp_path) -> None:
    runtime, _ = two_clients(tmp_path)
    client = TestClient(create_app(runtime))
    csrf = login(client)
    assert "cliente-b" in client.get("/token").text
    client.post("/admin/token/regenerate", data={
        "csrf": csrf, "actor": "bot-b", "profile": "cliente-b", "confirm": "yes"})
    stored = verify_token(runtime.settings, client.get("/token").text.split(
        'class="mono">')[1].split("<")[0])
    assert stored["profile"] == "cliente-b" and stored["sub"] == "bot-b"

    count_with(client, runtime, "cliente-b")
    report = client.get("/admin/report?profile=cliente-b").text
    assert "db_b" in report
