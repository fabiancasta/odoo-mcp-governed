"""Human approval for destructive or bulk operations.

The agent's call is refused with a request number; an operator approves it
in the panel; the agent repeats the *same* call (same arguments, so the same
digest) within the approval window and it goes through once. Notifications
carry no record values — only who wants to do what to which model.
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from odoo_mcp_governed.governance import (
    DetectorConfig,
    GovernanceDenied,
    GovernanceEngine,
    Operation,
    PolicyConfig,
    PolicyEngine,
    RiskConfig,
)
from odoo_mcp_governed.governance.approvals import ApprovalStore
from odoo_mcp_governed.notify import Notifier
from odoo_mcp_governed.runtime import Runtime
from odoo_mcp_governed.web.app import create_app

from .conftest import FakeClock, make_call
from .test_http import bearer, login, make_settings, rpc

POLICY = PolicyConfig(
    allowed_models=frozenset({"*"}), writable_models=frozenset({"*"}),
    deletable_models=frozenset({"*"}), approval_required=frozenset({"delete", "bulk"}),
    approval_bulk_threshold=20,
)


@pytest.fixture
def engine(audit, clock: FakeClock):
    store = ApprovalStore(":memory:", now_fn=clock)
    return GovernanceEngine(
        audit=audit, policy=PolicyEngine(POLICY),
        detector_config=DetectorConfig(business_timezone="UTC"),
        risk_config=RiskConfig(throttle_seconds=0), now_fn=clock, approvals=store,
    ), store


def delete(clock, digest="d1"):
    call = make_call(clock, tool="delete_record", operation=Operation.DELETE,
                     model="res.partner", record_count=1)
    return type(call)(**{**call.__dict__, "arg_digest": digest})


def run(engine, call) -> str:
    try:
        with engine.guard(call) as g:
            g.affected(1)
        return "ran"
    except GovernanceDenied as denied:
        return denied.judgement.explain()


class TestFlow:
    def test_refused_then_approved_then_runs_once(self, engine, clock) -> None:
        eng, store = engine
        first = run(eng, delete(clock))
        assert "approval_required" in first and "#1" in first
        [pending] = store.pending()
        assert pending["tool"] == "delete_record" and pending["model"] == "res.partner"

        store.decide(pending["id"], approve=True, by="admin@test")
        assert run(eng, delete(clock)) == "ran"
        assert "approval_required" in run(eng, delete(clock)), "an approval is single-use"

    def test_an_approval_covers_only_the_same_arguments(self, engine, clock) -> None:
        eng, store = engine
        run(eng, delete(clock, "d1"))
        store.decide(store.pending()[0]["id"], approve=True, by="admin")
        assert "approval_required" in run(eng, delete(clock, "other-args"))

    def test_repeating_while_pending_does_not_spam_requests(self, engine, clock) -> None:
        eng, store = engine
        for _ in range(4):
            run(eng, delete(clock))
        assert len(store.pending()) == 1

    def test_a_denied_request_stays_denied(self, engine, clock) -> None:
        eng, store = engine
        run(eng, delete(clock))
        store.decide(store.pending()[0]["id"], approve=False, by="admin")
        message = run(eng, delete(clock))
        assert "denied" in message and store.pending() == []

    def test_approvals_expire(self, engine, clock) -> None:
        eng, store = engine
        run(eng, delete(clock))
        store.decide(store.pending()[0]["id"], approve=True, by="admin")
        clock.advance(minutes=31)
        assert "approval_required" in run(eng, delete(clock))

    def test_bulk_writes_need_approval_small_ones_do_not(self, engine, clock) -> None:
        eng, _ = engine
        small = make_call(clock, tool="update_record", operation=Operation.WRITE,
                          model="res.partner", record_count=5)
        bulk = make_call(clock, tool="update_record", operation=Operation.WRITE,
                         model="res.partner", record_count=25)
        assert run(eng, small) == "ran"
        assert "approval_required" in run(eng, bulk)

    def test_sandbox_profiles_skip_approval(self, audit, clock) -> None:
        from dataclasses import replace
        store = ApprovalStore(":memory:", now_fn=clock)
        eng = GovernanceEngine(
            audit=audit, policy=PolicyEngine(replace(POLICY, sandbox_profiles=frozenset({"lab"}))),
            detector_config=DetectorConfig(business_timezone="UTC"),
            risk_config=RiskConfig(throttle_seconds=0), now_fn=clock, approvals=store,
        )
        call = make_call(clock, tool="delete_record", operation=Operation.DELETE,
                         model="res.partner", profile="lab")
        assert run(eng, call) == "ran"


class TestNotifier:
    def test_webhook_gets_who_what_where_but_no_values(self, monkeypatch) -> None:
        sent = []

        class FakeResponse:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b"ok"

        def fake_urlopen(request, timeout):
            sent.append((request.full_url, json.loads(request.data)))
            return FakeResponse()

        monkeypatch.setattr("odoo_mcp_governed.notify.urllib.request.urlopen", fake_urlopen)
        notifier = Notifier(webhook_url="https://hooks.example/approve",
                            panel_url="http://127.0.0.1:8020", background=False)
        notifier.approval_requested({"id": 7, "actor": "claude", "tool": "delete_record",
                                     "model": "res.partner", "record_count": 3,
                                     "profile": "local"})
        [(url, body)] = sent
        assert url == "https://hooks.example/approve"
        assert body["request_id"] == 7 and "res.partner" in body["text"]
        assert body["approve_url"].endswith("/admin/approvals")


def test_panel_lists_and_approves(tmp_path) -> None:
    runtime = Runtime(make_settings(
        tmp_path, odoo_environment="development", allowed_models="*", writable_models="*",
        deletable_models="*",
    ))
    runtime.update_policy({"approval_required": "delete"}, actor="admin@test")
    client = TestClient(create_app(runtime))
    csrf = login(client)
    response = client.post("/mcp", headers=bearer(runtime, "claude"), json=rpc(
        "tools/call", {"name": "delete_record", "arguments": {"model": "res.partner",
                                                              "record_id": 5}}))
    text = response.json()["result"]["content"][0]["text"]
    assert "approval" in text
    page = client.get("/admin/approvals").text
    assert "delete_record" in page and "claude" in page
    request_id = runtime.approvals.pending()[0]["id"]
    client.post("/admin/approvals/decide", data={"csrf": csrf, "id": str(request_id),
                                                 "decision": "approve"},
                follow_redirects=False)
    assert runtime.approvals.get(request_id)["status"] == "approved"
    assert any(e.tool == "admin.approval.approve" for e in runtime.audit.store.iter_all())
    assert timedelta(minutes=30) == runtime.approvals.ttl
