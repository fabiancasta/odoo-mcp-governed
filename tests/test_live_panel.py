"""The live dashboard: attack charts, the threshold console, and the one script.

The panel used to run no JavaScript at all. It now loads exactly one script,
served by the server itself (``script-src 'self'``: no inline code, nothing
from third parties), which only refreshes the charts and shows fader values.
Everything — including the panic switch and the console — still works with
JavaScript off, because every control is a plain form.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from odoo_mcp_governed.governance import Decision, Operation, Outcome, ToolCall
from odoo_mcp_governed.runtime import Runtime
from odoo_mcp_governed.web.app import create_app
from odoo_mcp_governed.web.metrics import categorise, summarise

from .test_http import login, make_settings


def record(runtime, *, decision=Decision.ALLOW, reasons=(), model="res.partner",
           when=None, actor="claude"):
    call = ToolCall(actor=actor, profile="p", tool="search_records",
                    operation=Operation.READ, model=model,
                    ts=when or datetime.now(timezone.utc))
    runtime.audit.record(call, decision=decision, reasons=reasons,
                         outcome=Outcome.DENIED if decision is Decision.DENY else Outcome.OK)


class TestMetrics:
    def test_refusals_are_grouped_by_kind(self) -> None:
        assert categorise(("model_denied: x",)) == "denylist"
        assert categorise(("sensitive_field: x",)) == "sensitive"
        assert categorise(("attachment_content: x",)) == "sensitive"
        assert categorise(("risk_block: x",)) == "risk"
        assert categorise(("panic_stop: x",)) == "operator"
        assert categorise(("auth_failed: x",)) == "auth"
        assert categorise(("model_not_allowed: x",)) == "not allowed"

    def test_summary_buckets_the_last_24_hours(self, tmp_path) -> None:
        runtime = Runtime(make_settings(tmp_path))
        now = datetime.now(timezone.utc)
        record(runtime)
        record(runtime, decision=Decision.DENY, reasons=("model_denied: ir.cron",),
               model="ir.cron")
        record(runtime, decision=Decision.DENY, reasons=("sensitive_field: password",))
        record(runtime, when=now - timedelta(hours=30))
        summary = summarise(runtime.audit.since(now - timedelta(hours=24)), now=now)
        assert summary["total"] >= 3
        assert summary["denied"] == 2
        assert summary["by_category"] == {"denylist": 1, "sensitive": 1}
        assert len(summary["hours"]) == 24
        assert sum(h["denied"] for h in summary["hours"]) == 2


class TestPanel:
    def test_one_script_from_self_and_no_inline_code(self, tmp_path) -> None:
        client = TestClient(create_app(Runtime(make_settings(tmp_path))))
        login(client)
        response = client.get("/admin")
        csp = response.headers["content-security-policy"]
        assert "script-src 'self'" in csp
        assert "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]
        assert re.findall(r"<script(?![^>]*\bsrc=)", response.text) == []
        script = client.get("/static/panel.js")
        assert script.status_code == 200
        assert "javascript" in script.headers["content-type"]

    def test_charts_render_without_javascript(self, tmp_path) -> None:
        runtime = Runtime(make_settings(tmp_path))
        record(runtime, decision=Decision.DENY, reasons=("model_denied: ir.cron",),
               model="ir.cron")
        client = TestClient(create_app(runtime))
        login(client)
        page = client.get("/admin").text
        assert "<svg" in page and "Blocked attempts" in page and "denylist" in page

    def test_live_fragment_needs_a_session(self, tmp_path) -> None:
        client = TestClient(create_app(Runtime(make_settings(tmp_path))))
        assert client.get("/admin/live", follow_redirects=False).status_code in (303, 401)
        login(client)
        fragment = client.get("/admin/live")
        assert fragment.status_code == 200 and "<svg" in fragment.text


class TestConsole:
    def test_thresholds_apply_live_persist_and_are_audited(self, tmp_path) -> None:
        runtime = Runtime(make_settings(tmp_path))
        client = TestClient(create_app(runtime))
        csrf = login(client)
        response = client.post("/admin/tuning", data={
            "csrf": csrf, "risk_throttle_threshold": "30", "risk_block_threshold": "60",
            "delete_burst_threshold": "5", "rate_threshold": "200", "half_life_minutes": "10",
        }, follow_redirects=False)
        assert response.status_code == 303
        assert runtime.engine.risk.config.throttle_threshold == 30
        assert runtime.engine.risk.config.block_threshold == 60
        assert runtime.engine.risk.config.half_life == timedelta(minutes=10)
        assert runtime.engine.detector_config.delete_burst_threshold == 5
        assert runtime.engine.detector_config.rate_threshold == 200
        assert any(e.tool == "admin.tuning.update" for e in runtime.audit.store.iter_all())

        restarted = Runtime(make_settings(tmp_path))
        assert restarted.engine.risk.config.block_threshold == 60
        assert restarted.engine.detector_config.delete_burst_threshold == 5

    def test_nonsense_is_refused(self, tmp_path) -> None:
        runtime = Runtime(make_settings(tmp_path))
        client = TestClient(create_app(runtime))
        csrf = login(client)
        client.post("/admin/tuning", data={
            "csrf": csrf, "risk_throttle_threshold": "80", "risk_block_threshold": "50",
            "delete_burst_threshold": "3", "rate_threshold": "90", "half_life_minutes": "15",
        })
        assert runtime.engine.risk.config.block_threshold == 70, "throttle must stay below block"
