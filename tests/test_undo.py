"""One-click undo from the change journal.

Undo is an administrator action: it is sealed into the audit chain with the
ids it touched, never runs through the risk engine, refuses to act on a
different Odoo than the one the change was made on, and cannot run twice.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from odoo_mcp_governed.runtime import Runtime, Snapshot, UndoError
from odoo_mcp_governed.web.app import create_app

from .test_http import login, make_settings
from .test_tools import FakeOdoo

FIELDS = {
    "name": {"type": "char", "readonly": False},
    "city": {"type": "char", "readonly": False},
    "country_id": {"type": "many2one", "readonly": False},
    "category_id": {"type": "many2many", "readonly": False},
    "child_ids": {"type": "one2many", "readonly": False},
    "display_name": {"type": "char", "readonly": True},
    "create_date": {"type": "datetime", "readonly": True},
}


@pytest.fixture
def setup(tmp_path):
    runtime = Runtime(make_settings(tmp_path, odoo_environment="development"))
    fake = FakeOdoo()
    fake.responses[("res.partner", "fields_get")] = FIELDS
    runtime._snapshot = Snapshot(runtime.profiles.active(), fake)
    return runtime, fake


def journal(runtime, operation, record_id, before, after) -> int:
    runtime.journal.add(
        audit_seq=1, ts=datetime.now(timezone.utc), actor="claude",
        profile=runtime.profile_name, model="res.partner", operation=operation,
        changes={record_id: (before, after)},
    )
    return runtime.journal.tail(1)[0]["id"]


def odoo_writes(fake):
    return [(m, meth, a) for m, meth, a, _k in fake.calls if meth in ("write", "create", "unlink")]


class TestUndo:
    def test_a_write_is_reverted_to_its_old_values(self, setup) -> None:
        runtime, fake = setup
        change = journal(runtime, "write", 16,
                         {"city": "Medellín", "country_id": [49, "Colombia"],
                          "category_id": [1, 2]},
                         {"city": "Cocorná"})
        runtime.undo_change(change, actor="admin@test")
        assert odoo_writes(fake) == [
            ("res.partner", "write",
             [[16], {"city": "Medellín", "country_id": 49, "category_id": [(6, 0, [1, 2])]}])
        ]

    def test_a_create_is_reverted_by_deleting_the_record(self, setup) -> None:
        runtime, fake = setup
        change = journal(runtime, "create", 43, None, {"name": "N"})
        runtime.undo_change(change, actor="admin@test")
        assert odoo_writes(fake) == [("res.partner", "unlink", [[43]])]

    def test_a_delete_is_reverted_by_recreating_the_record(self, setup) -> None:
        runtime, fake = setup
        fake.responses[("res.partner", "create")] = 77
        change = journal(runtime, "unlink", 9,
                         {"name": "Gone", "display_name": "Gone", "create_date": "2026-01-01",
                          "child_ids": [3], "country_id": False}, None)
        result = runtime.undo_change(change, actor="admin@test")
        assert odoo_writes(fake) == [
            ("res.partner", "create", [{"name": "Gone", "country_id": False}])
        ]
        assert result["new_id"] == 77

    def test_undo_runs_once(self, setup) -> None:
        runtime, _ = setup
        change = journal(runtime, "write", 16, {"city": "A"}, {"city": "B"})
        runtime.undo_change(change, actor="admin@test")
        with pytest.raises(UndoError, match="already"):
            runtime.undo_change(change, actor="admin@test")
        assert runtime.journal.get(change)["undone_at"]

    def test_undo_refuses_another_profile(self, setup) -> None:
        runtime, fake = setup
        runtime.journal.add(
            audit_seq=1, ts=datetime.now(timezone.utc), actor="claude", profile="elsewhere",
            model="res.partner", operation="write", changes={16: ({"city": "A"}, {"city": "B"})},
        )
        with pytest.raises(UndoError, match="elsewhere"):
            runtime.undo_change(runtime.journal.tail(1)[0]["id"], actor="admin@test")
        assert odoo_writes(fake) == []

    def test_undo_refuses_a_read_only_profile(self, tmp_path) -> None:
        runtime = Runtime(make_settings(tmp_path))  # unlabelled: production, read-only
        fake = FakeOdoo()
        runtime._snapshot = Snapshot(runtime.profiles.active(), fake)
        change = journal(runtime, "write", 16, {"city": "A"}, {"city": "B"})
        with pytest.raises(UndoError, match="read-only"):
            runtime.undo_change(change, actor="admin@test")
        assert odoo_writes(fake) == []

    def test_undo_is_audited_with_the_record_ids(self, setup) -> None:
        runtime, _ = setup
        change = journal(runtime, "write", 16, {"city": "A"}, {"city": "B"})
        runtime.undo_change(change, actor="admin@test")
        event = runtime.audit.store.tail(1)[0]
        assert event.tool == "admin.change.undo"
        assert event.record_ids == (16,)
        assert runtime.audit.verify().intact


def test_panel_undo_needs_confirmation(setup) -> None:
    runtime, fake = setup
    client = TestClient(create_app(runtime))
    csrf = login(client)
    change = journal(runtime, "write", 16, {"city": "A"}, {"city": "B"})
    assert "Undo" in client.get("/admin/changes").text
    client.post("/admin/changes/undo", data={"csrf": csrf, "change_id": str(change)},
                follow_redirects=False)
    assert odoo_writes(fake) == []
    client.post("/admin/changes/undo",
                data={"csrf": csrf, "change_id": str(change), "confirm": "yes"},
                follow_redirects=False)
    assert odoo_writes(fake) == [("res.partner", "write", [[16], {"city": "A"}])]
    assert "undone" in client.get("/admin/changes").text
