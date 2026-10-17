"""M5: which records a call changed, and what they looked like before.

The audit log said "update_record on res.partner, 1 record" but not which
record, so it could not answer the first question anyone asks after an
incident. Record ids now go into the hashed audit event, and a separate
change journal keeps before and after values — separate because the audit
log deliberately holds no values, and the journal deliberately does.
"""

from __future__ import annotations

import os
import sqlite3
import stat

from odoo_mcp_governed.governance import AuditLog, AuditStore, Operation, ToolCall
from odoo_mcp_governed.governance.events import Decision, Outcome
from odoo_mcp_governed.governance.store import _SCHEMA

from .test_tools import (
    call,
    env,  # noqa: F401 - shared fixture
)


def last_event(runtime):
    return runtime.audit.store.tail(1)[0]


class TestRecordIdsInTheAudit:
    def test_update_records_its_ids(self, env) -> None:  # noqa: F811
        runtime, fake, d = env
        fake.responses[("res.partner", "read")] = [{"id": 3, "name": "Old"}, {"id": 4, "name": "B"}]
        assert not call(d, "update_record", model="res.partner", ids=[3, 4],
                        values={"name": "New"})[0]
        assert last_event(runtime).record_ids == (3, 4)

    def test_create_records_the_new_id(self, env) -> None:  # noqa: F811
        runtime, fake, d = env
        fake.responses[("res.partner", "create")] = 42
        assert not call(d, "create_record", model="res.partner", values={"name": "N"})[0]
        assert last_event(runtime).record_ids == (42,)

    def test_delete_records_its_ids(self, env) -> None:  # noqa: F811
        runtime, fake, d = env
        fake.responses[("res.partner", "read")] = [{"id": 9, "name": "Gone"}]
        assert not call(d, "delete_record", model="res.partner", record_id=9)[0]
        assert last_event(runtime).record_ids == (9,)

    def test_ids_are_part_of_the_hashed_chain(self, env) -> None:  # noqa: F811
        runtime, fake, d = env
        fake.responses[("res.partner", "read")] = [{"id": 3, "name": "x"}]
        call(d, "update_record", model="res.partner", record_id=3, values={"name": "y"})
        store = runtime.audit.store
        with store.lock:
            store._conn.execute(
                "UPDATE audit_events SET record_ids = '[99]' WHERE seq = ?",
                (last_event(runtime).seq,),
            )
            store._conn.commit()
        assert not runtime.audit.verify().intact


class TestJournal:
    def test_update_keeps_before_and_after(self, env) -> None:  # noqa: F811
        runtime, fake, d = env
        fake.responses[("res.partner", "read")] = [{"id": 3, "name": "Old", "email": "a@x"}]
        call(d, "update_record", model="res.partner", record_id=3, values={"name": "New"})
        seq = last_event(runtime).seq
        [change] = runtime.journal.for_seq(seq)
        assert change["record_id"] == 3
        assert change["operation"] == "write"
        assert change["before"] == {"name": "Old"}
        assert change["after"] == {"name": "New"}

    def test_delete_keeps_a_snapshot_without_secrets(self, env) -> None:  # noqa: F811
        runtime, fake, d = env
        fake.responses[("res.partner", "read")] = [
            {"id": 9, "name": "Gone", "email": "g@x", "signup_token": "t0k"}
        ]
        call(d, "delete_record", model="res.partner", record_id=9)
        [change] = runtime.journal.for_seq(last_event(runtime).seq)
        assert change["before"] == {"name": "Gone", "email": "g@x"}
        assert change["after"] is None

    def test_create_keeps_the_values(self, env) -> None:  # noqa: F811
        runtime, fake, d = env
        fake.responses[("res.partner", "create")] = [43]
        call(d, "create_record", model="res.partner", values={"name": "N", "city": "Cocorná"})
        [change] = runtime.journal.for_seq(last_event(runtime).seq)
        assert change["record_id"] == 43
        assert change["before"] is None
        assert change["after"] == {"name": "N", "city": "Cocorná"}

    def test_refused_calls_leave_no_journal_entry(self, env) -> None:  # noqa: F811
        runtime, _, d = env
        assert call(d, "update_record", model="product.template", record_id=1,
                    values={"name": "x"})[0]
        assert runtime.journal.tail() == []

    def test_journal_file_is_private(self, env) -> None:  # noqa: F811
        runtime, *_ = env
        mode = stat.S_IMODE(os.stat(runtime.settings.data_dir / "changes.db").st_mode)
        assert mode == 0o600


def test_an_existing_log_without_the_column_is_migrated(tmp_path) -> None:
    """Upgrading must not break verification of everything written before."""
    path = tmp_path / "audit.db"
    old_schema = _SCHEMA.replace(",\n    record_ids     TEXT", "")
    assert old_schema != _SCHEMA
    conn = sqlite3.connect(path)
    conn.executescript(old_schema)
    conn.close()

    log = AuditLog(AuditStore(path))
    probe = ToolCall(actor="a", profile="p", tool="t", operation=Operation.READ)
    log.record(probe, decision=Decision.ALLOW, outcome=Outcome.OK)
    log.record(probe, decision=Decision.ALLOW, outcome=Outcome.OK, record_ids=(1, 2))
    assert log.verify().intact
    assert log.store.tail(1)[0].record_ids == (1, 2)


def test_changes_page_shows_values_escaped_and_needs_login(tmp_path) -> None:
    from fastapi.testclient import TestClient

    from odoo_mcp_governed.runtime import Runtime
    from odoo_mcp_governed.web.app import create_app

    from .test_http import login, make_settings

    runtime = Runtime(make_settings(tmp_path))
    client = TestClient(create_app(runtime))
    from datetime import datetime, timezone
    runtime.journal.add(
        audit_seq=1, ts=datetime.now(timezone.utc), actor="claude", profile="local",
        model="res.partner", operation="write",
        changes={5: ({"name": "<script>x</script>"}, {"name": "Nuevo"})},
    )
    assert client.get("/admin/changes", follow_redirects=False).status_code == 303
    login(client)
    page = client.get("/admin/changes?model=res.partner&record_id=5").text
    assert "Nuevo" in page
    assert "<script>x" not in page and "&lt;script&gt;" in page
