"""The activity report: what the agents did, in a form a business owner reads.

Counts and metadata only — which agent, which model, how many records, what
was refused and why — never record values, so the report can be emailed to a
client or attached to an invoice for a managed service. Rendered as a single
self-contained HTML page with print styles; "Print → Save as PDF" makes the
PDF.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from .governance import Decision, Operation, Outcome
from .web.metrics import CATEGORY_ORDER, categorise


def build(
    runtime: Any, *, days: int = 7, now: datetime | None = None, profile: str | None = None
) -> dict[str, Any]:
    """The report for a period, for one profile (one client) or for all."""
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    events = runtime.audit.since(start)
    if profile:
        events = [e for e in events if e.profile == profile]
    agents: dict[str, Counter] = defaultdict(Counter)
    models: Counter[str] = Counter()
    refusals: Counter[str] = Counter()
    admin: Counter[str] = Counter()
    peak_risk = 0
    for e in events:
        if e.tool.startswith("admin.") or e.tool == "self_check":
            admin[e.tool] += 1
            continue
        stats = agents[e.actor]
        stats["calls"] += 1
        peak_risk = max(peak_risk, e.risk_score)
        if e.decision is Decision.DENY:
            stats["refused"] += 1
            refusals[categorise(e.reasons)] += 1
            continue
        if e.outcome is Outcome.ERROR:
            stats["errors"] += 1
        if e.operation is Operation.READ:
            stats["records_read"] += e.affected_count or 0
        elif e.operation in (Operation.CREATE, Operation.WRITE):
            stats["records_written"] += e.affected_count or 0
        elif e.operation is Operation.DELETE:
            stats["records_deleted"] += e.affected_count or 0
        if e.model:
            models[e.model] += 1

    def mine(row: dict) -> bool:
        return not profile or row.get("profile") == profile

    changes = []
    if runtime.journal is not None:
        changes = [c for c in runtime.journal.tail(5000)
                   if c["ts"] >= start.isoformat() and mine(c)]
    approvals = [a for a in runtime.approvals.recent(5000) + runtime.approvals.pending()
                 if a["created_at"] >= start.isoformat() and mine(a)]
    status = runtime.audit.verify()
    profile = runtime.profiles.get(profile) if profile else runtime.profiles.active()
    return {
        "generated_at": now,
        "start": start,
        "days": days,
        "profile": profile.name if profile else "—",
        "database": profile.database if profile else "—",
        "environment": profile.environment if profile else "—",
        "agents": sorted(((a, dict(c)) for a, c in agents.items()),
                         key=lambda x: -x[1].get("calls", 0)),
        "models": models.most_common(10),
        "refusals": {c: refusals[c] for c in CATEGORY_ORDER if refusals[c]},
        "changes": {
            "total": len(changes),
            "by_operation": dict(Counter(c["operation"] for c in changes)),
            "undone": sum(1 for c in changes if c.get("undone_at")),
            "latest": changes[:15],
        },
        "approvals": dict(Counter(a["status"] for a in approvals)),
        "panic_events": admin.get("admin.panic", 0),
        "blocks": admin.get("admin.actor.block", 0),
        "peak_risk": peak_risk,
        "chain_intact": status.intact,
        "chain_summary": status.summary(),
        "total_calls": sum(c.get("calls", 0) for _, c in agents.items()),
        "total_refused": sum(c.get("refused", 0) for _, c in agents.items()),
    }
