"""Numbers for the live dashboard, computed from the audit log.

Pure functions of a list of events, so the charts are as trustworthy as the
log they are drawn from and as easy to test.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from ..governance import AuditEvent, Decision
from ..governance.policy import reason_code

_CATEGORIES = {
    "model_denied": "denylist",
    "model_not_allowed": "not allowed",
    "model_not_writable": "not allowed",
    "model_not_deletable": "not allowed",
    "tool_disabled": "not allowed",
    "execute_disabled": "not allowed",
    "method_not_allowed": "not allowed",
    "method_blocked": "methods",
    "method_private": "methods",
    "method_required": "methods",
    "sensitive_field": "sensitive",
    "attachment_content": "sensitive",
    "risk_block": "risk",
    "panic_stop": "operator",
    "actor_blocked": "operator",
    "profile_read_only": "production",
    "privileged_wildcard": "production",
    "auth_failed": "auth",
    "volume_exceeded": "volume",
}

CATEGORY_ORDER = ("denylist", "sensitive", "risk", "operator", "production", "methods",
                  "not allowed", "auth", "volume", "other")


def categorise(reasons: tuple[str, ...]) -> str:
    """The headline kind of a refusal, from its first recognised reason."""
    for reason in reasons:
        category = _CATEGORIES.get(reason_code(reason))
        if category:
            return category
    return "other"


def _is_agent_event(event: AuditEvent) -> bool:
    return not event.tool.startswith("admin.") and event.tool != "self_check"


def summarise(events: list[AuditEvent], *, now: datetime, hours: int = 24) -> dict[str, Any]:
    start = (now - timedelta(hours=hours - 1)).replace(minute=0, second=0, microsecond=0)
    buckets = [
        {"start": start + timedelta(hours=i), "allowed": 0, "flagged": 0, "denied": 0}
        for i in range(hours)
    ]
    by_category: Counter[str] = Counter()
    models: Counter[str] = Counter()
    total = denied = flagged = 0
    for event in events:
        if not _is_agent_event(event) or event.ts < start:
            continue
        index = int((event.ts - start).total_seconds() // 3600)
        if not 0 <= index < hours:
            continue
        total += 1
        if event.decision is Decision.DENY:
            denied += 1
            buckets[index]["denied"] += 1
            by_category[categorise(event.reasons)] += 1
        elif event.decision in (Decision.ALLOW_FLAGGED, Decision.THROTTLE):
            flagged += 1
            buckets[index]["flagged"] += 1
        else:
            buckets[index]["allowed"] += 1
        if event.model and event.decision is not Decision.DENY:
            models[event.model] += 1
    ordered = {c: by_category[c] for c in CATEGORY_ORDER if by_category[c]}
    return {
        "total": total,
        "denied": denied,
        "flagged": flagged,
        "by_category": ordered,
        "hours": buckets,
        "top_models": models.most_common(6),
    }
