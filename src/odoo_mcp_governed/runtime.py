"""Live server state: the active Odoo profile, its client, the cache, and the
governance engine — and the hot swap between profiles.

Every tool call starts by taking a :class:`Snapshot`: an immutable view of the
profile and client in force at that instant. A profile switch that lands
mid-call replaces the runtime's current snapshot, but the call already running
keeps the one it took, so it finishes against the database it started on. A
call never begins on one Odoo instance and ends on another.

Administrative changes — switching profile, editing a profile, changing policy,
logging into the panel — are themselves written to the audit chain. Governing
the agents while leaving the governors unrecorded would leave the most
privileged actions on the server as the only unaudited ones.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import Settings
from .governance import (
    AuditLog,
    AuditStore,
    Decision,
    GovernanceEngine,
    Operation,
    Outcome,
    PolicyConfig,
    PolicyEngine,
    ToolCall,
    digest_args,
)
from .governance.approvals import ApprovalStore
from .governance.detectors import DetectorConfig
from .governance.engine import RiskScorer
from .journal import ChangeJournal
from .notify import Notifier
from .odoo import OdooClient, TTLCache
from .policy_store import PolicyStore, policy_from_settings
from .profiles import Profile, ProfileError, ProfileStore
from .tuning import TuningStore

log = logging.getLogger(__name__)

ACTOR_NAME = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
"""The token subjects the panel and the CLI issue."""


SETTINGS_GROUP = "base.group_system"


@dataclass(frozen=True)
class Snapshot:
    profile: Profile
    client: OdooClient
    _facts: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    def settings_access(self) -> bool | None:
        """Whether the profile's Odoo user has Settings access, or ``None``
        when Odoo cannot say. A known answer is kept for the life of this
        snapshot — a profile edit or swap makes a new one; an unknown one is
        asked again next time, so an Odoo that was down is not held against
        the profile forever."""
        if "settings_access" not in self._facts:
            try:
                answer = self.client.execute(
                    "res.users", "has_group", [[self.client.uid], SETTINGS_GROUP]
                )
            except Exception:  # noqa: BLE001 - unknown is an answer here
                return None
            self._facts["settings_access"] = bool(answer)
        return self._facts["settings_access"]


class NoActiveProfile(RuntimeError):
    pass


def _client_for(profile: Profile) -> OdooClient:
    return OdooClient(
        profile.url,
        profile.database,
        profile.username,
        profile.secret,
        ssl_verify=profile.ssl_verify,
        timeout=profile.timeout,
    )


class Runtime:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        self.profiles = ProfileStore(settings.profiles_file, settings.protected_hosts)
        if settings.odoo_url and (settings.odoo_api_key or settings.odoo_password):
            try:
                created = self.profiles.bootstrap(
                    Profile(
                        name="default",
                        url=settings.odoo_url.rstrip("/"),
                        database=settings.odoo_db,
                        username=settings.odoo_username,
                        api_key=settings.odoo_api_key,
                        password=settings.odoo_password,
                        ssl_verify=settings.odoo_ssl_verify,
                        timeout=settings.odoo_timeout,
                        environment=settings.odoo_environment,
                        allow_writes=settings.odoo_allow_writes,
                    )
                )
                if created:
                    log.info("created profile 'default' from ODOO_* settings")
            except ProfileError as exc:
                log.warning("ODOO_* settings do not form a valid profile: %s", exc)

        self.policy_store = PolicyStore(settings.policy_file, policy_from_settings(settings))
        self._privileged: set[str] = set()
        self._privileged_lock = threading.Lock()
        self.audit = AuditLog(AuditStore(settings.audit_db), hmac_key=settings.hmac_key())
        self.journal = ChangeJournal(settings.journal_db) if settings.change_journal else None
        base_risk, base_detectors = settings.risk_config(), DetectorConfig()
        self.tuning = TuningStore(settings.data_dir / "tuning.json", {
            "risk_throttle_threshold": base_risk.throttle_threshold,
            "risk_block_threshold": base_risk.block_threshold,
            "delete_burst_threshold": base_detectors.delete_burst_threshold,
            "rate_threshold": base_detectors.rate_threshold,
            "half_life_minutes": int(base_risk.half_life.total_seconds() // 60),
        })
        self.approvals = ApprovalStore(
            settings.data_dir / "approvals.db",
            ttl=timedelta(minutes=max(1, settings.approval_ttl_minutes)),
        )
        self.notifier = Notifier(
            webhook_url=settings.approval_webhook_url,
            telegram_token=settings.telegram_bot_token,
            telegram_chat_id=settings.telegram_chat_id,
            panel_url=settings.mcp_public_url,
        )
        self.engine = GovernanceEngine(
            self.audit,
            PolicyEngine(self._effective_policy(self.policy_store.config)),
            detector_config=self._tuned_detectors(),
            risk_config=self._tuned_risk(),
            approvals=self.approvals,
        )
        self.engine.on_approval_request = self.notifier.approval_requested
        self.cache = TTLCache(
            ttl=settings.cache_ttl,
            max_size=settings.cache_max_size,
            enabled=settings.cache_enabled,
        )
        self._lock = threading.Lock()
        self._snapshot: Snapshot | None = None
        self._pinned: dict[str, Snapshot] = {}
        self._rebuild_snapshot()

    # -- profile hot swap --------------------------------------------------

    def _effective_policy(self, config: PolicyConfig) -> PolicyConfig:
        """The edited policy plus what the profiles impose: read-only ones, and
        production ones whose Odoo user turned out to have Settings access."""
        return replace(
            config,
            read_only_profiles=self.profiles.read_only_names(),
            sandbox_profiles=self.profiles.sandbox_names(),
            privileged_profiles=frozenset(self._privileged),
        )

    def note_privilege(self, profile: str, privileged: bool) -> None:
        """Record what a production profile's Odoo user can do, and re-apply
        the policy if that changed which profiles count as privileged."""
        with self._privileged_lock:
            before = profile in self._privileged
            if privileged == before:
                return
            if privileged:
                self._privileged.add(profile)
            else:
                self._privileged.discard(profile)
        self._apply_policy()

    def _apply_policy(self) -> None:
        # One attribute assignment, so no call sees half a policy.
        self.engine.policy = PolicyEngine(self._effective_policy(self.policy_store.config))

    def _snapshot_factory(self, profile: Profile) -> Snapshot:
        return Snapshot(profile, _client_for(profile))

    def _rebuild_snapshot(self) -> None:
        profile = self.profiles.active()
        with self._lock:
            self._snapshot = self._snapshot_factory(profile) if profile else None
            self._pinned.clear()
        self.cache.clear()

    def snapshot_for(self, profile_name: str | None) -> Snapshot:
        """The snapshot a call runs on: the active profile, or — for a token
        pinned to a profile — that profile, whatever is active. A pin to a
        profile that is gone or protected is refused, never rerouted: sending
        one client's agent to another client's Odoo is the failure this
        exists to prevent."""
        if not profile_name:
            return self.snapshot()
        active = self._snapshot
        if active is not None and active.profile.name == profile_name:
            return active
        with self._lock:
            snap = self._pinned.get(profile_name)
            if snap is None:
                profile = self.profiles.get(profile_name)
                if profile is None or self.profiles.is_protected(profile):
                    raise NoActiveProfile(
                        f"This agent's token is pinned to profile {profile_name!r}, which does "
                        "not exist or cannot be used. Ask the administrator for a new token."
                    )
                snap = self._pinned[profile_name] = self._snapshot_factory(profile)
            return snap

    def snapshot(self) -> Snapshot:
        snap = self._snapshot
        if snap is None:
            raise NoActiveProfile(
                "No Odoo profile is configured. Add one in the admin panel or set ODOO_*."
            )
        return snap

    @property
    def profile_name(self) -> str:
        snap = self._snapshot
        return snap.profile.name if snap else "-"

    def activate_profile(self, name: str, *, actor: str) -> Profile:
        with self.admin_action(actor, "admin.profile.activate", fields=("active",), detail=name):
            profile = self.profiles.activate(name)
            self._apply_policy()
            self._rebuild_snapshot()
        log.info("active profile switched to %r by %s", name, actor)
        return profile

    def save_profile(self, profile: Profile, *, actor: str) -> Profile:
        with self.admin_action(
            actor, "admin.profile.save", fields=("url", "database", "username"), detail=profile.name
        ):
            saved = self.profiles.save(profile)
            self._apply_policy()
            with self._lock:
                self._pinned.pop(saved.name, None)
            if saved.name == self.profiles.active_name:
                # Editing the active profile is also a swap: new credentials or
                # a new URL must take effect on the next call.
                self._rebuild_snapshot()
        return saved

    def delete_profile(self, name: str, *, actor: str) -> None:
        with self.admin_action(actor, "admin.profile.delete", detail=name):
            self.profiles.delete(name)
            self._apply_policy()
            with self._lock:
                self._pinned.pop(name, None)

    # -- live policy -------------------------------------------------------

    def update_policy(
        self, changes: dict[str, Any], *, actor: str
    ) -> tuple[PolicyConfig, list[str]]:
        with self.admin_action(actor, "admin.policy.update", detail=changes) as action:
            config, changed = self.policy_store.update(changes)
            self._apply_policy()
            # Record *which* keys changed, so the chain says what was loosened.
            action.fields = tuple(changed)
            action.count = len(changed)
        for warning in config.validate():
            log.warning("policy: %s", warning)
        return config, changed

    # -- live thresholds (the console) ---------------------------------------

    def _tuned_risk(self):
        v = self.tuning.values
        return replace(
            self.settings.risk_config(),
            throttle_threshold=v["risk_throttle_threshold"],
            block_threshold=v["risk_block_threshold"],
            half_life=timedelta(minutes=v["half_life_minutes"]),
        )

    def _tuned_detectors(self) -> DetectorConfig:
        v = self.tuning.values
        return replace(
            self.settings.detector_config(),
            delete_burst_threshold=v["delete_burst_threshold"],
            rate_threshold=v["rate_threshold"],
        )

    def update_tuning(self, values: dict[str, Any], *, actor: str) -> list[str]:
        """Move the console's faders. Applies to the next call, persists, and
        is audited with the names of what changed."""
        with self.admin_action(actor, "admin.tuning.update", detail=values) as action:
            changed = self.tuning.update(values)
            # Attribute swaps: a call in progress finishes on the old values.
            self.engine.risk = RiskScorer(self._tuned_risk())
            self.engine.detector_config = self._tuned_detectors()
            action.fields = tuple(changed)
            action.count = len(changed)
        return changed

    # -- approvals -----------------------------------------------------------

    def decide_approval(self, request_id: int, approve: bool, *, actor: str) -> bool:
        tool = "admin.approval.approve" if approve else "admin.approval.deny"
        with self.admin_action(actor, tool, detail={"request_id": request_id}) as action:
            decided = self.approvals.decide(request_id, approve=approve, by=actor)
            action.count = 1 if decided else 0
        return decided

    # -- emergency controls ------------------------------------------------

    def set_panic(self, on: bool, *, actor: str) -> None:
        """Stop or resume every agent. Takes effect on the next call and is
        persisted, so a restart does not silently resume service."""
        with self.admin_action(actor, "admin.panic", detail={"panic": on}) as action:
            _, changed = self.policy_store.update({"panic": on})
            self._apply_policy()
            action.fields = ("panic",) if changed else ()
        log.warning("panic switch %s by %s", "ENGAGED" if on else "released", actor)

    def set_actor_blocked(self, name: str, blocked: bool, *, actor: str) -> None:
        name = name.strip()
        if not ACTOR_NAME.match(name):
            raise ValueError("agent names may only contain letters, digits and _ . @ -")
        current = set(self.policy_store.config.blocked_actors)
        current = current | {name} if blocked else current - {name}
        tool = "admin.actor.block" if blocked else "admin.actor.unblock"
        with self.admin_action(actor, tool, detail={"actor": name}) as action:
            self.policy_store.update({"blocked_actors": sorted(current)})
            self._apply_policy()
            action.count = 1

    # -- undo ----------------------------------------------------------------

    def undo_change(self, change_id: int, *, actor: str) -> dict[str, Any]:
        """Revert one journalled change on the Odoo it was made on.

        write  → write the old values back
        create → delete the record that was created
        unlink → create the record again from its snapshot (it gets a new id)
        """
        if self.journal is None:
            raise UndoError("the change journal is off (CHANGE_JOURNAL=false)")
        change = self.journal.get(change_id)
        if change is None:
            raise UndoError(f"change {change_id} does not exist")
        if change["undone_at"]:
            raise UndoError(f"change {change_id} was already undone at {change['undone_at']}")
        snapshot = self.snapshot()
        profile = snapshot.profile
        if change["profile"] != profile.name:
            raise UndoError(
                f"change {change_id} was made on profile {change['profile']!r}, but "
                f"{profile.name!r} is active; activate it first"
            )
        if profile.read_only:
            raise UndoError(f"profile {profile.name!r} is production and read-only")

        client = snapshot.client
        # Claim first, act second: two clicks racing each other cannot both
        # reach Odoo. A failed undo releases the claim so it can be retried.
        if not self.journal.mark_undone(
            change_id, by=actor, note="undo in progress", at=datetime.now(timezone.utc)
        ):
            raise UndoError(f"change {change_id} is already undone or being undone")
        try:
            result = self._apply_undo(change, client, actor)
        except Exception:
            self.journal.set_undo_note(change_id, None)
            raise
        self.journal.set_undo_note(change_id, result["note"])
        self.cache.clear()
        return result

    def _apply_undo(self, change: dict[str, Any], client: Any, actor: str) -> dict[str, Any]:
        model, record_id, operation = change["model"], change["record_id"], change["operation"]
        change_id = change["id"]
        detail = {"change_id": change_id, "operation": operation, "model": model}
        with self.admin_action(actor, "admin.change.undo", detail=detail) as action:
            action.count = 1
            action.record_ids = (record_id,)
            defs = client.execute(model, "fields_get", [], {"attributes": ["type", "readonly"]})
            result: dict[str, Any] = {"model": model, "record_id": record_id}
            if operation == "write":
                values = _restorable(change["before"] or {}, defs, for_create=False)
                if not values:
                    raise UndoError("nothing to restore: the old values were not recorded")
                action.fields = tuple(sorted(values))
                client.execute(model, "write", [[record_id], values])
                note = f"restored {', '.join(sorted(values))}"
            elif operation == "create":
                client.execute(model, "unlink", [[record_id]])
                note = "deleted the created record"
            elif operation == "unlink":
                values = _restorable(change["before"] or {}, defs, for_create=True)
                if not values:
                    raise UndoError("nothing to restore: no snapshot was taken before the delete")
                action.fields = tuple(sorted(values))
                created = client.execute(model, "create", [values])
                new_id = created[0] if isinstance(created, list) else created
                result["new_id"] = new_id
                action.record_ids = (record_id, new_id) if isinstance(new_id, int) else (
                    record_id,)
                note = f"recreated as id {new_id}"
            else:
                raise UndoError(f"cannot undo a {operation!r}")
        result["note"] = note
        return result

    # -- auditing administrative actions -----------------------------------

    def _admin_call(
        self, actor: str, tool: str, *, fields: tuple[str, ...] = (), detail: Any = None
    ) -> ToolCall:
        return ToolCall(
            actor=actor,
            profile=self.profile_name,
            tool=tool,
            operation=Operation.ADMIN,
            fields_touched=fields,
            arg_digest=digest_args(detail),
        )

    @contextmanager
    def admin_action(
        self, actor: str, tool: str, *, fields: tuple[str, ...] = (), detail: Any = None
    ) -> Iterator[_AdminAction]:
        """Record an administrative change in the audit chain.

        Deliberately *not* run through the risk engine. Administrators are
        authenticated by password, and the moment they most need the panel —
        switching a tool off at 03:00 during an incident — is exactly when
        off-hours signals would be piling up. Response must never depend on a
        score. Every change is still sealed into the same chain as agent
        calls, success or failure.
        """
        action = _AdminAction(fields=fields)
        started = time.perf_counter()
        try:
            yield action
        except Exception as exc:
            self.audit.record(
                self._admin_call(actor, tool, fields=action.fields, detail=detail),
                decision=Decision.ALLOW,
                outcome=Outcome.ERROR,
                error_type=type(exc).__name__,
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
            raise
        self.audit.record(
            self._admin_call(actor, tool, fields=action.fields, detail=detail),
            decision=Decision.ALLOW,
            outcome=Outcome.OK,
            affected_count=action.count,
            latency_ms=int((time.perf_counter() - started) * 1000),
            record_ids=action.record_ids,
        )

    def record_login(self, actor: str, *, success: bool) -> None:
        call = self._admin_call(actor, "admin.login")
        self.audit.record(
            call,
            decision=Decision.ALLOW if success else Decision.DENY,
            reasons=() if success else ("admin_login_failed: wrong admin password",),
            outcome=Outcome.OK if success else Outcome.DENIED,
        )


@dataclass
class _AdminAction:
    fields: tuple[str, ...] = ()
    count: int | None = None
    record_ids: tuple[int, ...] = ()


class UndoError(Exception):
    """An undo that cannot or must not run. The message is for the operator."""


def _restorable(values: dict[str, Any], defs: dict[str, Any], *, for_create: bool) -> dict:
    """Turn values as Odoo *read* them into values Odoo can *write* back.

    A many2one reads as ``[id, name]`` and writes as ``id``; a many2many reads
    as a list of ids and writes as a replace command. One2many lines belong to
    their own records and are not restored through the parent. Read-only
    fields — computed values, create_date — are skipped when recreating.
    """
    result: dict[str, Any] = {}
    for name, value in values.items():
        meta = defs.get(name) if isinstance(defs, dict) else None
        kind = (meta or {}).get("type")
        if kind == "one2many":
            continue
        if for_create and (meta is None or meta.get("readonly")):
            continue
        if kind == "many2one" and isinstance(value, list):
            value = value[0] if value else False
        elif kind == "many2many" and isinstance(value, list):
            value = [(6, 0, [v for v in value if isinstance(v, int)])]
        result[name] = value
    return result
