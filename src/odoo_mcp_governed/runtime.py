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
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
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
from .odoo import OdooClient, TTLCache
from .policy_store import PolicyStore, policy_from_settings
from .profiles import Profile, ProfileError, ProfileStore

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Snapshot:
    profile: Profile
    client: OdooClient


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
        self.audit = AuditLog(AuditStore(settings.audit_db), hmac_key=settings.hmac_key())
        self.engine = GovernanceEngine(
            self.audit,
            PolicyEngine(self._effective_policy(self.policy_store.config)),
            detector_config=settings.detector_config(),
            risk_config=settings.risk_config(),
        )
        self.cache = TTLCache(
            ttl=settings.cache_ttl,
            max_size=settings.cache_max_size,
            enabled=settings.cache_enabled,
        )
        self._lock = threading.Lock()
        self._snapshot: Snapshot | None = None
        self._rebuild_snapshot()

    # -- profile hot swap --------------------------------------------------

    def _effective_policy(self, config: PolicyConfig) -> PolicyConfig:
        """The edited policy plus what the profiles impose (read-only ones)."""
        return replace(config, read_only_profiles=self.profiles.read_only_names())

    def _apply_policy(self) -> None:
        # One attribute assignment, so no call sees half a policy.
        self.engine.policy = PolicyEngine(self._effective_policy(self.policy_store.config))

    def _rebuild_snapshot(self) -> None:
        profile = self.profiles.active()
        with self._lock:
            self._snapshot = Snapshot(profile, _client_for(profile)) if profile else None
        self.cache.clear()

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
            if saved.name == self.profiles.active_name:
                # Editing the active profile is also a swap: new credentials or
                # a new URL must take effect on the next call.
                self._rebuild_snapshot()
        return saved

    def delete_profile(self, name: str, *, actor: str) -> None:
        with self.admin_action(actor, "admin.profile.delete", detail=name):
            self.profiles.delete(name)
            self._apply_policy()

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
