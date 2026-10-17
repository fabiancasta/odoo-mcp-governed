"""Odoo connection profiles, switchable at runtime.

A profile is one Odoo instance: URL, database, user, and a credential. Several
can be stored and exactly one is active. Switching is "hot": the next call
goes to the new instance without restarting the server.

Credential handling rules, all enforced here rather than in the admin UI so
that no future UI can get them wrong:

* Secrets never leave this module in a form meant for display.
  :meth:`Profile.public` is the only shape the admin panel ever renders, and
  it carries ``has_api_key``/``has_password`` booleans, not values.
* Editing a profile with an empty secret field keeps the stored secret. The
  browser never had it, so an empty field means "unchanged", not "erase".
* Profile names are restricted to ``A-Z a-z 0-9 _ . -``. Names end up in file
  content, HTML and log lines; a narrow charset makes all three safe without
  relying on every renderer escaping correctly.

Two production safeguards live here too:

* **Unlabelled means production.** Every profile has an ``environment``, and a
  profile loaded without one — the typical result of copying a profile file in
  from another tool — is treated as ``production``. Production profiles are
  read-only unless ``allow_writes`` is set on that profile explicitly. Writing
  to a test database requires saying it is a test database; forgetting to say
  so costs a refused write, not a deleted customer.
* **Protected hosts are unreachable.** ``PROTECTED_HOSTS`` names hosts this
  server must never talk to at all — not read-only, not at all. A profile
  pointing at one can be stored but never activated, and an active profile
  that turns out to point at one is deactivated on load.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import threading
from collections.abc import Iterable
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .storage import read_json, write_private_json

PROFILE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
ENVIRONMENTS = ("production", "staging", "development")

log = logging.getLogger(__name__)


def url_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def host_is_protected(url: str, protected: Iterable[str]) -> bool:
    """Whether ``url`` points at a protected host or any subdomain of one.

    ``erp.example.com`` protects ``crm.erp.example.com`` too; an IP
    entry matches that exact address (in any notation Python normalises).
    """
    host = url_host(url)
    if not host:
        return False
    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        host_ip = None
    for entry in protected:
        entry = entry.strip().lower().rstrip(".")
        if not entry:
            continue
        if host_ip is not None:
            try:
                if host_ip == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                pass
            continue
        if host == entry or host.endswith("." + entry):
            return True
    return False


class ProfileError(ValueError):
    """A profile operation was rejected. The message is safe to show a user."""


@dataclass(frozen=True)
class Profile:
    name: str
    url: str
    database: str
    username: str
    api_key: str = ""
    password: str = ""
    ssl_verify: bool = True
    timeout: float = 30.0
    environment: str = "production"
    allow_writes: bool = False
    """Only meaningful for production: lifts the read-only default. Should be
    rare, deliberate, and visible — the panel shows it in red."""
    sandbox: bool = False
    """Test databases and controlled activities: model lists do not apply and
    risk is only observed. Never allowed on production."""

    @property
    def read_only(self) -> bool:
        return self.environment == "production" and not self.allow_writes

    @property
    def secret(self) -> str:
        """The credential to authenticate with. API keys win over passwords:
        they can be scoped, rotated and revoked without touching the login."""
        return self.api_key or self.password

    def public(self) -> dict[str, Any]:
        """Everything safe to render. Never includes a secret."""
        return {
            "name": self.name,
            "url": self.url,
            "database": self.database,
            "username": self.username,
            "has_api_key": bool(self.api_key),
            "has_password": bool(self.password),
            "ssl_verify": self.ssl_verify,
            "timeout": self.timeout,
            "environment": self.environment,
            "allow_writes": self.allow_writes,
            "read_only": self.read_only,
            "sandbox": self.sandbox,
        }

    def validate(self) -> None:
        if not PROFILE_NAME.match(self.name):
            raise ProfileError(
                "Profile name may only contain letters, digits, '_', '.' and '-' (max 64)."
            )
        if not self.url.startswith(("http://", "https://")):
            raise ProfileError("URL must start with http:// or https://")
        if not self.database or not self.username:
            raise ProfileError("Database and username are required.")
        if not self.secret:
            raise ProfileError("An API key or a password is required.")
        if not (1 <= self.timeout <= 600):
            raise ProfileError("Timeout must be between 1 and 600 seconds.")
        if self.environment not in ENVIRONMENTS:
            raise ProfileError(f"Environment must be one of: {', '.join(ENVIRONMENTS)}.")
        if self.sandbox and self.environment == "production":
            raise ProfileError("A production profile can never be a sandbox.")


def _profile_from_dict(name: str, raw: dict[str, Any]) -> Profile:
    return Profile(
        name=name,
        url=str(raw.get("url", "")).rstrip("/"),
        database=str(raw.get("database") or raw.get("db") or ""),
        username=str(raw.get("username", "")),
        api_key=str(raw.get("api_key") or ""),
        password=str(raw.get("password") or ""),
        ssl_verify=bool(raw.get("ssl_verify", True)),
        timeout=float(raw.get("timeout", 30.0)),
        # Missing label: assume the worst. See the module docstring.
        environment=str(raw.get("environment") or "production"),
        allow_writes=bool(raw.get("allow_writes", False)),
        sandbox=bool(raw.get("sandbox", False)) and raw.get("environment") != "production",
    )


class ProfileStore:
    """Profiles persisted in ``profiles.json`` (mode 0600)."""

    def __init__(self, path: str | Path, protected_hosts: Iterable[str] = ()) -> None:
        self.path = Path(path)
        self.protected_hosts = frozenset(h.strip().lower() for h in protected_hosts if h.strip())
        self._lock = threading.RLock()
        self._profiles: dict[str, Profile] = {}
        self._active: str | None = None
        self._load()

    # -- persistence -------------------------------------------------------

    def _load(self) -> None:
        raw = read_json(self.path, default=None)
        if not raw:
            return
        # Accept {"active": ..., "profiles": {...}} and also a flat
        # {name: profile} mapping, so an existing profile file can be dropped in.
        profiles = raw.get("profiles") if isinstance(raw.get("profiles"), dict) else raw
        for name, data in profiles.items():
            if isinstance(data, dict) and PROFILE_NAME.match(name):
                self._profiles[name] = _profile_from_dict(name, data)
        active = raw.get("active")
        if isinstance(active, str) and active in self._profiles:
            self._active = active
        elif self._profiles:
            self._active = next(iter(sorted(self._profiles)))
        if self._active and self.is_protected(self._profiles[self._active]):
            log.error(
                "active profile %r points at a protected host (%s); starting with no "
                "active profile", self._active, url_host(self._profiles[self._active].url),
            )
            self._active = None

    def _save(self) -> None:
        write_private_json(
            self.path,
            {
                "active": self._active,
                "profiles": {
                    name: {k: v for k, v in asdict(p).items() if k != "name"}
                    for name, p in sorted(self._profiles.items())
                },
            },
        )

    # -- queries -----------------------------------------------------------

    def is_protected(self, profile: Profile) -> bool:
        return host_is_protected(profile.url, self.protected_hosts)

    def _refuse_protected(self, profile: Profile) -> None:
        if self.is_protected(profile):
            raise ProfileError(
                f"{url_host(profile.url)} is covered by PROTECTED_HOSTS; this server will "
                "not connect to it."
            )

    def sandbox_names(self) -> frozenset[str]:
        with self._lock:
            return frozenset(
                n for n, p in self._profiles.items()
                if p.sandbox and p.environment != "production"
            )

    def read_only_names(self) -> frozenset[str]:
        with self._lock:
            return frozenset(n for n, p in self._profiles.items() if p.read_only)

    @property
    def active_name(self) -> str | None:
        return self._active

    def active(self) -> Profile | None:
        with self._lock:
            return self._profiles.get(self._active) if self._active else None

    def get(self, name: str) -> Profile | None:
        return self._profiles.get(name)

    def names(self) -> list[str]:
        return sorted(self._profiles)

    def public(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {**p.public(), "active": name == self._active, "protected": self.is_protected(p)}
                for name, p in sorted(self._profiles.items())
            ]

    # -- mutations ---------------------------------------------------------

    def bootstrap(self, profile: Profile) -> bool:
        """Create the first profile from environment settings, if there are none."""
        with self._lock:
            if self._profiles:
                return False
            profile.validate()
            self._refuse_protected(profile)
            self._profiles[profile.name] = profile
            self._active = profile.name
            self._save()
            return True

    def save(self, profile: Profile) -> Profile:
        """Create or update. Empty secrets on update keep the stored ones."""
        with self._lock:
            existing = self._profiles.get(profile.name)
            if existing is not None:
                profile = replace(
                    profile,
                    api_key=profile.api_key or existing.api_key,
                    password=profile.password or existing.password,
                )
            profile.validate()
            self._refuse_protected(profile)
            self._profiles[profile.name] = profile
            if self._active is None:
                self._active = profile.name
            self._save()
            return profile

    def activate(self, name: str) -> Profile:
        with self._lock:
            profile = self._profiles.get(name)
            if profile is None:
                raise ProfileError(f"No profile named {name!r}.")
            self._refuse_protected(profile)
            self._active = name
            self._save()
            return profile

    def delete(self, name: str) -> None:
        with self._lock:
            if name not in self._profiles:
                raise ProfileError(f"No profile named {name!r}.")
            if name == self._active:
                raise ProfileError("Cannot delete the active profile; activate another first.")
            del self._profiles[name]
            self._save()
