"""Settings, read from the environment and ``.env``.

The rule this module enforces: **fail closed**. A missing or weak secret stops
the server from starting, with a message naming the variable and how to fix
it. A server that starts "open" because someone forgot a line in ``.env`` is
the most common way an internal tool ends up on the internet unauthenticated,
and it is entirely preventable at boot.

Only the HTTP transport needs the HTTP secrets. Stdio is a local pipe owned by
the user who launched it, so requiring a JWT secret there would be ceremony.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Annotated

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from .governance.detectors import DetectorConfig, parse_days, parse_hours
from .governance.engine import RiskConfig
from .governance.policy import DEFAULT_DENIED_MODELS, SENSITIVE_FIELDS

MIN_JWT_SECRET_LENGTH = 32
MIN_ADMIN_PASSWORD_LENGTH = 12


class ConfigError(RuntimeError):
    """Raised when the configuration is unsafe to start with."""


# Comma-separated in the environment. ``NoDecode`` stops pydantic-settings
# from trying to parse the value as JSON before our validator sees it.
ModelSet = Annotated[frozenset[str], NoDecode]


def _csv(value: object) -> frozenset[str]:
    if value is None:
        return frozenset()
    items = value if isinstance(value, (set, frozenset, list, tuple)) else str(value).split(",")
    return frozenset(item.strip() for item in items if str(item).strip())


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- default Odoo profile (bootstraps profiles.json when it is absent) ---
    odoo_url: str = ""
    odoo_db: str = ""
    odoo_username: str = ""
    odoo_password: str = ""
    odoo_api_key: str = ""
    odoo_ssl_verify: bool = True
    odoo_timeout: float = 30.0
    odoo_environment: str = "production"
    """Label for the profile bootstrapped from ODOO_*. Production unless said
    otherwise — and production is read-only."""
    odoo_allow_writes: bool = False

    protected_hosts: ModelSet = frozenset()
    """Hosts this server must never connect to. Use it on development machines
    to make pointing at production impossible rather than merely unlikely."""

    # --- HTTP transport ---
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8000
    mcp_public_url: str = ""
    https_mode: bool = False
    forwarded_allow_ips: str = "127.0.0.1"
    """Proxies trusted to set X-Forwarded-For. Rate limits are keyed on the
    client IP, so trusting the header from anywhere would let any caller pick
    its own rate-limit bucket."""

    max_body_mb: float = 25.0

    jwt_secret: str = Field(
        default="", validation_alias=AliasChoices("jwt_secret", "mcp_jwt_secret")
    )
    jwt_issuer: str = "odoo-mcp-governed"
    token_expiry_hours: int = Field(
        default=8760, validation_alias=AliasChoices("token_expiry_hours", "mcp_token_expiry_hours")
    )
    """One year by default. Revocation is by rotating JWT_SECRET, which
    invalidates every token at once — see the README."""

    admin_password: str = ""
    admin_session_hours: float = 8.0

    rate_limit_mcp: str = "60/minute"
    rate_limit_health: str = "30/minute"
    rate_limit_login: str = "5/minute"

    # --- cache ---
    cache_enabled: bool = True
    cache_ttl: int = 300
    cache_max_size: int = 1000

    # --- storage ---
    data_dir: Path = Path("./data")
    audit_hmac_key: str = ""

    # --- governance: initial policy (policy.json overrides once it exists) ---
    allowed_models: ModelSet = frozenset()
    writable_models: ModelSet = frozenset()
    deletable_models: ModelSet = frozenset()
    denied_models: ModelSet = Field(
        default=DEFAULT_DENIED_MODELS,
        validation_alias=AliasChoices("denied_models", "not_allowed_models"),
    )
    disabled_tools: ModelSet = frozenset()
    forbidden_methods: ModelSet = frozenset()
    sensitive_fields: ModelSet = SENSITIVE_FIELDS
    """Glob patterns for credential fields, on top of a built-in floor that
    cannot be removed (*password*, *secret*, *token*, *api_key*...)."""
    allow_execute_method: bool = False
    execute_method_allowlist: ModelSet = frozenset()
    max_records_per_call: int = 500
    max_attachment_mb: float = 10.0

    # --- governance: detection and risk ---
    business_hours: str = "07:00-20:00"
    business_days: str = "mon,tue,wed,thu,fri,sat"
    business_timezone: str = ""
    risk_throttle_threshold: int = 40
    risk_block_threshold: int = 70
    risk_throttle_seconds: float = 2.0

    # --- misc ---
    log_level: str = Field(
        default="INFO", validation_alias=AliasChoices("log_level", "mcp_log_level")
    )
    stdio_actor: str = "stdio-local"

    @field_validator(
        "allowed_models",
        "writable_models",
        "deletable_models",
        "denied_models",
        "disabled_tools",
        "forbidden_methods",
        "execute_method_allowlist",
        "sensitive_fields",
        "protected_hosts",
        mode="before",
    )
    @classmethod
    def _split_csv(cls, value: object) -> frozenset[str]:
        return _csv(value)

    # -- derived paths -----------------------------------------------------

    @property
    def profiles_file(self) -> Path:
        return self.data_dir / "profiles.json"

    @property
    def policy_file(self) -> Path:
        return self.data_dir / "policy.json"

    @property
    def token_file(self) -> Path:
        return self.data_dir / "mcp_token.json"

    @property
    def audit_db(self) -> Path:
        return self.data_dir / "audit.db"

    @property
    def anchors_file(self) -> Path:
        return self.data_dir / "anchors.log"

    # -- governance objects ------------------------------------------------

    def detector_config(self) -> DetectorConfig:
        return DetectorConfig(
            business_hours=parse_hours(self.business_hours),
            business_days=parse_days(self.business_days),
            business_timezone=self.business_timezone or None,
        )

    def risk_config(self) -> RiskConfig:
        return RiskConfig(
            throttle_threshold=self.risk_throttle_threshold,
            block_threshold=self.risk_block_threshold,
            throttle_seconds=self.risk_throttle_seconds,
        )

    @property
    def admin_session_ttl(self) -> timedelta:
        return timedelta(hours=self.admin_session_hours)

    # -- fail-closed checks ------------------------------------------------

    def require_http_secrets(self) -> None:
        """Refuse to serve HTTP without strong secrets. Raises ConfigError."""
        problems: list[str] = []
        if len(self.jwt_secret) < MIN_JWT_SECRET_LENGTH:
            problems.append(
                f"JWT_SECRET must be at least {MIN_JWT_SECRET_LENGTH} characters "
                f"(got {len(self.jwt_secret)}). Generate one with:\n"
                '    python -c "import secrets; print(secrets.token_urlsafe(48))"'
            )
        if len(self.admin_password) < MIN_ADMIN_PASSWORD_LENGTH:
            problems.append(
                f"ADMIN_PASSWORD must be at least {MIN_ADMIN_PASSWORD_LENGTH} characters "
                f"(got {len(self.admin_password)}). There is no default."
            )
        if problems:
            raise ConfigError(
                "Refusing to start the HTTP server:\n  - " + "\n  - ".join(problems)
            )

    def hmac_key(self) -> bytes | None:
        return self.audit_hmac_key.encode("utf-8") if self.audit_hmac_key else None
