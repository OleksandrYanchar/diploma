"""Application configuration.

All settings are loaded from environment variables.  pydantic-settings reads
values from the process environment and, optionally, from a .env file.  No
secret value is hardcoded here; every field that carries a default is a
non-sensitive operational parameter.

Security property enforced: SR-19 (no hardcoded secrets), SR-06 (token TTL
is configurable and defaults to the mandated 15-minute access token window).
"""

from __future__ import annotations

from typing import Any

from pydantic import Field, PostgresDsn, RedisDsn, field_validator, model_validator
from pydantic.fields import FieldInfo
from pydantic_settings import BaseSettings, EnvSettingsSource, SettingsConfigDict


class _CommaListEnvSource(EnvSettingsSource):
    """EnvSettingsSource subclass that accepts comma-separated list values.

    pydantic-settings v2 calls ``json.loads()`` on complex-type fields before
    any field validator runs.  A bare comma-separated string such as
    ``http://localhost,http://localhost:3000`` is not valid JSON, so the
    default source raises ``SettingsError`` before the application boots.

    This subclass overrides ``decode_complex_value`` to detect comma-separated
    strings and split them before falling back to JSON decoding.  Both formats
    are therefore accepted, which lets ``docker-compose.yml`` and ``.env``
    files use the human-readable comma-separated form.
    """

    def decode_complex_value(
        self, field_name: str, field: FieldInfo, value: Any
    ) -> Any:
        """Decode a raw env string for a complex-type field.

        For ``allowed_origins`` (and any other list field), if the raw value
        is a plain comma-separated string it is split and returned as a list.
        JSON-encoded values (starting with ``[`` or ``{``) are passed to the
        standard JSON decoder as normal.

        Args:
            field_name: Name of the settings field being decoded.
            field: Pydantic ``FieldInfo`` for the field.
            value: Raw string value from the environment.

        Returns:
            A Python object decoded from the raw string.
        """
        if isinstance(value, str):
            stripped = value.strip()
            if not (stripped.startswith("[") or stripped.startswith("{")):
                # Not JSON — try comma-separated for list fields.
                annotation = field.annotation
                origin = getattr(annotation, "__origin__", None)
                if origin is list:
                    return [
                        item.strip() for item in stripped.split(",") if item.strip()
                    ]
        return super().decode_complex_value(field_name, field, value)


class Settings(BaseSettings):
    """Central configuration object.

    Instantiate once via the module-level ``get_settings`` factory and inject
    through FastAPI's ``Depends()`` wherever configuration is needed.  Never
    import this class directly in business logic; always receive it through
    dependency injection so tests can override it cleanly.
    """

    model_config = SettingsConfigDict(
        # Search for .env in the backend/ directory first, then one level up
        # (the repo root).  This means:
        #   - Inside Docker (WORKDIR /backend): finds /backend/.env if present,
        #     otherwise the env vars injected by Compose are already in the
        #     process environment and no file is needed.
        #   - Local development: finds backend/.env or the root .env — a single
        #     file at the repo root covers both docker-compose and local tooling.
        # Variables already present in the process environment always take
        # precedence over the file, so Docker Compose injected vars win.
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        # Ignore unknown environment variables (many will be present in Docker).
        extra="ignore",
        case_sensitive=False,
    )

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------
    app_name: str = Field(
        default="Zero Trust Financial API",
        description="Human-readable application name",
    )
    app_version: str = Field(default="0.1.0")
    debug: bool = Field(
        default=False,
        description="Enable debug mode. Must be False in production.",
    )
    environment: str = Field(
        default="production",
        description="Runtime environment: development | production | test",
    )

    # ------------------------------------------------------------------
    # PostgreSQL — component variables
    #
    # Used by docker-compose for the postgres service AND to construct
    # DATABASE_URL when it is not provided directly (e.g. local Alembic runs).
    # ------------------------------------------------------------------
    postgres_user: str | None = Field(default=None, description="PostgreSQL user name.")
    postgres_password: str | None = Field(
        default=None, description="PostgreSQL password."
    )
    postgres_db: str | None = Field(
        default=None, description="PostgreSQL database name."
    )
    postgres_host: str = Field(default="localhost", description="PostgreSQL host.")
    postgres_port: int = Field(default=5432, description="PostgreSQL port.")

    # Full async DSN — required at runtime.  Constructed from the component
    # vars above when not provided directly (see build_connection_urls validator).
    database_url: PostgresDsn | None = Field(
        default=None,
        description=(
            "Async PostgreSQL DSN.  "
            "Constructed automatically from POSTGRES_* vars when not set directly."
        ),
    )

    # ------------------------------------------------------------------
    # Redis — component variables
    # ------------------------------------------------------------------
    redis_password: str | None = Field(default=None, description="Redis password.")
    redis_host: str = Field(default="localhost", description="Redis host.")
    redis_port: int = Field(default=6379, description="Redis port.")

    # Full Redis URL — constructed from component vars when not provided directly.
    redis_url: RedisDsn | None = Field(
        default=None,
        description=(
            "Redis connection URL.  "
            "Constructed automatically from REDIS_* vars when not set directly."
        ),
    )

    # ------------------------------------------------------------------
    # JWT / Token settings
    # ------------------------------------------------------------------
    jwt_secret_key: str = Field(
        description=(
            "HMAC secret for signing JWT access tokens.  "
            "Must be at least 32 bytes of cryptographic randomness.  "
            'Generate with: python -c "import secrets; print(secrets.token_hex(32))"'
        )
    )
    jwt_algorithm: str = Field(default="HS256", description="JWT signing algorithm.")

    # Access token lifetime (SR-06: maximum 15 minutes)
    access_token_expire_minutes: int = Field(
        default=15,
        ge=1,
        le=15,
        description="Access token lifetime in minutes. Maximum 15 per SR-06.",
    )

    # Refresh token lifetime
    refresh_token_expire_days: int = Field(
        default=7,
        ge=1,
        le=30,
        description="Refresh token lifetime in days.",
    )

    # Step-up token lifetime (SR-13: 5 minutes)
    step_up_token_expire_minutes: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Step-up token lifetime in minutes. Maximum 10 per SR-13.",
    )

    # ------------------------------------------------------------------
    # Security policy parameters
    # ------------------------------------------------------------------
    # SR-05: account lockout after N consecutive failed logins
    max_failed_login_attempts: int = Field(
        default=5,
        ge=3,
        description=(
            "Number of consecutive failed login attempts before account lockout."
        ),
    )

    # Duration (minutes) the account remains locked
    account_lockout_minutes: int = Field(
        default=30,
        ge=1,
        description=(
            "Minutes an account remains locked after exceeding failed login threshold."
        ),
    )

    # SR-13: step-up authentication threshold (in USD cents or base currency units)
    step_up_transfer_threshold: int = Field(
        default=100000,  # 1000.00 USD stored as integer cents
        ge=1,
        description=(
            "Transfer amount (in smallest currency unit) at or above which "
            "step-up authentication is required."
        ),
    )

    # ------------------------------------------------------------------
    # CORS (used by FastAPI middleware in later phases)
    # ------------------------------------------------------------------
    allowed_origins: list[str] = Field(
        default=["http://localhost:3000"],
        description=(
            "List of allowed CORS origins.  "
            "Lock down to the frontend URL in production."
        ),
    )

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------
    @model_validator(mode="before")
    @classmethod
    def build_connection_urls(cls, data: Any) -> Any:
        """Construct DATABASE_URL and REDIS_URL from component variables.

        pydantic-settings merges all sources (env vars, .env file) into a dict
        before field validation runs.  This validator inspects that dict and
        constructs the full DSN strings from their component parts when the
        full URLs are not already present.

        This means .env only needs POSTGRES_USER / POSTGRES_PASSWORD /
        POSTGRES_DB / REDIS_PASSWORD — the full connection strings are derived
        automatically, both locally and inside Docker.

        Args:
            data: Raw merged settings dict from all pydantic-settings sources.

        Returns:
            The same dict, with ``database_url`` and/or ``redis_url`` added
            when they were absent and the required components were present.

        Raises:
            ValueError: If neither the full URL nor all required component
                variables are available for either connection.
        """
        if not isinstance(data, dict):
            return data

        # --- PostgreSQL ---
        if not data.get("database_url"):
            user = data.get("postgres_user")
            password = data.get("postgres_password")
            db = data.get("postgres_db")
            host = data.get("postgres_host", "localhost")
            port = data.get("postgres_port", 5432)
            if user and password and db:
                data["database_url"] = (
                    f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{db}"
                )
            else:
                raise ValueError(
                    "Provide DATABASE_URL or all of: "
                    "POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB."
                )

        # --- Redis ---
        if not data.get("redis_url"):
            password = data.get("redis_password")
            host = data.get("redis_host", "localhost")
            port = data.get("redis_port", 6379)
            auth = f":{password}" if password else ""
            data["redis_url"] = f"redis://{auth}@{host}:{port}/0"

        return data

    @field_validator("jwt_secret_key")
    @classmethod
    def jwt_secret_must_be_strong(cls, value: str) -> str:
        """Reject JWT secrets that are too short.

        A minimum of 32 characters is enforced to ensure adequate entropy for
        HS256 signing.  This does not guarantee the key is random, but it
        prevents obviously weak values.
        """
        if len(value) < 32:
            msg = "jwt_secret_key must be at least 32 characters long."
            raise ValueError(msg)
        return value

    @field_validator("environment")
    @classmethod
    def environment_must_be_known(cls, value: str) -> str:
        """Restrict environment to known values to prevent misconfiguration."""
        allowed = {"development", "production", "test"}
        if value not in allowed:
            msg = f"environment must be one of {allowed}, got '{value}'."
            raise ValueError(msg)
        return value

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        **kwargs: Any,
    ) -> tuple[Any, ...]:
        """Replace the default env source with one that accepts comma-separated lists.

        pydantic-settings v2 tries to JSON-decode every complex-type field
        before field validators run.  A comma-separated ``ALLOWED_ORIGINS``
        string (the natural format for .env and docker-compose files) is not
        valid JSON, so the default source raises ``SettingsError`` at startup.

        By substituting ``_CommaListEnvSource`` for the built-in
        ``EnvSettingsSource``, both comma-separated and JSON-array formats are
        accepted without changing .env syntax.

        Returns:
            A tuple of settings sources in precedence order:
            init values > env vars (comma-list-aware) > .env file > defaults.
        """
        sources = super().settings_customise_sources(settings_cls, **kwargs)
        return tuple(
            _CommaListEnvSource(settings_cls)
            if isinstance(src, EnvSettingsSource)
            else src
            for src in sources
        )


def get_settings() -> Settings:
    """Return the application settings instance.

    This function is used as a FastAPI dependency so that tests can override
    it with ``app.dependency_overrides``.  Do not cache with
    ``@lru_cache`` here — tests need a fresh instance per override.

    Usage in a route::

        from fastapi import Depends
        from app.core.config import Settings, get_settings

        @router.get("/example")
        async def example(settings: Settings = Depends(get_settings)):
            ...
    """
    return Settings()  # type: ignore[call-arg]
