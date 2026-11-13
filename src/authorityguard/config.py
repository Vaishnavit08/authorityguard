from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AG_", env_file=".env", extra="ignore")

    # dev: local laptop. demo: public showcase (synthetic data, ephemeral key allowed).
    env: str = "dev"
    database_url: str = "sqlite:///./authorityguard.db"

    # Capability tokens
    token_issuer: str = "authorityguard"  # noqa: S105  (names, not secrets)
    token_audience: str = "authorityguard-gateway"  # noqa: S105
    # Ed25519 private key (PEM). In dev/demo it is generated on first use; elsewhere it must exist.
    signing_key_path: str = ".keys/signing-ed25519.pem"
    capability_default_ttl_seconds: int = 900  # 15 minutes
    capability_max_ttl_seconds: int = 3600  # 1 hour hard cap

    # Policy-as-code document (see policies/default.json)
    policy_path: str = "policies/default.json"
    approval_ttl_seconds: int = 600  # a pending approval expires after 10 minutes

    # If set, management endpoints (create users/agents/tasks, issue/revoke capabilities,
    # decide approvals) require the header `X-API-Key: <value>`.
    admin_api_key: str | None = None

    # Public demo endpoint rate limit (runs per minute per process)
    demo_runs_per_minute: int = 20

    @property
    def allow_generated_key(self) -> bool:
        return self.env in {"dev", "demo"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
