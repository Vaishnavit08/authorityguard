from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AG_", env_file=".env", extra="ignore")

    env: str = "dev"
    database_url: str = "sqlite:///./authorityguard.db"

    # Capability tokens
    token_issuer: str = "authorityguard"  # noqa: S105  (names, not secrets)
    token_audience: str = "authorityguard-gateway"  # noqa: S105
    # Ed25519 private key (PEM). In dev it is generated on first use; elsewhere it must exist.
    signing_key_path: str = ".keys/signing-ed25519.pem"
    capability_default_ttl_seconds: int = 900  # 15 minutes
    capability_max_ttl_seconds: int = 3600  # 1 hour hard cap


@lru_cache
def get_settings() -> Settings:
    return Settings()
