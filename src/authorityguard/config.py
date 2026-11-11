from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AG_", env_file=".env", extra="ignore")

    env: str = "dev"
    database_url: str = "sqlite:///./authorityguard.db"


@lru_cache
def get_settings() -> Settings:
    return Settings()
