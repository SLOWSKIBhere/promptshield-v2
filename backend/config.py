"""Central, deterministic application configuration."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


BACKEND_DIR = Path(__file__).resolve().parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    anthropic_api_key: str | None = None
    openai_api_key: str | None = None
    groq_api_key: str | None = None
    promptshield_api_key: str | None = None
    allowed_origins: str = "http://127.0.0.1:5173,http://localhost:5173"
    database_path: Path = BACKEND_DIR / "promptshield.db"
    anthropic_target_model: str = "claude-haiku-4-5-20251001"
    anthropic_judge_model: str = "claude-haiku-4-5-20251001"
    openai_target_model: str = "gpt-4o-mini"
    openai_judge_model: str = "gpt-4o-mini"
    groq_target_model: str = "llama-3.1-8b-instant"
    groq_judge_model: str = "llama-3.1-8b-instant"
    groq_base_url: str = "https://api.groq.com/openai/v1"
    target_provider: Literal["auto", "anthropic", "openai", "groq"] = "auto"
    judge_provider: Literal["auto", "anthropic", "openai", "groq", "heuristic"] = "auto"
    allow_private_targets: bool = False
    target_timeout_seconds: float = 30.0

    @property
    def cors_origins(self) -> list[str]:
        if self.allowed_origins.strip() == "*":
            return ["*"]
        return [item.strip() for item in self.allowed_origins.split(",") if item.strip()]

    @field_validator("database_path", mode="after")
    @classmethod
    def resolve_database_path(cls, value: Path) -> Path:
        return value if value.is_absolute() else (BACKEND_DIR / value).resolve()


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
