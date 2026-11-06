"""Central configuration loader.

Reads settings from environment variables and an optional `.env` file.
No secret has a default value: a missing secret is an error where it is needed,
never a silent fallback.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # LLM (Gemini free tier)
    gemini_api_key: SecretStr | None = None
    gemini_model: str = "gemini-3.5-flash-lite"
    llm_max_retries: int = 5
    llm_backoff_seconds: float = 2.0

    # Database
    postgres_user: str = "agentfirewall"
    postgres_password: SecretStr | None = None
    postgres_db: str = "agentfirewall"
    postgres_host: str = "127.0.0.1"
    postgres_port: int = 5432

    # Gateway
    gateway_host: str = "127.0.0.1"
    gateway_port: int = 8080
    gateway_url: str = "http://127.0.0.1:8080/mcp"  # what the agents connect to
    gateway_call_timeout_seconds: float = 30.0  # limit for one downstream tool call
    policy_dir: str = "policies"
    approval_expiry_minutes: int = 15
    # Rate limit (Stage 3): token bucket per agent. Sustained rate and the largest burst.
    rate_limit_calls_per_minute: float = Field(default=30, gt=0)
    rate_limit_burst: int = Field(default=10, ge=1)

    # Agent identity (Stage 2): one API key per agent, shown once by scripts/register_agents.py
    agent_key_ttl_days: int = 90
    finance_agent_key: SecretStr | None = None
    it_ops_agent_key: SecretStr | None = None
    developer_agent_key: SecretStr | None = None

    # Downstream MCP servers (internal network only)
    company_data_mcp_url: str = "http://company-data:9001/mcp"
    operations_mcp_url: str = "http://operations:9002/mcp"
    developer_tools_mcp_url: str = "http://developer-tools:9003/mcp"

    # Admin API / approver login
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    approver_username: str = "approver"
    approver_password: SecretStr | None = None

    # Audit
    audit_hash_algorithm: str = "sha256"

    @property
    def database_url(self) -> str:
        if self.postgres_password is None:
            raise RuntimeError("POSTGRES_PASSWORD is not set (see .env.example)")
        password = self.postgres_password.get_secret_value()  # secret-scan: ignore
        return (
            f"postgresql+psycopg://{self.postgres_user}:{password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    def require_gemini_key(self) -> str:
        if self.gemini_api_key is None or not self.gemini_api_key.get_secret_value():
            raise RuntimeError("GEMINI_API_KEY is not set (see .env.example)")
        return self.gemini_api_key.get_secret_value()


@lru_cache
def get_settings() -> Settings:
    return Settings()
