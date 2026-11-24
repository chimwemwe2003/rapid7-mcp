from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="R7_",
        env_file=".env",
        env_file_encoding="utf-8",
        populate_by_name=True,
        extra="ignore",
    )

    # InsightVM (on-prem console, Basic Auth)
    console_url: str = "https://localhost:3780"
    username: str = "admin"
    password: str = "password"
    verify_ssl: bool = False

    # InsightIDR (Insight Platform cloud API, X-Api-Key)
    idr_region: str = Field(default="us", validation_alias="IDR_REGION")
    idr_api_key: str = Field(default="", validation_alias="IDR_API_KEY")

    # Metasploit Pro (local/remote MSP console, token auth, read-only)
    msp_url: str = Field(default="https://localhost:3790", validation_alias="MSP_URL")
    msp_token: str = Field(default="", validation_alias="MSP_TOKEN")
    msp_verify_ssl: bool = Field(default=False, validation_alias="MSP_VERIFY_SSL")

    # Demo mode — return fixture data, skip all live connectivity
    demo_mode: bool = Field(default=False, validation_alias="DEMO_MODE")

    # Check Point Quantum Smart-1 Cloud via Infinity Portal Gateway (read-only)
    chkp_enabled: bool = Field(default=False, validation_alias="CHKP_ENABLED")
    chkp_key_mode: str = Field(default="per_user", validation_alias="CHECKPOINT_KEY_MODE")  # "per_user" | "shared"
    chkp_auth_url: str = Field(default="https://cloudinfra-gw.portal.checkpoint.com", validation_alias="CHKP_AUTH_URL")
    chkp_client_id: str = Field(default="", validation_alias="CHKP_CLIENT_ID")
    chkp_secret_key: str = Field(default="", validation_alias="CHKP_SECRET_KEY")
    chkp_service_id: str = Field(default="", validation_alias="CHKP_SERVICE_ID")
    chkp_mgmt_admin_api_key: str = Field(default="", validation_alias="CHKP_MGMT_ADMIN_API_KEY")
    chkp_auth_method: str = Field(default="infinity_portal_api_key", validation_alias="CHKP_AUTH_METHOD")
    chkp_mgmt_host: str = Field(default="", validation_alias="CHKP_MGMT_HOST")
    chkp_port: int = Field(default=443, validation_alias="CHKP_PORT")
    chkp_portal_region: str = Field(default="eu", validation_alias="CHKP_PORTAL_REGION")
    chkp_shared_api_key: str = Field(default="", validation_alias="CHKP_SHARED_API_KEY")
    chkp_domain: str | None = Field(default=None, validation_alias="CHKP_DOMAIN")
    chkp_ca_bundle: str | None = Field(default=None, validation_alias="CHKP_CA_BUNDLE")
    chkp_timeout: float = Field(default=15.0, validation_alias="CHKP_TIMEOUT")

    # General and Investigation Limits
    investigations_max_results: int = Field(default=1000, validation_alias="INVESTIGATIONS_MAX_RESULTS")
    max_list_results: int = Field(default=1000, validation_alias="MAX_LIST_RESULTS")

    # VirusTotal Threat Intelligence API v3 (Lookups only)
    vt_enabled: bool = Field(default=False, validation_alias="VT_ENABLED")
    vt_api_tier: str = Field(default="public", validation_alias="VT_API_TIER")  # "public" | "premium"
    vt_key_mode: str = Field(default="per_user", validation_alias="VT_KEY_MODE")  # "per_user" | "shared"
    vt_shared_key: str = Field(default="", validation_alias="VT_SHARED_KEY")
    vt_rate_limit_per_min: int = Field(default=4, validation_alias="VT_RATE_LIMIT_PER_MIN")
    vt_daily_quota: int = Field(default=500, validation_alias="VT_DAILY_QUOTA")
    internal_domains: list[str] = Field(
        default=["local", "internal", "corp", "lan"],
        validation_alias="INTERNAL_DOMAINS",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


_settings = get_settings()

# Module-level convenience exports for runtime and UI configuration
CHKP_ENABLED: bool = _settings.chkp_enabled
CHKP_KEY_MODE: str = _settings.chkp_key_mode
CHKP_AUTH_URL: str = _settings.chkp_auth_url
CHKP_CLIENT_ID: str = _settings.chkp_client_id
CHKP_SECRET_KEY: str = _settings.chkp_secret_key
CHKP_SERVICE_ID: str = _settings.chkp_service_id
CHKP_MGMT_ADMIN_API_KEY: str = _settings.chkp_mgmt_admin_api_key
CHKP_AUTH_METHOD: str = _settings.chkp_auth_method
CHKP_MGMT_HOST: str = _settings.chkp_mgmt_host
CHKP_PORT: int = _settings.chkp_port
CHKP_PORTAL_REGION: str = _settings.chkp_portal_region
CHKP_SHARED_API_KEY: str = _settings.chkp_shared_api_key
CHKP_DOMAIN: str | None = _settings.chkp_domain
CHKP_CA_BUNDLE: str | None = _settings.chkp_ca_bundle
CHKP_TIMEOUT: float = _settings.chkp_timeout

INVESTIGATIONS_MAX_RESULTS: int = _settings.investigations_max_results
MAX_LIST_RESULTS: int = _settings.max_list_results

VT_ENABLED: bool = _settings.vt_enabled
VT_API_TIER: str = _settings.vt_api_tier
VT_KEY_MODE: str = _settings.vt_key_mode
VT_SHARED_KEY: str = _settings.vt_shared_key
VT_RATE_LIMIT_PER_MIN: int = _settings.vt_rate_limit_per_min
VT_DAILY_QUOTA: int = _settings.vt_daily_quota
INTERNAL_DOMAINS: list[str] = _settings.internal_domains

