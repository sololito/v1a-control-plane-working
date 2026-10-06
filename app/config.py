"""Central application configuration. Env-driven, no hardcoded secrets."""
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "odivora-home-connectivity"
    app_env: str = "dev"
    api_v1_prefix: str = "/api/v1"
    host: str = "0.0.0.0"
    port: int = 8000
    secret_key: str = "change-me-to-a-long-random-secret-min-32-chars"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30
    gateway_token_expire_minutes: int = 60
    session_token_expire_minutes: int = 60
    database_url: str = "sqlite:///./odivora_home.db"
    redis_url: str = "redis://localhost:6379/0"
    rate_limit_per_minute: int = 60
    pairing_code_ttl_minutes: int = 15
    heartbeat_offline_after_seconds: int = 120
    # --- Background maintenance (lifespan-started; off in tests) ---
    maintenance_enabled: bool = True
    maintenance_interval_seconds: int = 30
    # --- Production hardening ---
    cors_origins: str = "*"  # comma-separated; "*" only for dev
    login_max_attempts: int = 5
    login_lockout_minutes: int = 15
    pairing_max_attempts: int = 5
    auth_rate_per_minute: int = 10
    gateway_rate_per_minute: int = 30
    session_max_active: int = 5  # fallback cap if entitlement missing
    tunnel_provider: str = "null"  # null|wireguard
    # --- Audit trail / device forensics ---
    # Real client IP: when the API sits behind a reverse proxy, the socket peer
    # is the proxy, so the last X-Forwarded-For entry (appended by the trusted
    # proxy) is used. Set false when the API is directly exposed.
    trust_proxy_headers: bool = True
    # How many visited sites are retained per device+tunnel-session ("first ten").
    visit_site_limit: int = 10
    audit_page_max: int = 500
    # --- V1B relay / NAT traversal ---
    relay_control_url: str = ""  # e.g. http://relay.internal:9090; empty = dev/local allocation
    relay_public_host: str = ""  # public host:port advertised to phone/gateway
    relay_port_start: int = 20000
    relay_port_end: int = 20999
    # The Cloud must learn that a relay allocation failed before it hands the
    # ports to a phone, so these are short but not instant: a relay restart is
    # worth waiting out, an unreachable relay is not worth a hung request.
    relay_control_timeout_seconds: float = 1.5
    relay_control_retries: int = 2
    relay_control_backoff_seconds: float = 0.2
    relay_idle_ttl_seconds: int = 120  # must match the relay's own reaper
    relay_reconcile_seconds: int = 30  # 0 disables the reconcile sweep
    # --- Billing / M-Pesa Daraja (stubs in V1; no live charging unless BILLING_LIVE=true) ---
    billing_live: bool = False
    mpesa_env: str = "sandbox"  # sandbox|production
    mpesa_consumer_key: str = ""
    mpesa_consumer_secret: str = ""
    mpesa_shortcode: str = ""
    mpesa_passkey: str = ""
    mpesa_callback_url: str = ""
    mpesa_currency: str = "KES"
    mpesa_account_ref: str = "ODIVORA"
    mpesa_transaction_desc: str = "ODIVORA plan"

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()
