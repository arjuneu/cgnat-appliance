import os
from typing import Any
try:
    from config_vault import ConfigVault
    _vault = ConfigVault()
except Exception:
    _vault = None

def get_config(key: str, default: Any = None) -> Any:
    if _vault is not None:
        val = _vault.get(key)
        if val is not None and str(val).strip() != "":
            return val
    return os.getenv(key, default)

# Network & Infrastructure
ISP_NAME = get_config("ISP_NAME", "Enterprise ISP")
ROUTER_IPS = [x.strip() for x in str(get_config("ROUTER_IPS", "")).split(",") if x.strip()]
ISP_PUBLIC_POOLS = [x.strip() for x in str(get_config("ISP_PUBLIC_POOLS", "203.0.113.0/24")).split(",") if x.strip()]
CGNAT_POOLS = [x.strip() for x in str(get_config("CGNAT_POOLS", "100.64.0.0/10")).split(",") if x.strip()]

# ClickHouse DB
CLICKHOUSE_HOST = get_config("CLICKHOUSE_HOST", "127.0.0.1")
CLICKHOUSE_PORT = int(get_config("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_DB = get_config("CLICKHOUSE_DB", "nat_logs")
CLICKHOUSE_USER = get_config("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = get_config("CLICKHOUSE_PASSWORD", "")

# Router Credentials
MIKROTIK_IP = get_config("MIKROTIK_IP", "")
MIKROTIK_USER = get_config("MIKROTIK_USER", "natlog")
MIKROTIK_PASSWORD = get_config("MIKROTIK_PASSWORD", "")

# RADIUS Billing API
RADIUS_API_URL = get_config("RADIUS_API_URL", "")
RADIUS_API_TOKEN = get_config("RADIUS_API_TOKEN", "")
RADIUS_AUTH_TYPE = get_config("RADIUS_AUTH_TYPE", "bearer")
RADIUS_AUTH_HEADER = get_config("RADIUS_AUTH_HEADER", "Authorization")
RADIUS_HTTP_METHOD = get_config("RADIUS_HTTP_METHOD", "GET")
RADIUS_PARAM_IP = get_config("RADIUS_PARAM_IP", "ip")
RADIUS_PARAM_TIME = get_config("RADIUS_PARAM_TIME", "timestamp")
RADIUS_FIELD_USERNAME = get_config("RADIUS_FIELD_USERNAME", "customer.pppoe_username")
RADIUS_FIELD_NAME = get_config("RADIUS_FIELD_NAME", "customer.name")
RADIUS_FIELD_CODE = get_config("RADIUS_FIELD_CODE", "customer.customer_code")
RADIUS_FIELD_PHONE = get_config("RADIUS_FIELD_PHONE", "customer.contact.primary")
RADIUS_FIELD_ADDRESS = get_config("RADIUS_FIELD_ADDRESS", "customer.address")
RADIUS_FIELD_BRANCH = get_config("RADIUS_FIELD_BRANCH", "customer.branch")
RADIUS_FIELD_MAC = get_config("RADIUS_FIELD_MAC", "session.mac_address")
RADIUS_FIELD_START = get_config("RADIUS_FIELD_START", "session.session_start_time")
RADIUS_FIELD_STOP = get_config("RADIUS_FIELD_STOP", "session.session_stop_time")

# Alerts & Discord
DISCORD_WEBHOOK_URL = get_config("DISCORD_WEBHOOK_URL", "")

# Anomaly Thresholds & Server Settings
SCAN_INTERVAL_SECONDS = int(get_config("SCAN_INTERVAL_SECONDS", "300"))
PORT_EXHAUSTION_THRESHOLD = int(get_config("PORT_EXHAUSTION_THRESHOLD", "45000"))
PRIVATE_IP_FLOW_THRESHOLD = int(get_config("PRIVATE_IP_FLOW_THRESHOLD", "2500"))
PRIVATE_IP_TARGET_THRESHOLD = int(get_config("PRIVATE_IP_TARGET_THRESHOLD", "400"))

API_HOST = get_config("API_HOST", "0.0.0.0")
API_PORT = int(get_config("API_PORT", "8088"))
SERVER_TIMEZONE = get_config("SERVER_TIMEZONE", "Asia/Kathmandu")

# AI Reasoning Engine Fallback Mode
AI_OFFLINE_FALLBACK_ENABLED = get_config("AI_OFFLINE_FALLBACK_ENABLED", "false").lower() in ("true", "1", "yes")
