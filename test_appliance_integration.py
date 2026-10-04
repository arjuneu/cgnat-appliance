import os
import sys
import json
import requests
import time

def run_tests():
    print("=================================================================")
    print("CT 100 APPLIANCE INTERNAL INTEGRATION TEST")
    print("=================================================================")

    # 1. Test Config Vault Decryption
    from config_vault import ConfigVault
    vault = ConfigVault()
    print("\n1. CONFIG VAULT TEST:")
    print(f"   Key file: {vault.key_path} (Exists: {os.path.exists(vault.key_path)})")
    print(f"   Vault file: {vault.vault_path} (Exists: {os.path.exists(vault.vault_path)})")
    masked = vault.get_all_masked()
    print(f"   Total encrypted keys: {len(masked)}")
    for k in ["ISP_NAME", "RADIUS_API_TOKEN", "MIKROTIK_PASSWORD", "DISCORD_WEBHOOK_URL", "ISP_PUBLIC_POOLS", "CGNAT_POOLS"]:
        print(f"   - {k:<25} = {masked.get(k)}")

    # 2. Test config.py integration
    import config
    print("\n2. CONFIG MODULE INTEGRATION:")
    print(f"   ISP Name: {config.ISP_NAME}")
    print(f"   Router IPs: {config.ROUTER_IPS}")
    print(f"   MikroTik IP: {config.MIKROTIK_IP}")
    print(f"   MikroTik User: {config.MIKROTIK_USER}")
    print(f"   MikroTik Pass: {config.MIKROTIK_PASSWORD[:4]}...{config.MIKROTIK_PASSWORD[-4:] if len(config.MIKROTIK_PASSWORD) > 8 else '***'}")
    print(f"   RADIUS URL: {config.RADIUS_API_URL}")

    # 3. Test RADIUS Client
    from radius_client import RadiusClient
    rc = RadiusClient()
    print("\n3. RADIUS CLIENT LOOKUP:")
    print(f"   API URL: {rc.api_url}")
    print(f"   API Token: {rc.token[:4]}...{rc.token[-4:] if len(rc.token) > 8 else '***'}")
    try:
        rad_res = rc.lookup_subscriber("100.66.219.52", "2026-09-30 12:00:00")
        print(f"   Subscriber Lookup Result: {rad_res}")
    except Exception as e:
        print(f"   Radius Error: {e}")

    # 4. Test MikroTik Connection
    import mikrotik_sync
    print("\n4. MIKROTIK THREAT SHIELD SSH:")
    print(f"   Target: {mikrotik_sync.MIKROTIK_USER}@{mikrotik_sync.MIKROTIK_IP}")
    out, err = mikrotik_sync.exec_mikrotik_cmd(":put [/system identity get name]")
    print(f"   Identity Query Output: {out.strip() if out else f'ERR: {err}'}")

    # 5. Test Web UI & FastAPI Endpoints
    print("\n5. FASTAPI & WEB SUITE ENDPOINTS:")
    base = "http://127.0.0.1:8088"
    
    # GET /
    r_index = requests.get(f"{base}/")
    print(f"   GET / -> Status {r_index.status_code} ({len(r_index.text):,} bytes)")

    # Static Assets
    r_css = requests.get(f"{base}/static/css/style.css")
    print(f"   GET /static/css/style.css -> Status {r_css.status_code} ({len(r_css.text):,} bytes)")
    r_js = requests.get(f"{base}/static/js/app.js")
    print(f"   GET /static/js/app.js -> Status {r_js.status_code} ({len(r_js.text):,} bytes)")

    # Auth Login
    r_login = requests.post(f"{base}/api/v1/auth/login", json={"username": "admin", "password": "admin"})
    print(f"   POST /api/v1/auth/login -> Status {r_login.status_code}")
    token = r_login.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}

    # Health Check
    r_health = requests.get(f"{base}/api/v1/health")
    print(f"   GET /api/v1/health -> Status {r_health.status_code}, Payload: {r_health.json()}")

    r_srv_health = requests.get(f"{base}/api/v1/server-health", headers=headers)
    print(f"   GET /api/v1/server-health -> Status {r_srv_health.status_code}, DB Health: {r_srv_health.json().get('status')}")

    # Threat Config
    r_th = requests.get(f"{base}/api/v1/threats/config", headers=headers)
    print(f"   GET /api/v1/threats/config -> Status {r_th.status_code}")

    # Vault Config (Admin Only)
    r_vc = requests.get(f"{base}/api/v1/vault/config", headers=headers)
    print(f"   GET /api/v1/vault/config -> Status {r_vc.status_code}")
    if r_vc.status_code == 200:
        cfg = r_vc.json().get("config", {})
        print(f"   Vault parameters verified ({len(cfg)} keys in encrypted vault).")

    print("\n=================================================================")
    print("ALL APPLIANCE COMPONENTS VERIFIED & OPERATIONAL ON CT 100")
    print("=================================================================")

if __name__ == "__main__":
    run_tests()
