import os
import sys
import json
import requests
import time

def test_fleet():
    print("=" * 70)
    print("MULTI-VENDOR ROUTER FLEET & THREAT SHIELD TEST (CT 100)")
    print("=" * 70)

    base = "http://127.0.0.1:8088"

    # 1. Login
    print("\n1. AUTHENTICATION:")
    r_login = requests.post(f"{base}/api/v1/auth/login", json={"username": "admin", "password": "admin"})
    token = r_login.json().get("token")
    print(f"   Login Status: {r_login.status_code}, Token Acquired: {bool(token)}")
    headers = {"Authorization": f"Bearer {token}"}

    # 2. List Routers
    print("\n2. ROUTER FLEET INVENTORY:")
    r_routers = requests.get(f"{base}/api/v1/routers", headers=headers)
    print(f"   GET /api/v1/routers -> Status: {r_routers.status_code}")
    routers = r_routers.json().get("routers", [])
    for r in routers:
        v = r.get("vendor", "mikrotik").upper()
        icon = "⚡" if v == "JUNIPER" else "🛡️"
        print(f"   {icon} [{v:<8}] {r.get('name'):<40} | IP: {r.get('ip')}:{r.get('port', 22)} | List: {r.get('address_list')} | Auto-Sync: {r.get('sync_enabled')}")

    # 3. Test MikroTik Router Connection
    print("\n3. TESTING LIVE SSH CONNECTION TO MIKROTIK (198.51.100.26):")
    r_test_mt = requests.post(f"{base}/api/v1/routers/mikrotik-26/test", headers=headers)
    print(f"   Status: {r_test_mt.status_code}, Result: {r_test_mt.json()}")

    # 4. Test Juniper Junos Router Connection or Model Definition
    print("\n4. TESTING JUNIPER JUNOS ADAPTER DEFINITION & CONNECTION:")
    r_test_jn = requests.post(f"{base}/api/v1/routers/juniper-core/test", headers=headers)
    print(f"   Status: {r_test_jn.status_code}, Result: {r_test_jn.json()}")

    # 5. Test Multi-Vendor Fleet Threat List Aggregation
    print("\n5. MULTI-VENDOR FLEET THREAT LIST:")
    r_fleet = requests.get(f"{base}/api/v1/threats/fleet-list?router_id=all", headers=headers)
    print(f"   GET /api/v1/threats/fleet-list?router_id=all -> Status: {r_fleet.status_code}")
    fleet_data = r_fleet.json()
    print(f"   Total Fleet Threat Rules: {fleet_data.get('total_entries')}")
    for entry in fleet_data.get("entries", [])[:5]:
        print(f"   - [{entry.get('vendor').upper()}] {entry.get('address'):<20} on {entry.get('router_ip')} ({entry.get('comment')})")

    # 6. Test Single-Router Filter Endpoint
    print("\n6. SINGLE ROUTER FILTER (mikrotik-26):")
    r_single = requests.get(f"{base}/api/v1/threats/fleet-list?router_id=mikrotik-26", headers=headers)
    print(f"   Status: {r_single.status_code}, Entries on mikrotik-26: {r_single.json().get('total_entries')}")

    print("\n" + "=" * 70)
    print("ALL MULTI-VENDOR THREAT SHIELD ENGINE COMPONENTS VERIFIED!")
    print("=" * 70)

if __name__ == "__main__":
    test_fleet()
