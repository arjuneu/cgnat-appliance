#!/usr/bin/env python3
import os
import sys
import time
import json
import subprocess
import ipaddress
import urllib.request
import logging
from collections import defaultdict
from typing import Dict, List, Tuple, Any, Optional
import clickhouse_connect
import config

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("router_sync")

MIKROTIK_IP = getattr(config, "MIKROTIK_IP", "")
MIKROTIK_USER = getattr(config, "MIKROTIK_USER", "natlog")
MIKROTIK_PASSWORD = getattr(config, "MIKROTIK_PASSWORD", "")
ADDRESS_LIST_NAME = os.getenv("MIKROTIK_ADDRESS_LIST", "scanner")

# Base Default Thresholds (Overridden dynamically by admin settings in STATE_FILE)
UDP_SWEEP_MIN_PORTS = int(os.getenv("UDP_SWEEP_MIN_PORTS", "1000"))       # Default 1000 ports for UDP sweep blocking
VERTICAL_SCAN_MIN_PORTS = int(os.getenv("VERTICAL_SCAN_MIN_PORTS", "1000")) # Default 1000 ports for TCP/generic scans
FLOOD_MIN_FLOWS = int(os.getenv("FLOOD_MIN_FLOWS", "10000"))              # Default 10,000 flows for flood detection
MAX_SUBSCRIBERS_FOR_BLOCK = int(os.getenv("MAX_SUBSCRIBERS_FOR_BLOCK", "4")) # Default max 4 subscribers (<5)

STATE_FILE = os.getenv("SYNC_STATE_FILE", "/opt/nat-ai-agent/data/mikrotik_sync_state.json")

DISCORD_WEBHOOK_URL = getattr(config, "DISCORD_WEBHOOK_URL", "")

CLICKHOUSE_HOST = getattr(config, "CLICKHOUSE_HOST", "127.0.0.1")
CLICKHOUSE_PORT = int(getattr(config, "CLICKHOUSE_PORT", 8123))
CLICKHOUSE_DB = getattr(config, "CLICKHOUSE_DB", "nat_logs")
CLICKHOUSE_USER = getattr(config, "CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = getattr(config, "CLICKHOUSE_PASSWORD", "")

# Protected Subnets and ISP Whitelist (Never block our own public pools, private, or router subnets)
def _build_whitelist_networks():
    nets = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
            ]
    for pool in getattr(config, "ISP_PUBLIC_POOLS", ["203.0.113.0/24"]):
        try: nets.append(ipaddress.ip_network(pool.strip()))
        except Exception: pass
    for pool in getattr(config, "CGNAT_POOLS", ["100.64.0.0/10"]):
        try: nets.append(ipaddress.ip_network(pool.strip()))
        except Exception: pass
    return nets

WHITELIST_NETWORKS = _build_whitelist_networks()

def get_threat_config() -> Dict[str, Any]:
    """Retrieves current admin-configured threat parameters and sync state from persistent JSON."""
    defaults = {
        "enabled": True,
        "enforcement_scope": "fleet_wide",
        # 1. Subnet Sweep Detection (/24)
        "subnet_min_hosts": 8,
        "subnet_min_ports": 100,
        "subnet_min_flows": 2000,
        # 2. Single-IP Port Sweep & Scanner Detection
        "min_ports": UDP_SWEEP_MIN_PORTS,
        # 3. Traffic Flood Detection
        "flood_min_flows": FLOOD_MIN_FLOWS,
        # 4. Multi-User Safety Guardrail
        "max_subscribers": MAX_SUBSCRIBERS_FOR_BLOCK,
        # 5. Internal Subscriber Anomaly Scanner
        "private_ip_flow_threshold": 2500,
        "private_ip_target_threshold": 400,
        "private_ip_port_threshold": 1000,
        "port_exhaustion_threshold": 45000,
        "destination_spike_flows": 150000,
        "updated_at": None,
        "updated_by": "system",
        "reason": "Default Active"
    }
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                for k, v in data.items():
                    if v is not None:
                        defaults[k] = v
        defaults["has_ai_keys"] = has_ai_keys()
        defaults["effective_enabled"] = defaults.get("enabled", True) and has_ai_keys()
        return defaults
    except Exception as e:
        logger.error(f"Error reading sync state file ({STATE_FILE}): {e}")
    defaults["has_ai_keys"] = has_ai_keys()
    defaults["effective_enabled"] = defaults.get("enabled", True) and has_ai_keys()
    return defaults

def set_threat_config(
    enabled: Optional[bool] = None,
    enforcement_scope: Optional[str] = None,
    subnet_min_hosts: Optional[int] = None,
    subnet_min_ports: Optional[int] = None,
    subnet_min_flows: Optional[int] = None,
    min_ports: Optional[int] = None,
    flood_min_flows: Optional[int] = None,
    max_subscribers: Optional[int] = None,
    private_ip_flow_threshold: Optional[int] = None,
    private_ip_target_threshold: Optional[int] = None,
    private_ip_port_threshold: Optional[int] = None,
    port_exhaustion_threshold: Optional[int] = None,
    destination_spike_flows: Optional[int] = None,
    updated_by: str = "admin",
    reason: str = ""
) -> Dict[str, Any]:
    """Saves updated threat parameters and sync toggle state to persistent JSON."""
    current = get_threat_config()
    state = dict(current)
    if enabled is not None: state["enabled"] = bool(enabled)
    if enforcement_scope is not None and str(enforcement_scope).strip(): state["enforcement_scope"] = str(enforcement_scope).strip()
    if subnet_min_hosts is not None: state["subnet_min_hosts"] = int(subnet_min_hosts)
    if subnet_min_ports is not None: state["subnet_min_ports"] = int(subnet_min_ports)
    if subnet_min_flows is not None: state["subnet_min_flows"] = int(subnet_min_flows)
    if min_ports is not None: state["min_ports"] = int(min_ports)
    if flood_min_flows is not None: state["flood_min_flows"] = int(flood_min_flows)
    if max_subscribers is not None: state["max_subscribers"] = int(max_subscribers)
    if private_ip_flow_threshold is not None: state["private_ip_flow_threshold"] = int(private_ip_flow_threshold)
    if private_ip_target_threshold is not None: state["private_ip_target_threshold"] = int(private_ip_target_threshold)
    if private_ip_port_threshold is not None: state["private_ip_port_threshold"] = int(private_ip_port_threshold)
    if port_exhaustion_threshold is not None: state["port_exhaustion_threshold"] = int(port_exhaustion_threshold)
    if destination_spike_flows is not None: state["destination_spike_flows"] = int(destination_spike_flows)
    state["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    state["updated_by"] = updated_by
    state["reason"] = reason or "Threat parameters updated"
    
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        temp_path = STATE_FILE + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.replace(temp_path, STATE_FILE)
        logger.info(f"Threat config updated by {updated_by}: {state}")
    except Exception as e:
        logger.error(f"Error saving threat config file ({STATE_FILE}): {e}")
    return state

def get_sync_state() -> Dict[str, Any]:
    """Retrieves current stop/start toggle state for MikroTik sync."""
    return get_threat_config()

def set_sync_state(enabled: bool, updated_by: str = "admin", reason: str = "") -> Dict[str, Any]:
    """Sets stop/start toggle state for MikroTik sync while preserving threshold settings."""
    return set_threat_config(enabled=enabled, updated_by=updated_by, reason=reason)

def has_ai_keys() -> bool:
    """Checks if there is at least one active Gemini AI key available for autonomous reasoning."""
    try:
        from ai_key_vault import key_vault
        if key_vault and key_vault.has_active_keys():
            return True
    except Exception:
        pass
    env_key = os.getenv("GEMINI_API_KEY", "").strip()
    return bool(env_key and not env_key.startswith("AQ.dummy"))

def is_sync_enabled() -> bool:
    # Strictly block automated sync if no AI API keys are configured
    if not has_ai_keys():
        return False
    return get_sync_state().get("enabled", True)

def is_whitelisted(addr_str: str) -> bool:
    """Checks if an IP or CIDR network is in the protected ISP / Private whitelist."""
    try:
        net = ipaddress.ip_network(addr_str.strip(), strict=False)
        for w in WHITELIST_NETWORKS:
            if net.subnet_of(w) or w.subnet_of(net) or net.overlaps(w):
                return True
    except Exception as e:
        logger.warning(f"Error parsing address for whitelist check ({addr_str}): {e}")
    return False

def get_ch_client():
    return clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_PORT,
        username=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DB
    )

def send_discord_webhook(added_entries: List[Dict[str, Any]], trigger_type: str = "Automated Sync") -> bool:
    """Sends a rich Discord notification embed for newly blocked prefixes / IPs."""
    if not DISCORD_WEBHOOK_URL or not added_entries:
        return False

    cfg = get_threat_config()
    fields = []
    for entry in added_entries[:12]:
        addr = entry.get("address", "")
        comment = entry.get("comment", "")
        fields.append({
            "name": f"🛡️ `{addr}`",
            "value": f"{comment}",
            "inline": False
        })
        
    extra = len(added_entries) - 12
    if extra > 0:
        fields.append({
            "name": "➕ More Blocked Targets",
            "value": f"...and **{extra}** additional prefix/IP addresses blocked.",
            "inline": False
        })

    payload = {
        "username": "NAT AI Threat Shield",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/3067/3067451.png",
        "embeds": [
            {
                "title": f"🚨 {len(added_entries)} Threat Prefix(es) Blocked on MikroTik",
                "description": f"New scanner and flood targets identified in last 15m logs (≥{cfg['min_ports']} ports, ≤{cfg['max_subscribers']} subs) and added to MikroTik firewall drop list.",
                "color": 15158332, # Red / Crimson
                "fields": [
                    {"name": "Router Node", "value": f"`{MIKROTIK_IP}`", "inline": True},
                    {"name": "Address List", "value": f"`{ADDRESS_LIST_NAME}`", "inline": True},
                    {"name": "Trigger", "value": f"`{trigger_type}`", "inline": True}
                ] + fields,
                "footer": {
                    "text": f"NAT AI Carrier-Grade Threat Intelligence • Live MikroTik Shield (≥{cfg['min_ports']} ports, ≤{cfg['max_subscribers']} subs)"
                },
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        ]
    }

    try:
        req = urllib.request.Request(
            DISCORD_WEBHOOK_URL,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json', 'User-Agent': 'NAT-AI-Agent'}
        )
        with urllib.request.urlopen(req, timeout=6) as response:
            logger.info(f"Discord webhook notification delivered successfully (Status {response.status})")
            return True
    except Exception as e:
        logger.error(f"Failed to send Discord webhook: {e}")
        return False

def exec_mikrotik_cmd(cmd_str: str) -> Tuple[str, str]:
    escaped = cmd_str.replace("'", "'\\''")
    full_cmd = f"sshpass -p '{MIKROTIK_PASSWORD}' ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {MIKROTIK_USER}@{MIKROTIK_IP} '{escaped}'"
    res = subprocess.run(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.stdout, res.stderr

def get_mikrotik_address_list(list_name: str = ADDRESS_LIST_NAME) -> List[Dict[str, Any]]:
    """Fetches currently configured entries in the MikroTik address-list."""
    out, err = exec_mikrotik_cmd(f"/ip firewall address-list print detail without-paging where list=\"{list_name}\"")
    items = []
    
    current_item = {}
    for line in out.splitlines():
        line_s = line.strip()
        if not line_s or line_s.startswith("Flags:"):
            continue
        
        parts = line_s.split()
        if len(parts) >= 2 and parts[0].isdigit():
            if current_item and "address" in current_item:
                items.append(current_item)
            current_item = {"id": parts[0]}
            
        for token in parts:
            if token.startswith("list="):
                current_item["list"] = token.split("=", 1)[1]
            elif token.startswith("address="):
                current_item["address"] = token.split("=", 1)[1]
            elif token.startswith("comment="):
                current_item["comment"] = token.split("=", 1)[1].strip('"')
            elif token.startswith("creation-time="):
                current_item["creation_time"] = token.split("=", 1)[1]

        if ";;;" in line_s:
            comment_text = line_s.split(";;;", 1)[1].strip()
            current_item["comment"] = comment_text

    if current_item and "address" in current_item:
        items.append(current_item)

    if not items:
        out_simple, _ = exec_mikrotik_cmd(f"/ip firewall address-list print without-paging where list=\"{list_name}\"")
        for l in out_simple.splitlines():
            p = l.strip().split()
            if len(p) >= 3 and p[1] == list_name:
                items.append({
                    "id": p[0],
                    "list": p[1],
                    "address": p[2],
                    "comment": "Configured address",
                    "creation_time": " ".join(p[3:]) if len(p) > 3 else ""
                })

    return items

def add_to_mikrotik(address: str, comment: str = "Auto-detected threat", list_name: str = ADDRESS_LIST_NAME, notify_discord: bool = True) -> Tuple[bool, str]:
    """Adds an IP or CIDR subnet to MikroTik address list and notifies Discord, enforcing strict whitelist protection."""
    address = address.strip()
    
    if is_whitelisted(address):
        msg = f"Address/prefix {address} belongs to protected ISP subnet (203.0.113.0/24 or Private/CGNAT) and CANNOT be blocked."
        logger.warning(f"BLOCKED ACTION PREVENTED: {msg}")
        return False, msg

    clean_comment = comment.replace('"', '').replace("'", "")
    cmd = f"/ip firewall address-list add list={list_name} address={address} comment=\"{clean_comment}\""
    out, err = exec_mikrotik_cmd(cmd)
    if "already have" in out.lower() or "failure" in err.lower():
        return False, f"{out} {err}".strip()
    
    if notify_discord:
        send_discord_webhook([{"address": address, "comment": clean_comment}], trigger_type="Manual Addition")
        
    return True, "Added successfully"

def remove_from_mikrotik(address: str, list_name: str = ADDRESS_LIST_NAME) -> Tuple[bool, str]:
    """Removes an IP or CIDR subnet from MikroTik address list."""
    address = address.strip()
    cmd = f"/ip firewall address-list remove [find where list=\"{list_name}\" and address=\"{address}\"]"
    out, err = exec_mikrotik_cmd(cmd)
    if "failure" in err.lower() or "error" in out.lower():
        return False, f"{out} {err}".strip()
    return True, "Removed successfully"

def find_scanner_and_flood_candidates(minutes: int = 15, limit: int = 100, router_filter: str = MIKROTIK_IP,
                                      min_ports: Optional[int] = None, max_subscribers: Optional[int] = None) -> Tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
    """Identifies scanning, sweeping, and flooding external destination IPs/subnets in the given time window.
    Strictly filters out ISP/private IPs and enforces minimum distinct ports and maximum subscriber guardrails."""
    cfg = get_threat_config()
    sweep_min_ports = int(min_ports) if min_ports is not None else cfg["min_ports"]
    max_subs_allowed = int(max_subscribers) if max_subscribers is not None else cfg["max_subscribers"]
    flood_flows_threshold = cfg.get("flood_min_flows", FLOOD_MIN_FLOWS)
    sub_min_hosts = int(cfg.get("subnet_min_hosts", 8))
    sub_min_ports = int(cfg.get("subnet_min_ports", 100))
    sub_min_flows = int(cfg.get("subnet_min_flows", 2000))

    client = get_ch_client()
    try:
        candidates = []
        subnet_groups = defaultdict(list)
        detected_subnet_cidrs = set()

        # Phase 1: Native /24 Horizontal Subnet Sweep Detection
        q_subnets = f"""
        SELECT 
            concat(toString(IPv4NumToString(bitAnd(toUInt32(dst_ip), 4294967040))), '/24') as subnet_cidr,
            count() as total_flows,
            uniq(dst_ip) as distinct_host_ips,
            uniq(dst_port) as distinct_ports,
            uniq(src_ip) as subscriber_count,
            topK(5)(dst_port) as top_ports,
            topK(2)(protocol) as protocols,
            topK(3)(toString(src_ip)) as sample_attackers,
            topK(3)(toString(router_ip)) as routers,
            min(timestamp) as first_seen,
            max(timestamp) as last_seen
        FROM nat_logs.translations
        WHERE toDate(timestamp) >= today() - 1 AND timestamp >= now() - INTERVAL {int(minutes)} MINUTE
          AND router_ip = '{router_filter}'
          AND NOT (dst_ip >= IPv4StringToNum('203.0.113.0') AND dst_ip <= IPv4StringToNum('203.0.113.255'))
          AND NOT (dst_ip >= IPv4StringToNum('100.64.0.0') AND dst_ip <= IPv4StringToNum('100.127.255.255'))
          AND NOT (dst_ip >= IPv4StringToNum('198.51.100.0') AND dst_ip <= IPv4StringToNum('198.51.100.255'))
          AND NOT (dst_ip >= IPv4StringToNum('10.0.0.0') AND dst_ip <= IPv4StringToNum('10.255.255.255'))
          AND NOT (dst_ip >= IPv4StringToNum('172.16.0.0') AND dst_ip <= IPv4StringToNum('172.31.255.255'))
          AND NOT (dst_ip >= IPv4StringToNum('192.168.0.0') AND dst_ip <= IPv4StringToNum('192.168.255.255'))
        GROUP BY subnet_cidr
        HAVING (
            (distinct_host_ips >= {sub_min_hosts} AND (distinct_ports >= {sub_min_ports} OR total_flows >= {sub_min_flows}))
            OR
            (distinct_ports >= {sweep_min_ports} OR total_flows >= {flood_flows_threshold})
        )
        AND (subscriber_count <= {max_subs_allowed})
        ORDER BY distinct_ports DESC, total_flows DESC
        LIMIT {int(limit)}
        SETTINGS max_threads = 8, max_execution_time = 30
        """
        sub_rows = client.query(q_subnets).result_rows
        for r in sub_rows:
            subnet_cidr = str(r[0])
            if is_whitelisted(subnet_cidr):
                continue

            flows = int(r[1])
            host_ips = int(r[2])
            ports = int(r[3])
            subs = int(r[4])
            top_ports = [int(p) for p in r[5]]
            protocols = [str(p) for p in r[6]]
            sample_attackers = [str(s) for s in r[7]]
            routers = [str(rt) for rt in r[8]]
            first_seen = str(r[9])
            last_seen = str(r[10])

            score = min(100, int((ports * 0.5) + (flows / 1000) + (host_ips * 2)))
            severity = "CRITICAL" if score >= 85 or flows >= 50000 or ports >= 5000 else "HIGH"

            item = {
                "dst_ip": subnet_cidr,
                "threat_type": "SUBNET_SWEEP",
                "severity": severity,
                "score": score,
                "total_flows": flows,
                "distinct_ports": ports,
                "distinct_host_ips": host_ips,
                "subscriber_count": subs,
                "top_ports": top_ports,
                "protocols": protocols,
                "sample_attackers": sample_attackers,
                "routers": routers,
                "first_seen": first_seen,
                "last_seen": last_seen
            }
            candidates.append(item)
            subnet_groups[subnet_cidr].append(item)
            detected_subnet_cidrs.add(subnet_cidr)

        # Phase 2: Single IP Scanning & Flooding Detection
        q_single = f"""
        SELECT 
            dst_ip,
            count() AS total_flows,
            uniq(dst_port) AS distinct_ports,
            uniq(src_ip) AS subscriber_count,
            topK(5)(dst_port) AS top_ports,
            topK(2)(protocol) AS protocols,
            topK(3)(src_ip) AS sample_attackers,
            topK(3)(router_ip) AS routers,
            min(timestamp) AS first_seen,
            max(timestamp) AS last_seen
        FROM nat_logs.translations
        WHERE toDate(timestamp) >= today() - 1 AND timestamp >= now() - INTERVAL {int(minutes)} MINUTE
          AND router_ip = '{router_filter}'
          AND NOT (dst_ip >= IPv4StringToNum('203.0.113.0') AND dst_ip <= IPv4StringToNum('203.0.113.255'))
          AND NOT (dst_ip >= IPv4StringToNum('100.64.0.0') AND dst_ip <= IPv4StringToNum('100.127.255.255'))
          AND NOT (dst_ip >= IPv4StringToNum('198.51.100.0') AND dst_ip <= IPv4StringToNum('198.51.100.255'))
          AND NOT (dst_ip >= IPv4StringToNum('10.0.0.0') AND dst_ip <= IPv4StringToNum('10.255.255.255'))
          AND NOT (dst_ip >= IPv4StringToNum('172.16.0.0') AND dst_ip <= IPv4StringToNum('172.31.255.255'))
          AND NOT (dst_ip >= IPv4StringToNum('192.168.0.0') AND dst_ip <= IPv4StringToNum('192.168.255.255'))
        GROUP BY dst_ip
        HAVING ((distinct_ports >= {sweep_min_ports}) OR (total_flows >= {flood_flows_threshold} AND distinct_ports >= 5))
           AND (subscriber_count <= {max_subs_allowed})
        ORDER BY distinct_ports DESC, total_flows DESC
        LIMIT {int(limit)}
        SETTINGS max_threads = 8, max_execution_time = 30
        """
        rows = client.query(q_single).result_rows

        for r in rows:
            dst_ip_str = str(r[0])
            if is_whitelisted(dst_ip_str):
                continue

            flows = int(r[1])
            ports = int(r[2])
            subs = int(r[3])
            top_ports = [int(p) for p in r[4]]
            protocols = [str(p) for p in r[5]]
            sample_attackers = [str(s) for s in r[6]]
            routers = [str(rt) for rt in r[7]]
            first_seen = str(r[8])
            last_seen = str(r[9])

            if subs > max_subs_allowed:
                continue

            is_udp = "UDP" in protocols
            if is_udp:
                if ports < sweep_min_ports and flows < flood_flows_threshold:
                    continue
                threat_type = "UDP_PORT_SWEEP" if ports >= sweep_min_ports else "TRAFFIC_FLOOD"
            elif flows >= flood_flows_threshold and ports < 10:
                threat_type = "TRAFFIC_FLOOD"
            elif ports >= sweep_min_ports:
                threat_type = "VERTICAL_PORT_SCAN"
            else:
                continue

            score = min(100, int((ports * 1.5) + (flows / 500) + (subs * 5)))
            severity = "CRITICAL" if score >= 85 or ports >= 2000 else ("HIGH" if score >= 50 or ports >= sweep_min_ports else "WARNING")

            item = {
                "dst_ip": dst_ip_str,
                "threat_type": threat_type,
                "severity": severity,
                "score": score,
                "total_flows": flows,
                "distinct_ports": ports,
                "subscriber_count": subs,
                "top_ports": top_ports,
                "protocols": protocols,
                "sample_attackers": sample_attackers,
                "routers": routers,
                "first_seen": first_seen,
                "last_seen": last_seen
            }

            try:
                ip_net = str(ipaddress.ip_network(f"{dst_ip_str}/24", strict=False))
                if not is_whitelisted(ip_net):
                    subnet_groups[ip_net].append(item)
                    # If this subnet wasn't already caught as a full SUBNET_SWEEP, add the individual IP
                    if ip_net not in detected_subnet_cidrs:
                        candidates.append(item)
            except Exception:
                candidates.append(item)

        return candidates, subnet_groups
    finally:
        client.close()

def prune_redundant_single_ips(address_list: str = ADDRESS_LIST_NAME, dry_run: bool = False) -> Dict[str, Any]:
    """Audits MikroTik address list and removes individual IPs that are already covered by an existing subnet."""
    items = get_mikrotik_address_list(address_list)
    networks = []
    single_ips = []

    for it in items:
        addr = it.get('address', '').strip()
        if not addr:
            continue
        try:
            if '/' in addr:
                net = ipaddress.ip_network(addr, strict=False)
                if net.prefixlen < 32:
                    networks.append({"net": net, "raw": addr, "comment": it.get("comment", "")})
                else:
                    ip_obj = ipaddress.ip_address(addr.split('/')[0])
                    single_ips.append({"ip": ip_obj, "raw": addr, "comment": it.get("comment", "")})
            else:
                ip_obj = ipaddress.ip_address(addr)
                single_ips.append({"ip": ip_obj, "raw": addr, "comment": it.get("comment", "")})
        except Exception as e:
            logger.debug(f"Error parsing address for prune ({addr}): {e}")

    redundant = []
    for s in single_ips:
        ip = s['ip']
        for n in networks:
            if ip in n['net']:
                redundant.append({
                    "ip": s['raw'],
                    "covered_by": n['raw'],
                    "comment": s['comment']
                })
                break

    logger.info(f"Subnet audit: Found {len(networks)} subnets and {len(redundant)} redundant single IPs in list '{address_list}'.")
    
    removed = []
    errors = []
    if not dry_run and redundant:
        for r in redundant:
            addr = r['ip']
            logger.info(f"Removing redundant single IP {addr} (covered by {r['covered_by']})")
            success, msg = remove_from_mikrotik(addr, address_list)
            if success:
                removed.append(addr)
            else:
                errors.append({"address": addr, "error": msg})
            time.sleep(0.05)

    return {
        "total_subnets": len(networks),
        "total_single_ips": len(single_ips),
        "redundant_found": len(redundant),
        "removed": removed,
        "errors": errors
    }

def audit_and_prune_mikrotik(address_list: str = ADDRESS_LIST_NAME, min_ports: Optional[int] = None, 
                              max_subscribers: Optional[int] = None, dry_run: bool = False) -> Dict[str, Any]:
    """Audits current MikroTik address-list entries against admin-configured thresholds 
    (>= min_ports, <= max_subscribers, not whitelisted, and non-redundant), removing non-compliant entries."""
    import re
    cfg = get_threat_config()
    min_p = int(min_ports) if min_ports is not None else cfg["min_ports"]
    max_s = int(max_subscribers) if max_subscribers is not None else cfg["max_subscribers"]
    flood_f = cfg.get("flood_min_flows", FLOOD_MIN_FLOWS)

    items = get_mikrotik_address_list(address_list)
    total_before = len(items)
    
    to_remove = []
    to_keep = []
    need_ch_query = []

    # 1. Parse comments & whitelists
    for it in items:
        addr = it.get('address', '').strip()
        comment = it.get('comment', '') or ''
        
        if is_whitelisted(addr):
            to_remove.append({
                "address": addr,
                "reason": "Whitelisted ISP / Private network (protected)",
                "comment": comment
            })
            continue

        m_ports = re.search(r'(?:max_ports|ports)=(\d+)', comment)
        m_flows = re.search(r'flows=(\d+)', comment)
        
        if m_ports:
            ports_val = int(m_ports.group(1))
            flows_val = int(m_flows.group(1)) if m_flows else 0
            
            if ports_val < min_p and flows_val < flood_f:
                to_remove.append({
                    "address": addr,
                    "reason": f"Distinct ports ({ports_val}) < {min_p} threshold and flows ({flows_val}) < {flood_f}",
                    "ports": ports_val,
                    "flows": flows_val,
                    "comment": comment
                })
            else:
                to_keep.append({
                    "address": addr,
                    "reason": f"Ports ({ports_val}) >= {min_p}",
                    "ports": ports_val,
                    "flows": flows_val,
                    "comment": comment
                })
        else:
            need_ch_query.append(it)

    # 2. Query ClickHouse for entries without port comments
    if need_ch_query:
        client = None
        try:
            client = get_ch_client()
            for it in need_ch_query:
                addr = it.get('address', '').strip()
                comment = it.get('comment', '') or ''
                try:
                    if '/' in addr:
                        net = ipaddress.ip_network(addr, strict=False)
                        q = f"""
                        SELECT count() AS total_flows, uniq(dst_port) AS distinct_ports, uniq(src_ip) AS subscriber_count
                        FROM nat_logs.translations
                        WHERE toDate(timestamp) >= today() - 2 AND timestamp >= now() - INTERVAL 48 HOUR
                          AND dst_ip >= toIPv4('{net.network_address}') AND dst_ip <= toIPv4('{net.broadcast_address}')
                        SETTINGS max_threads=4, max_execution_time=5
                        """
                    else:
                        q = f"""
                        SELECT count() AS total_flows, uniq(dst_port) AS distinct_ports, uniq(src_ip) AS subscriber_count
                        FROM nat_logs.translations
                        WHERE toDate(timestamp) >= today() - 2 AND timestamp >= now() - INTERVAL 48 HOUR
                          AND dst_ip = toIPv4('{addr}')
                        SETTINGS max_threads=4, max_execution_time=5
                        """
                    r = client.query(q).result_rows[0]
                    flows, ports, subs = int(r[0]), int(r[1]), int(r[2])
                    if subs > max_s:
                        to_remove.append({
                            "address": addr,
                            "reason": f"Subscribers ({subs}) > {max_s} threshold",
                            "ports": ports,
                            "subs": subs,
                            "flows": flows,
                            "comment": comment
                        })
                    elif ports < min_p and flows < flood_f:
                        to_remove.append({
                            "address": addr,
                            "reason": f"Ports ({ports}) < {min_p} threshold and flows ({flows}) < {flood_f}",
                            "ports": ports,
                            "subs": subs,
                            "flows": flows,
                            "comment": comment
                        })
                    else:
                        to_keep.append({
                            "address": addr,
                            "reason": f"ClickHouse verified: ports={ports} >= {min_p}, subs={subs} <= {max_s}",
                            "ports": ports,
                            "subs": subs,
                            "flows": flows,
                            "comment": comment
                        })
                except Exception as e:
                    to_remove.append({
                        "address": addr,
                        "reason": f"Legacy entry without port metadata or qualifying activity",
                        "comment": comment
                    })
        except Exception as err:
            logger.warning(f"Error querying ClickHouse during audit: {err}")
        finally:
            if client:
                client.close()

    # 3. Check subscriber counts for kept single IPs over last 48h
    kept_single_ips = [k['address'] for k in to_keep if '/' not in k['address']]
    if kept_single_ips:
        client = None
        try:
            client = get_ch_client()
            ip_chunks = [kept_single_ips[i:i+40] for i in range(0, len(kept_single_ips), 40)]
            for chunk in ip_chunks:
                chunk_str = ",".join(f"toIPv4('{a}')" for a in chunk)
                q = f"""
                SELECT IPv4NumToString(dst_ip) AS ip_str, uniq(src_ip) AS subscriber_count
                FROM nat_logs.translations
                WHERE toDate(timestamp) >= today() - 2 AND timestamp >= now() - INTERVAL 48 HOUR
                  AND dst_ip IN ({chunk_str})
                GROUP BY dst_ip
                HAVING subscriber_count > {max_s}
                SETTINGS max_threads=4, max_execution_time=10
                """
                high_subs = client.query(q).result_rows
                for r in high_subs:
                    ip, s_cnt = str(r[0]), int(r[1])
                    to_keep = [k for k in to_keep if k['address'] != ip]
                    to_remove.append({
                        "address": ip,
                        "reason": f"Subscribers ({s_cnt}) > {max_s} threshold in recent logs",
                        "subs": s_cnt
                    })
        except Exception as e:
            logger.warning(f"Error checking subscriber count in audit: {e}")
        finally:
            if client:
                client.close()

    # 4. Check redundant single IPs covered by subnets in to_keep
    kept_nets = []
    for k in to_keep:
        addr = k['address']
        if '/' in addr and not addr.endswith('/32'):
            try:
                kept_nets.append(ipaddress.ip_network(addr, strict=False))
            except Exception:
                pass

    filtered_to_keep = []
    for k in to_keep:
        addr = k['address']
        if '/' not in addr or addr.endswith('/32'):
            try:
                ip_obj = ipaddress.ip_address(addr.split('/')[0])
                covered_net = None
                for net in kept_nets:
                    if ip_obj in net:
                        covered_net = net
                        break
                if covered_net:
                    to_remove.append({
                        "address": addr,
                        "reason": f"Redundant single IP covered by subnet {covered_net}",
                        "comment": k.get('comment', '')
                    })
                    continue
            except Exception:
                pass
        filtered_to_keep.append(k)

    to_keep = filtered_to_keep

    reasons_summary = {}
    for r in to_remove:
        reason_key = r['reason'].split('(')[0].strip()
        reasons_summary[reason_key] = reasons_summary.get(reason_key, 0) + 1

    removed_count = 0
    if not dry_run and to_remove:
        addresses_to_remove = [item["address"] for item in to_remove]
        chunk_size = 25
        for i in range(0, len(addresses_to_remove), chunk_size):
            chunk = addresses_to_remove[i:i+chunk_size]
            cmd_parts = [f'/ip firewall address-list remove [find where list="{address_list}" and address="{addr}"]' for addr in chunk]
            combined_cmd = " ; ".join(cmd_parts)
            exec_mikrotik_cmd(combined_cmd)
            removed_count += len(chunk)
            time.sleep(0.1)

    after_items = get_mikrotik_address_list(address_list) if not dry_run else items

    return {
        "status": "ok",
        "dry_run": dry_run,
        "thresholds_applied": {
            "min_ports": min_p,
            "max_subscribers": max_s,
            "flood_min_flows": flood_f
        },
        "total_before": total_before,
        "to_keep_count": len(to_keep),
        "to_remove_count": len(to_remove),
        "removed_count": removed_count if not dry_run else 0,
        "remaining_count": len(after_items),
        "reasons_summary": reasons_summary,
        "removed_entries": to_remove[:100]
    }

def sync_all(dry_run: bool = False, minutes: int = 15) -> Dict[str, Any]:
    cfg = get_threat_config()
    logger.info(f"Synchronizing scanner/flood threats with MikroTik ({MIKROTIK_IP}). Sync enabled: {cfg.get('enabled')}")

    # If sync is stopped or no AI keys exist, stop immediately unless dry-run
    if not is_sync_enabled() and not dry_run:
        reason_msg = "Automated threat sync is blocked: Requires at least one configured AI API key. Threats must be added manually." if not has_ai_keys() else "MikroTik automatic synchronization is currently STOPPED. No changes made."
        logger.warning(f"MikroTik sync skipped: {reason_msg}")
        existing_items = get_mikrotik_address_list(ADDRESS_LIST_NAME)
        return {
            "status": "blocked" if not has_ai_keys() else "stopped",
            "message": reason_msg,
            "has_ai_keys": has_ai_keys(),
            "sync_state": cfg,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "minutes_window": minutes,
            "mikrotik_ip": MIKROTIK_IP,
            "address_list": ADDRESS_LIST_NAME,
            "detected_candidates": 0,
            "new_entries_to_add": 0,
            "current_mikrotik_entries": len(existing_items),
            "synced": [],
            "errors": []
        }

    candidates, subnet_groups = find_scanner_and_flood_candidates(minutes=minutes)
    existing_items = get_mikrotik_address_list(ADDRESS_LIST_NAME)
    existing_addrs = {item["address"]: item for item in existing_items if "address" in item}

    to_add = []
    added_subnets = set()
    sweep_min_ports = cfg["min_ports"]
    max_subs_allowed = cfg["max_subscribers"]

    # 1. Process /24 Subnet Sweeps
    for subnet_str, items in subnet_groups.items():
        if is_whitelisted(subnet_str):
            continue
            
        # Check if native SUBNET_SWEEP detected
        subnet_threat_items = [i for i in items if i.get("threat_type") == "SUBNET_SWEEP"]
        if subnet_threat_items:
            s_item = subnet_threat_items[0]
            flows = s_item["total_flows"]
            ports = s_item["distinct_ports"]
            host_ips = s_item.get("distinct_host_ips", 256)
            sample_att = s_item.get("sample_attackers", [])[:2]
            att_str = f", attackers={', '.join(sample_att)}" if sample_att else ""
            comment = f"Auto-detected SUBNET_SWEEP ({host_ips} IPs, ports={ports:,}, flows={flows:,}{att_str})"
            to_add.append({
                "address": subnet_str,
                "comment": comment,
                "reason": f"SUBNET_SWEEP across {host_ips} host IPs ({ports:,} ports, {flows:,} flows)"
            })
            added_subnets.add(subnet_str)
        else:
            valid_items = [
                i for i in items 
                if (i.get("distinct_ports", 0) >= sweep_min_ports or i.get("threat_type") == "TRAFFIC_FLOOD") 
                and i.get("subscriber_count", 0) <= max_subs_allowed
            ]
            if len(valid_items) >= 2:
                total_flows = sum(i["total_flows"] for i in valid_items)
                max_ports = max(i["distinct_ports"] for i in valid_items)
                sample_att = list(set(sum([i.get("sample_attackers", []) for i in valid_items], [])))[:2]
                att_str = f", attackers={', '.join(sample_att)}" if sample_att else ""
                comment = f"Auto-detected subnet sweep ({len(valid_items)} IPs, max_ports={max_ports:,}, flows={total_flows:,}{att_str})"
                to_add.append({
                    "address": subnet_str,
                    "comment": comment,
                    "reason": f"Subnet sweep across {len(valid_items)} targets (min_ports>={sweep_min_ports})"
                })
                added_subnets.add(subnet_str)

    # Build list of all covering subnets (existing in MikroTik + newly added)
    all_subnets = list(added_subnets)
    for addr in existing_addrs.keys():
        if '/' in addr and not addr.endswith('/32'):
            all_subnets.append(addr)

    # Add individual targets if not covered by any /24 or larger subnet block
    for c in candidates:
        ip_str = c["dst_ip"]
        if is_whitelisted(ip_str):
            continue

        # Check if covered by any subnet
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if any(ip_obj in ipaddress.ip_network(s, strict=False) for s in all_subnets):
                logger.info(f"Skipping {ip_str} because it is covered by subnet in MikroTik")
                continue
        except Exception:
            pass

        # Enforce distinct_ports >= min_ports for UDP sweep targets
        if c.get("threat_type") == "UDP_PORT_SWEEP" and c.get("distinct_ports", 0) < sweep_min_ports:
            logger.info(f"Skipping {ip_str} because distinct_ports ({c.get('distinct_ports')}) < {sweep_min_ports}")
            continue

        # Enforce subscriber_count <= max_subscribers
        if c.get("subscriber_count", 0) > max_subs_allowed:
            logger.info(f"Skipping {ip_str} because subscriber_count ({c.get('subscriber_count')}) > {max_subs_allowed}")
            continue

        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if any(ip_obj in ipaddress.ip_network(s) for s in added_subnets):
                continue
        except Exception:
            pass

        if ip_str in existing_addrs:
            continue

        sample_att = c.get("sample_attackers", [])[:2]
        att_str = f", attackers={', '.join(sample_att)}" if sample_att else ""
        comment = f"Auto-detected {c['threat_type']} (ports={c['distinct_ports']}, flows={c['total_flows']}{att_str})"
        to_add.append({
            "address": ip_str,
            "comment": comment,
            "reason": f"{c['threat_type']} ({c['distinct_ports']} ports, {c['total_flows']} flows)"
        })

    results = {
        "status": "ok",
        "sync_state": cfg,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "minutes_window": minutes,
        "mikrotik_ip": MIKROTIK_IP,
        "address_list": ADDRESS_LIST_NAME,
        "detected_candidates": len(candidates),
        "new_entries_to_add": len(to_add),
        "current_mikrotik_entries": len(existing_items),
        "synced": [],
        "errors": []
    }

    successfully_added = []

    for entry in to_add:
        addr = entry["address"]
        comment = entry["comment"]
        
        if addr in existing_addrs:
            continue

        if dry_run:
            logger.info(f"[DRY-RUN] Would add: {addr} ({comment})")
            results["synced"].append({"address": addr, "comment": comment, "status": "dry_run"})
        else:
            success, msg = add_to_mikrotik(addr, comment, ADDRESS_LIST_NAME, notify_discord=False)
            if success:
                logger.info(f"Successfully added to MikroTik: {addr}")
                results["synced"].append({"address": addr, "comment": comment, "status": "added"})
                existing_addrs[addr] = {"address": addr, "comment": comment}
                successfully_added.append({"address": addr, "comment": comment})
            else:
                logger.warning(f"Error adding {addr}: {msg}")
                results["errors"].append({"address": addr, "error": msg})

    # Send consolidated Discord notification for all newly added entries
    if successfully_added and not dry_run:
        send_discord_webhook(successfully_added, trigger_type="Automated 15m Sync")

    # Prune any redundant single IPs covered by subnets
    if not dry_run and added_subnets:
        prune_redundant_single_ips(ADDRESS_LIST_NAME)

    return results

def main():
    dry = "--dry-run" in sys.argv
    audit = "--audit" in sys.argv
    prune = "--prune" in sys.argv
    mins = 15
    for arg in sys.argv:
        if arg.startswith("--minutes="):
            try:
                mins = int(arg.split("=")[1])
            except Exception:
                pass
    
    if audit or prune:
        res = audit_and_prune_mikrotik(dry_run=(not prune))
        print(json.dumps(res, indent=2))
    else:
        res = sync_all(dry_run=dry, minutes=mins)
        print(json.dumps(res, indent=2))

if __name__ == "__main__":
    main()
