#!/usr/bin/env python3
import os
import sys
import time
import json
import logging
import ipaddress
import subprocess
import urllib.request
from collections import defaultdict
from typing import Dict, List, Tuple, Any, Optional
import clickhouse_connect
try:
    import router_sync as mikrotik_sync
except ImportError:
    import mikrotik_sync

import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("daily_threat_sync")

MIKROTIK_IP = getattr(config, "MIKROTIK_IP", "")
MIKROTIK_USER = getattr(config, "MIKROTIK_USER", "natlog")
MIKROTIK_PASSWORD = getattr(config, "MIKROTIK_PASSWORD", "")
ADDRESS_LIST_NAME = os.getenv("MIKROTIK_ADDRESS_LIST", "scanner")

STATE_FILE = os.getenv("SYNC_STATE_FILE", "/opt/nat-ai-agent/data/mikrotik_sync_state.json")
DISCORD_WEBHOOK_URL = getattr(config, "DISCORD_WEBHOOK_URL", "")

CLICKHOUSE_HOST = getattr(config, "CLICKHOUSE_HOST", "127.0.0.1")
CLICKHOUSE_PORT = int(getattr(config, "CLICKHOUSE_PORT", 8123))
CLICKHOUSE_DB = getattr(config, "CLICKHOUSE_DB", "nat_logs")
CLICKHOUSE_USER = getattr(config, "CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = getattr(config, "CLICKHOUSE_PASSWORD", "")

WHITELIST_NETWORKS = mikrotik_sync.WHITELIST_NETWORKS

def is_sync_enabled() -> bool:
    return mikrotik_sync.is_sync_enabled()

def is_whitelisted(addr_str: str) -> bool:
    return mikrotik_sync.is_whitelisted(addr_str)

def get_ch_client():
    return mikrotik_sync.get_ch_client()

def exec_mikrotik_cmd(cmd_str: str) -> Tuple[str, str]:
    return mikrotik_sync.exec_mikrotik_cmd(cmd_str)

def get_mikrotik_address_list(list_name: str = ADDRESS_LIST_NAME) -> List[Dict[str, Any]]:
    return mikrotik_sync.get_mikrotik_address_list(list_name)

def send_discord_webhook(added_entries: List[Dict[str, Any]], trigger_type: str = "Daily 3AM Sync") -> bool:
    """Sends a rich Discord notification embed for newly blocked prefixes / IPs."""
    if not DISCORD_WEBHOOK_URL or not added_entries:
        return False

    cfg = mikrotik_sync.get_threat_config()
    fields = []
    for entry in added_entries[:15]:
        addr = entry.get("address", "")
        comment = entry.get("comment", "")
        fields.append({
            "name": f"🛡️ `{addr}`",
            "value": f"{comment}",
            "inline": False
        })
        
    extra = len(added_entries) - 15
    if extra > 0:
        fields.append({
            "name": "➕ More Blocked Targets",
            "value": f"...and **{extra}** additional prefix/IP addresses blocked.",
            "inline": False
        })

    payload = {
        "username": "NAT AI Threat Shield (Daily 3 AM Sync)",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/3067/3067451.png",
        "embeds": [
            {
                "title": f"🚨 Daily 3 AM Sync: {len(added_entries)} Scanner/Flood Targets Blocked",
                "description": f"Analyzed 24h subscriber scan and flood logs on router `{MIKROTIK_IP}` and applied firewall drop rules.",
                "color": 15158332, # Red / Crimson
                "fields": [
                    {"name": "Router Node", "value": f"`{MIKROTIK_IP}`", "inline": True},
                    {"name": "Address List", "value": f"`{ADDRESS_LIST_NAME}`", "inline": True},
                    {"name": "Execution Time", "value": f"`{time.strftime('%Y-%m-%d %H:%M:%S')}`", "inline": True}
                ] + fields,
                "footer": {
                    "text": f"NAT AI Daily 3AM Intelligence Service • Safe Guardrails Active (≥{cfg['min_ports']} ports, ≤{cfg['max_subscribers']} subs)"
                },
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        ]
    }

    try:
        req = urllib.request.Request(
            DISCORD_WEBHOOK_URL,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json', 'User-Agent': 'NAT-AI-Daily-Agent'}
        )
        with urllib.request.urlopen(req, timeout=6) as response:
            logger.info(f"Discord webhook notification delivered successfully (Status {response.status})")
            return True
    except Exception as e:
        logger.error(f"Failed to send Discord webhook: {e}")
        return False

def find_daily_scanner_subscriber_targets(hours: int = 24, min_ports: Optional[int] = None, 
                                          max_subscribers: Optional[int] = None) -> Tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
    """Analyzes all scanner / flooder subscribers from ai_anomalies and high-spread translations in the last 24h
    and returns their high-confidence destination targets and /24 subnet groupings."""
    cfg = mikrotik_sync.get_threat_config()
    sweep_min_ports = int(min_ports) if min_ports is not None else cfg["min_ports"]
    max_subs_allowed = int(max_subscribers) if max_subscribers is not None else cfg["max_subscribers"]
    flood_flows = cfg.get("flood_min_flows", 10000)
    sub_min_hosts = int(cfg.get("subnet_min_hosts", 8))
    sub_min_ports = int(cfg.get("subnet_min_ports", 100))
    sub_min_flows = int(cfg.get("subnet_min_flows", 2000))

    client = get_ch_client()
    try:
        # Step 1: Identify all bad/scanner subscribers in the last 24h on this router
        q_subs = f"""
        SELECT 
            target_ip AS src_ip,
            count() AS anomaly_count
        FROM nat_logs.ai_anomalies
        WHERE toDate(timestamp) >= today() - 1 AND timestamp >= now() - INTERVAL {int(hours)} HOUR
          AND router_ip = '{MIKROTIK_IP}'
          AND anomaly_type IN ('ABUSE_SCANNER', 'HEAVY_SUBSCRIBER')
        GROUP BY target_ip
        """
        anomaly_subs = [str(r[0]) for r in client.query(q_subs).result_rows]

        # Also get heavy spread subscribers in last 24h
        q_heavy = f"""
        SELECT 
            src_ip,
            count() AS flows,
            uniq(dst_ip) AS distinct_dests,
            uniq(dst_port) AS distinct_ports
        FROM nat_logs.translations
        WHERE toDate(timestamp) >= today() - 1 AND timestamp >= now() - INTERVAL {int(hours)} HOUR
          AND router_ip = '{MIKROTIK_IP}'
        GROUP BY src_ip
        HAVING distinct_dests >= 300 OR distinct_ports >= 300 OR flows >= 5000
        LIMIT 200
        """
        heavy_subs = [str(r[0]) for r in client.query(q_heavy).result_rows]

        all_bad_subs = list(set(anomaly_subs + heavy_subs))
        logger.info(f"Identified {len(all_bad_subs)} anomalous/scanner subscribers in last {hours}h.")

        if not all_bad_subs:
            return [], {}

        sub_list_sql = ",".join(f"'{s}'" for s in all_bad_subs)
        candidates = []
        subnet_groups = defaultdict(list)
        detected_subnet_cidrs = set()

        # Step 2a: Query /24 Subnet Sweeps targeted by these scanner subscribers
        q_subnets = f"""
        SELECT 
            concat(toString(IPv4NumToString(bitAnd(toUInt32(dst_ip), 4294967040))), '/24') as subnet_cidr,
            count() as total_flows,
            uniq(dst_ip) as distinct_host_ips,
            uniq(dst_port) as distinct_ports,
            uniq(src_ip) as subscriber_count,
            groupUniqArray(src_ip) as attacking_subscribers,
            topK(5)(dst_port) as sample_ports,
            topK(2)(protocol) as protocols,
            min(timestamp) as first_seen,
            max(timestamp) as last_seen
        FROM nat_logs.translations
        WHERE toDate(timestamp) >= today() - 1 AND timestamp >= now() - INTERVAL {int(hours)} HOUR
          AND router_ip = '{MIKROTIK_IP}'
          AND src_ip IN ({sub_list_sql})
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
            (distinct_ports >= {sweep_min_ports} OR total_flows >= {flood_flows})
        )
        AND (subscriber_count <= {max_subs_allowed})
        ORDER BY distinct_ports DESC, total_flows DESC
        LIMIT 300
        SETTINGS max_threads = 8, max_execution_time = 45
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
            attackers = [str(s) for s in r[5]]
            top_ports = [int(p) for p in r[6]]
            protocols = [str(p) for p in r[7]]
            first_seen = str(r[8])
            last_seen = str(r[9])

            item = {
                "dst_ip": subnet_cidr,
                "threat_type": "SUBNET_SWEEP",
                "total_flows": flows,
                "distinct_ports": ports,
                "distinct_host_ips": host_ips,
                "subscriber_count": subs,
                "attackers": attackers,
                "top_ports": top_ports,
                "protocols": protocols,
                "first_seen": first_seen,
                "last_seen": last_seen
            }
            candidates.append(item)
            subnet_groups[subnet_cidr].append(item)
            detected_subnet_cidrs.add(subnet_cidr)

        # Step 2b: Query individual destination IPs targeted by these scanner subscribers
        q_dsts = f"""
        SELECT 
            dst_ip,
            count() AS total_flows,
            uniq(dst_port) AS distinct_ports,
            uniq(src_ip) AS subscriber_count,
            groupUniqArray(src_ip) AS attacking_subscribers,
            topK(5)(dst_port) AS sample_ports,
            topK(2)(protocol) AS protocols,
            min(timestamp) AS first_seen,
            max(timestamp) AS last_seen
        FROM nat_logs.translations
        WHERE toDate(timestamp) >= today() - 1 AND timestamp >= now() - INTERVAL {int(hours)} HOUR
          AND router_ip = '{MIKROTIK_IP}'
          AND src_ip IN ({sub_list_sql})
          AND NOT (dst_ip >= IPv4StringToNum('203.0.113.0') AND dst_ip <= IPv4StringToNum('203.0.113.255'))
          AND NOT (dst_ip >= IPv4StringToNum('100.64.0.0') AND dst_ip <= IPv4StringToNum('100.127.255.255'))
          AND NOT (dst_ip >= IPv4StringToNum('198.51.100.0') AND dst_ip <= IPv4StringToNum('198.51.100.255'))
          AND NOT (dst_ip >= IPv4StringToNum('10.0.0.0') AND dst_ip <= IPv4StringToNum('10.255.255.255'))
          AND NOT (dst_ip >= IPv4StringToNum('172.16.0.0') AND dst_ip <= IPv4StringToNum('172.31.255.255'))
          AND NOT (dst_ip >= IPv4StringToNum('192.168.0.0') AND dst_ip <= IPv4StringToNum('192.168.255.255'))
        GROUP BY dst_ip
        HAVING ((distinct_ports >= {sweep_min_ports}) OR (total_flows >= {flood_flows} AND distinct_ports >= 5))
           AND (subscriber_count <= {max_subs_allowed})
        ORDER BY distinct_ports DESC, total_flows DESC
        LIMIT 500
        SETTINGS max_threads = 8, max_execution_time = 45
        """
        rows = client.query(q_dsts).result_rows
        logger.info(f"Found {len(rows)} high-intensity destination targets from scanner subscribers.")

        for r in rows:
            dst_ip_str = str(r[0])
            if is_whitelisted(dst_ip_str):
                continue

            flows = int(r[1])
            ports = int(r[2])
            subs = int(r[3])
            attackers = [str(s) for s in r[4]]
            top_ports = [int(p) for p in r[5]]
            protocols = [str(p) for p in r[6]]
            first_seen = str(r[7])
            last_seen = str(r[8])

            if subs > max_subs_allowed:
                continue

            is_udp = "UDP" in protocols
            if is_udp:
                if ports < sweep_min_ports and flows < flood_flows:
                    continue
                threat_type = "UDP_PORT_SWEEP" if ports >= sweep_min_ports else "TRAFFIC_FLOOD"
            elif flows >= flood_flows and ports < 10:
                threat_type = "TRAFFIC_FLOOD"
            elif ports >= sweep_min_ports:
                threat_type = "VERTICAL_PORT_SCAN"
            else:
                continue

            item = {
                "dst_ip": dst_ip_str,
                "threat_type": threat_type,
                "total_flows": flows,
                "distinct_ports": ports,
                "subscriber_count": subs,
                "attackers": attackers,
                "top_ports": top_ports,
                "protocols": protocols,
                "first_seen": first_seen,
                "last_seen": last_seen
            }

            try:
                ip_net = str(ipaddress.ip_network(f"{dst_ip_str}/24", strict=False))
                if not is_whitelisted(ip_net):
                    subnet_groups[ip_net].append(item)
                    if ip_net not in detected_subnet_cidrs:
                        candidates.append(item)
            except Exception:
                candidates.append(item)

        return candidates, subnet_groups
    finally:
        client.close()

def run_daily_sync(dry_run: bool = False, hours: int = 24) -> Dict[str, Any]:
    """Executes the daily 3AM sync for scanner subscriber destinations on MikroTik."""
    cfg = mikrotik_sync.get_threat_config()
    sweep_min_ports = cfg["min_ports"]
    max_subs_allowed = cfg["max_subscribers"]

    logger.info("=" * 70)
    logger.info(f"STARTING DAILY 3AM SCANNER DESTINATION SYNC (Router: {MIKROTIK_IP})")
    logger.info(f"Thresholds: min_ports>={sweep_min_ports}, max_subs<={max_subs_allowed}")
    logger.info("=" * 70)

    if not is_sync_enabled() and not dry_run:
        has_keys = getattr(mikrotik_sync, "has_ai_keys", lambda: False)()
        if not has_keys:
            logger.warning("Automated daily threat sync aborted: No active AI API keys configured. Threats must be added manually.")
            return {
                "status": "blocked",
                "reason": "no_ai_keys",
                "message": "Automated threat sync is blocked: Zero AI keys configured. Mitigations must be done manually.",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
        logger.warning("MikroTik sync is currently STOPPED/PAUSED in configuration. Skipping additions.")
        return {
            "status": "stopped",
            "message": "MikroTik sync is stopped by administrator.",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

    candidates, subnet_groups = find_daily_scanner_subscriber_targets(hours=hours)
    existing_items = get_mikrotik_address_list(ADDRESS_LIST_NAME)
    existing_addrs = {item["address"]: item for item in existing_items if "address" in item}

    to_add = []
    added_subnets = set()

    # 1. Evaluate /24 Subnet Sweeps
    for subnet_str, items in subnet_groups.items():
        if is_whitelisted(subnet_str):
            continue

        subnet_threat_items = [i for i in items if i.get("threat_type") == "SUBNET_SWEEP"]
        if subnet_threat_items:
            s_item = subnet_threat_items[0]
            flows = s_item["total_flows"]
            ports = s_item["distinct_ports"]
            host_ips = s_item.get("distinct_host_ips", 256)
            sample_att = s_item.get("attackers", [])[:2]
            att_str = f", attackers={', '.join(sample_att)}" if sample_att else ""
            comment = f"Daily 3AM SUBNET_SWEEP ({host_ips} IPs, ports={ports:,}, flows={flows:,}{att_str})"
            if subnet_str not in existing_addrs:
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
            if len(valid_items) >= 2 or (len(items) >= 1 and max(i["distinct_ports"] for i in items) >= 5000):
                total_flows = sum(i["total_flows"] for i in valid_items) if valid_items else sum(i["total_flows"] for i in items)
                max_ports = max(i["distinct_ports"] for i in (valid_items or items))
                sample_att = list(set(sum([i.get("attackers", []) for i in (valid_items or items)], [])))[:2]
                att_str = f", attackers={', '.join(sample_att)}" if sample_att else ""
                comment = f"Daily 3AM subnet sweep ({len(items)} IPs, max_ports={max_ports:,}, flows={total_flows:,}{att_str})"
                
                if subnet_str not in existing_addrs:
                    to_add.append({
                        "address": subnet_str,
                        "comment": comment,
                        "reason": f"Subnet sweep across {len(items)} targets (min_ports>={sweep_min_ports})"
                    })
                added_subnets.add(subnet_str)

    # Build list of all covering subnets (existing in MikroTik + newly added)
    all_subnets = list(added_subnets)
    for addr in existing_addrs.keys():
        if '/' in addr and not addr.endswith('/32'):
            all_subnets.append(addr)

    # 2. Add individual targets not covered by any subnet block
    for c in candidates:
        ip_str = c["dst_ip"]
        if is_whitelisted(ip_str):
            continue

        # Check if covered by any subnet block
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if any(ip_obj in ipaddress.ip_network(s, strict=False) for s in all_subnets):
                logger.info(f"Skipping {ip_str} because it is covered by subnet in MikroTik")
                continue
        except Exception:
            pass

        if ip_str in existing_addrs:
            continue

        sample_att = c.get("attackers", [])[:2]
        att_str = f", attackers={', '.join(sample_att)}" if sample_att else ""
        comment = f"Daily 3AM {c['threat_type']} (ports={c['distinct_ports']}, flows={c['total_flows']}{att_str})"
        to_add.append({
            "address": ip_str,
            "comment": comment,
            "reason": f"{c['threat_type']} ({c['distinct_ports']} ports, {c['total_flows']} flows)"
        })

    logger.info(f"Identified {len(to_add)} new prefix/IP entries to stage for MikroTik blocking.")

    results = {
        "status": "ok",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hours_window": hours,
        "mikrotik_ip": MIKROTIK_IP,
        "address_list": ADDRESS_LIST_NAME,
        "total_scanner_candidates_found": len(candidates),
        "new_entries_staged": len(to_add),
        "current_mikrotik_entries": len(existing_items),
        "added": [],
        "errors": []
    }

    successfully_added = []

    # Batch add to MikroTik
    if to_add:
        if dry_run:
            for entry in to_add:
                logger.info(f"[DRY-RUN] Would add: {entry['address']} ({entry['comment']})")
                results["added"].append({"address": entry["address"], "comment": entry["comment"], "status": "dry_run"})
        else:
            for entry in to_add:
                addr = entry["address"]
                comment = entry["comment"].replace('"', '').replace("'", "")
                cmd = f"/ip firewall address-list add list={ADDRESS_LIST_NAME} address={addr} comment=\"{comment}\""
                out, err = exec_mikrotik_cmd(cmd)
                if "already have" in out.lower():
                    continue
                if "failure" in err.lower() or "error" in out.lower():
                    logger.warning(f"Error adding {addr}: {out} {err}")
                    results["errors"].append({"address": addr, "error": f"{out} {err}".strip()})
                else:
                    logger.info(f"Successfully added to MikroTik: {addr}")
                    results["added"].append({"address": addr, "comment": comment, "status": "added"})
                    successfully_added.append({"address": addr, "comment": comment})
                    existing_addrs[addr] = {"address": addr, "comment": comment}
                time.sleep(0.1)

    # Discord notification
    if successfully_added and not dry_run:
        send_discord_webhook(successfully_added, trigger_type="Daily 3AM Threat Sync")

    if not dry_run:
        mikrotik_sync.prune_redundant_single_ips(ADDRESS_LIST_NAME)

    logger.info(f"Daily 3AM Sync Completed. Staged: {len(to_add)}, Added: {len(successfully_added)}")
    return results

if __name__ == "__main__":
    dry = "--dry-run" in sys.argv
    hours = 24
    for arg in sys.argv:
        if arg.startswith("--hours="):
            try:
                hours = int(arg.split("=")[1])
            except Exception:
                pass
    res = run_daily_sync(dry_run=dry, hours=hours)
    print(json.dumps(res, indent=2))
