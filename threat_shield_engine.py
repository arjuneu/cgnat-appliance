"""
Threat Shield Engine & Multi-Vendor Fleet Dispatcher
===================================================
Automates real-time anomaly discovery, port-scan / DDoS mitigation,
and pushes address-list/prefix-list rules across multi-vendor routers.
Supports router-wise blocking, custom target lists, and timeouts.
"""

import os
import json
import time
import logging
import ipaddress
import urllib.request
from typing import Dict, List, Tuple, Any, Optional
import clickhouse_connect

import config
from router_registry import router_registry

logger = logging.getLogger("threat_shield_engine")

STATE_FILE = os.getenv("THREAT_STATE_FILE", "/opt/nat-ai-agent/data/mikrotik_sync_state.json")

DEFAULT_THREAT_CONFIG = {
    "enabled": True,
    "enforcement_scope": "fleet_wide",
    "subnet_min_hosts": 50,
    "subnet_min_ports": 100,
    "subnet_min_flows": 20000,
    "min_ports": 10000,
    "flood_min_flows": 10000,
    "max_subscribers": 3,
    "private_ip_flow_threshold": 2500,
    "private_ip_target_threshold": 400,
    "private_ip_port_threshold": 1000,
    "port_exhaustion_threshold": 45000,
    "destination_spike_flows": 150000,
    "udp_sweep_min_ports": 10000,
    "vertical_scan_min_ports": 10000,
    "max_subscribers_for_block": 3
}

def get_threat_config() -> Dict[str, Any]:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                merged = dict(DEFAULT_THREAT_CONFIG)
                merged.update(cfg)
                return merged
        except Exception as e:
            logger.error(f"Failed to read threat state: {e}")
    return dict(DEFAULT_THREAT_CONFIG)

def set_threat_config(new_config: Dict[str, Any], updated_by: str = "admin") -> Dict[str, Any]:
    current = get_threat_config()
    current.update(new_config)
    current["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    current["updated_by"] = updated_by
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(current, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save threat state: {e}")
    return current

def is_sync_enabled() -> bool:
    return get_threat_config().get("enabled", True)

def _build_whitelist_networks() -> List[ipaddress.IPv4Network]:
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

def is_whitelisted(addr_str: str) -> bool:
    try:
        if "/" in addr_str:
            target_net = ipaddress.ip_network(addr_str, strict=False)
            for net in WHITELIST_NETWORKS:
                if target_net.overlaps(net):
                    return True
            return False
        else:
            ip = ipaddress.ip_address(addr_str)
            return any(ip in net for net in WHITELIST_NETWORKS)
    except Exception:
        return True

def get_ch_client():
    return clickhouse_connect.get_client(
        host=config.CLICKHOUSE_HOST,
        port=config.CLICKHOUSE_PORT,
        username=config.CLICKHOUSE_USER,
        password=config.CLICKHOUSE_PASSWORD,
        database=config.CLICKHOUSE_DB
    )

def send_discord_webhook(added_entries: List[Dict[str, Any]], router_name: str = "Fleet"):
    webhook_url = getattr(config, "DISCORD_WEBHOOK_URL", "")
    if not webhook_url or not added_entries:
        return

    fields = []
    for item in added_entries[:8]:
        addr = item.get("address", "")
        reason = item.get("reason", "Scanner / Flood")
        flows = item.get("flows", 0)
        subs = item.get("subscriber_count", 0)
        fields.append({
            "name": f"🛡️ Blacklisted: `{addr}`",
            "value": f"**Reason:** {reason}\n**Impact:** {flows:,} flows across {subs} subscriber(s)",
            "inline": False
        })

    payload = {
        "username": "NAT AI Multi-Vendor Threat Shield",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/2092/2092663.png",
        "embeds": [{
            "title": f"🚨 Automated Threat Shield Update ({router_name})",
            "description": f"Successfully mitigated **{len(added_entries)}** malicious threat vectors on **{router_name}**.",
            "color": 15158332,
            "fields": fields,
            "footer": {"text": f"NAT AI Master Appliance • {time.strftime('%Y-%m-%d %H:%M:%S')}"}
        }]
    }

    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "NAT-AI-ThreatShield/2.0"}
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        logger.error(f"Failed to send Discord notification: {e}")

class ThreatShieldEngine:
    def __init__(self):
        self.registry = router_registry

    def get_fleet_threat_lists(self, router_id: Optional[str] = None, list_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve threat list entries from a specific router or all fleet routers."""
        if router_id and router_id != "all":
            adapter = self.registry.get_adapter(router_id)
            if not adapter:
                return []
            return adapter.get_address_list(list_name=list_name)
        
        all_entries = []
        for adapter in self.registry.get_adapters(enabled_only=False):
            try:
                entries = adapter.get_address_list(list_name=list_name)
                all_entries.extend(entries)
            except Exception as e:
                logger.error(f"Failed to get threat list from {adapter.name}: {e}")
        return all_entries

    def add_threat_to_fleet(self, address: str, comment: str, router_id: Optional[str] = None, list_name: Optional[str] = None, timeout: Optional[str] = None) -> Tuple[bool, str]:
        if is_whitelisted(address):
            return False, f"Address {address} is protected by ISP Whitelist."

        if router_id and router_id != "all":
            adapter = self.registry.get_adapter(router_id)
            if not adapter:
                return False, f"Router '{router_id}' not found"
            return adapter.add_entry(address, comment, list_name=list_name, timeout=timeout)

        results = []
        success_any = False
        for adapter in self.registry.get_adapters(enabled_only=True):
            ok, msg = adapter.add_entry(address, comment, list_name=list_name, timeout=timeout)
            results.append(f"{adapter.name}: {msg}")
            if ok: success_any = True

        return success_any, " | ".join(results)

    def remove_threat_from_fleet(self, address: str, router_id: Optional[str] = None, list_name: Optional[str] = None) -> Tuple[bool, str]:
        if router_id and router_id != "all":
            adapter = self.registry.get_adapter(router_id)
            if not adapter:
                return False, f"Router '{router_id}' not found"
            return adapter.remove_entry(address, list_name=list_name)

        results = []
        success_any = False
        for adapter in self.registry.get_adapters(enabled_only=True):
            ok, msg = adapter.remove_entry(address, list_name=list_name)
            results.append(f"{adapter.name}: {msg}")
            if ok: success_any = True

        return success_any, " | ".join(results)

    def find_threat_candidates(self, minutes: int = 15, router_filter: Optional[str] = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Queries ClickHouse for vertical scans, UDP floods, and horizontal /24 subnet sweeps."""
        cfg = get_threat_config()
        udp_min_ports = cfg.get("udp_sweep_min_ports", 10000)
        vert_min_ports = cfg.get("vertical_scan_min_ports", 10000)
        flood_min_flows = cfg.get("flood_min_flows", 10000)
        max_subscribers = cfg.get("max_subscribers_for_block", 3)
        subnet_min_flows = cfg.get("subnet_min_flows", 20000)
        subnet_min_hosts = cfg.get("subnet_min_unique_hosts", 50)

        client = get_ch_client()
        
        router_clause = ""
        params = {"minutes": minutes}
        if router_filter and router_filter != "all":
            router_clause = "AND router_ip = %(router_ip)s"
            params["router_ip"] = router_filter

        # 1. Single IP candidate query
        sql = f"""
        SELECT
            dst_ip,
            count() AS flow_count,
            uniqExact(src_ip) AS distinct_subscribers,
            uniqExact(dst_port) AS distinct_ports,
            countIf(protocol = 'UDP') AS udp_flows,
            countIf(protocol = 'TCP') AS tcp_flows,
            countIf(protocol = 'ICMP') AS icmp_flows
        FROM nat_logs.translations
        WHERE timestamp >= now() - INTERVAL %(minutes)s MINUTE
          {router_clause}
        GROUP BY dst_ip
        HAVING distinct_subscribers <= {max_subscribers}
           AND (
               (countIf(protocol = 'UDP') >= {flood_min_flows} AND uniqExact(dst_port) >= {udp_min_ports})
               OR (uniqExact(dst_port) >= {vert_min_ports} AND count() >= 500)
               OR (count() >= {flood_min_flows})
           )
        ORDER BY flow_count DESC
        LIMIT 200
        """
        res = client.query(sql, parameters=params)
        scanners = []
        floods = []

        for row in res.result_rows:
            dst_ip = str(row[0])
            flows = int(row[1])
            subs = int(row[2])
            ports = int(row[3])
            udp_f = int(row[4])

            if is_whitelisted(dst_ip):
                continue

            if udp_f >= flood_min_flows:
                floods.append({
                    "address": dst_ip,
                    "reason": f"High Volume UDP Flood ({flows:,} flows, {ports} ports)",
                    "flows": flows,
                    "subscriber_count": subs,
                    "distinct_ports": ports
                })
            else:
                scanners.append({
                    "address": dst_ip,
                    "reason": f"Vertical Port Scanner ({ports} ports, {flows:,} flows)",
                    "flows": flows,
                    "subscriber_count": subs,
                    "distinct_ports": ports
                })

        # 2. Horizontal /24 Subnet Sweep query
        sql_subnet = f"""
        SELECT
            concat(cutIPv4(dst_ip, 3), '.0') AS subnet_base,
            count() AS total_flows,
            uniqExact(dst_ip) AS distinct_target_hosts,
            uniqExact(src_ip) AS distinct_subscribers,
            uniqExact(dst_port) AS distinct_ports
        FROM nat_logs.translations
        WHERE timestamp >= now() - INTERVAL %(minutes)s MINUTE
          {router_clause}
        GROUP BY subnet_base
        HAVING distinct_target_hosts >= {subnet_min_hosts}
           AND distinct_subscribers <= {max_subscribers}
           AND total_flows >= {subnet_min_flows}
        ORDER BY flow_count DESC
        LIMIT 50
        """
        res_subnet = client.query(sql_subnet, parameters=params)
        subnet_sweeps = []

        for row in res_subnet.result_rows:
            base_ip = str(row[0])
            flows = int(row[1])
            hosts = int(row[2])
            subs = int(row[3])
            ports = int(row[4])
            cidr = f"{base_ip}/24"

            if is_whitelisted(cidr):
                continue

            subnet_sweeps.append({
                "address": cidr,
                "reason": f"Distributed /24 Botnet Sweep ({hosts} hosts, {flows:,} flows)",
                "flows": flows,
                "subscriber_count": subs,
                "distinct_hosts": hosts,
                "distinct_ports": ports
            })

        return scanners, floods, subnet_sweeps

    def sync_fleet(self, minutes: int = 15, dry_run: bool = False, router_id: Optional[str] = None) -> Dict[str, Any]:
        """Full automated sync cycle across fleet or chosen router."""
        if not is_sync_enabled() and not dry_run:
            return {"status": "skipped", "message": "Threat shield sync is disabled in settings"}

        scanners, floods, sweeps = self.find_threat_candidates(minutes=minutes)
        all_candidates = sweeps + scanners + floods

        adapters = [self.registry.get_adapter(router_id)] if (router_id and router_id != "all") else self.registry.get_adapters(enabled_only=True)
        adapters = [a for a in adapters if a is not None]

        sync_report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "minutes_scanned": minutes,
            "dry_run": dry_run,
            "target_routers": [a.name for a in adapters],
            "candidates_found": len(all_candidates),
            "sweeps_found": len(sweeps),
            "scanners_found": len(scanners),
            "floods_found": len(floods),
            "router_results": {}
        }

        if dry_run or not all_candidates:
            sync_report["status"] = "dry_run_complete" if dry_run else "no_new_threats"
            sync_report["candidates"] = all_candidates
            return sync_report

        for adapter in adapters:
            current_entries = adapter.get_address_list()
            current_addrs = {e["address"] for e in current_entries}
            
            to_add = []
            for item in all_candidates:
                addr = item["address"]
                if addr not in current_addrs:
                    to_add.append({
                        "address": addr,
                        "comment": f"NAT-AI: {item['reason']}"
                    })

            if to_add:
                added_count, msgs = adapter.add_entries_batch(to_add)
                send_discord_webhook(to_add, router_name=adapter.name)
            else:
                added_count, msgs = 0, ["Already synchronized"]

            # Prune redundant IPs if subnets exist
            active_subnets = [c["address"] for c in sweeps]
            pruned_count, prune_msgs = adapter.prune_redundant_entries(active_subnets)

            sync_report["router_results"][adapter.router_id] = {
                "router_name": adapter.name,
                "added": added_count,
                "pruned": pruned_count,
                "messages": msgs + prune_msgs
            }

        return sync_report

threat_engine = ThreatShieldEngine()
