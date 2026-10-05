#!/usr/bin/env python3
"""
NAT AI Threat Shield — Autonomous AI Threat Classifier Engine
===================================================================
Replaces static 3 AM / 15-minute heuristic rules with an Agentic LLM Decision Engine.

Integrates with:
- AIKeyVault: Encrypted multi-account priority key pool with custom naming & failover.
- ClickHouse CTE: Sub-second traffic aggregation (~0.25s).
- Google Gemini AI API: Structured JSON threat evaluation.
- MikroTik RouterOS: Dynamic address-list synchronization & single-IP pruning.
- Threat Shield Web UI: Real-time 15-minute threat streaming.
- Discord Operations Alerts: Rich threat reports with AI explanations.
"""

import os
import sys
import json
import time
import logging
import ipaddress
import urllib.request
import urllib.error
from typing import Dict, List, Tuple, Any, Optional
import config

try:
    from ai_key_vault import key_vault
except ImportError:
    try:
        sys.path.insert(0, "/opt/nat-ai-agent")
        from ai_key_vault import key_vault
    except Exception:
        key_vault = None


def is_threat_sync_enabled() -> bool:
    try:
        from threat_shield_engine import is_sync_enabled
        return is_sync_enabled()
    except Exception:
        try:
            import mikrotik_sync
            return mikrotik_sync.is_sync_enabled()
        except Exception:
            return True

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("ai_threat_classifier")

# Router & Storage Settings
def _get_default_router_ip() -> str:
    env_ip = os.getenv("MIKROTIK_IP", "").strip()
    if env_ip and not env_ip.startswith("192.0.2."):
        return env_ip
    try:
        from router_registry import router_registry
        adapters = router_registry.get_adapters(enabled_only=True)
        if adapters:
            return adapters[0].ip
    except Exception:
        pass
    try:
        cfg_ip = getattr(config, "MIKROTIK_IP", "")
        if cfg_ip and not cfg_ip.startswith("192.0.2."):
            return cfg_ip
    except Exception:
        pass
    return "100.100.48.26"

MIKROTIK_IP = _get_default_router_ip()
ADDRESS_LIST_NAME = os.getenv("MIKROTIK_ADDRESS_LIST", "scanner")

CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "127.0.0.1")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_DB = os.getenv("CLICKHOUSE_DB", "nat_logs")
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")

try:
    from config_vault import ConfigVault
    _cv = ConfigVault()
    _vault_disc = _cv.get("DISCORD_WEBHOOK_URL", "")
except Exception:
    _vault_disc = ""

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", _vault_disc or getattr(config, "DISCORD_WEBHOOK_URL", ""))

LATEST_THREATS_FILE = os.getenv("LATEST_THREATS_FILE", "/opt/nat-ai-agent/data/latest_ai_threats.json")

# Protected ISP Whitelist (Strictly Immune from Blocking)
def _build_protected_networks() -> List[ipaddress.IPv4Network]:
    nets = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("100.100.48.0/22"),
    ]
    for pool in getattr(config, "ISP_PUBLIC_POOLS", ["103.155.20.0/23"]):
        try: nets.append(ipaddress.ip_network(pool.strip()))
        except Exception: pass
    for pool in getattr(config, "CGNAT_POOLS", ["100.64.0.0/10"]):
        try: nets.append(ipaddress.ip_network(pool.strip()))
        except Exception: pass
    return nets

PROTECTED_NETWORKS = _build_protected_networks()

GEMINI_MODELS = ["gemini-3.5-flash-lite", "gemini-3.1-flash-lite", "gemini-flash-lite-latest", "gemini-3.8-flash"]

def is_whitelisted(addr_str: str) -> bool:
    try:
        if "/" in addr_str:
            target_net = ipaddress.ip_network(addr_str, strict=False)
            return any(target_net.overlaps(p) for p in PROTECTED_NETWORKS)
        else:
            target_ip = ipaddress.ip_address(addr_str)
            return any(target_ip in p for p in PROTECTED_NETWORKS)
    except Exception:
        return False

# ==============================================================================

LOCAL_BLOCK_CACHE_FILE = os.getenv("LOCAL_BLOCK_CACHE_FILE", "/opt/nat-ai-agent/data/active_blocked_cache.json")

def get_local_blocked_cache() -> Dict[str, Any]:
    """Reads local blocked targets cache from disk (<1ms, zero SSH)."""
    if os.path.exists(LOCAL_BLOCK_CACHE_FILE):
        try:
            with open(LOCAL_BLOCK_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {"targets": {}}
        except Exception as e:
            logger.warning(f"Error reading local blocked cache: {e}")
    return {"targets": {}}

def is_target_locally_blocked(target: str, cache: Optional[Dict[str, Any]] = None) -> bool:
    """Checks if a target IP or subnet is already recorded as blocked."""
    if cache is None:
        cache = get_local_blocked_cache()
    targets = cache.get("targets", {})
    if target in targets:
        return True
    if "/" not in target:
        try:
            parent_24 = f"{ipaddress.ip_network(f'{target}/24', strict=False).network_address}/24"
            if parent_24 in targets:
                return True
        except Exception:
            pass
    return False

def add_targets_to_local_cache(verdicts_or_targets: List[Any], updated_by: str = "ai_classifier"):
    """Adds newly blocked targets to local cache immediately."""
    cache = get_local_blocked_cache()
    targets = cache.get("targets", {})
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    added = False
    
    for item in verdicts_or_targets:
        if isinstance(item, dict):
            target = item.get("target") or item.get("address")
            threat_type = item.get("threat_type", "BOTNET_SWEEP")
            rationale = item.get("rationale", "AI Blocked")
        else:
            target = str(item)
            threat_type = "MANUAL_BLOCK"
            rationale = "Operator block"
            
        if target and target not in targets:
            targets[target] = {
                "blocked_at": now_str,
                "threat_type": threat_type,
                "rationale": rationale,
                "source": updated_by
            }
            added = True

    if added or "targets" not in cache:
        cache["targets"] = targets
        cache["last_updated"] = now_str
        try:
            os.makedirs(os.path.dirname(LOCAL_BLOCK_CACHE_FILE), exist_ok=True)
            with open(LOCAL_BLOCK_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(cache, f, indent=2)
            logger.info(f"Local blocklist cache updated. Total active cached blocks: {len(targets)}")
        except Exception as e:
            logger.error(f"Failed to write local block cache: {e}")

def remove_target_from_local_cache(target: str):
    """Removes a target from local cache upon unblock."""
    cache = get_local_blocked_cache()
    targets = cache.get("targets", {})
    if target in targets:
        del targets[target]
        cache["targets"] = targets
        cache["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(LOCAL_BLOCK_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(cache, f, indent=2)
            logger.info(f"Removed {target} from local block cache.")
        except Exception as e:
            logger.error(f"Failed to update local block cache: {e}")

def seed_cache_from_router_if_empty():
    """Initializes local cache from router once on startup if cache is empty."""
    cache = get_local_blocked_cache()
    if not cache.get("targets"):
        try:
            from router_registry import router_registry
            adapters = router_registry.get_adapters(enabled_only=True)
            all_entries = []
            for a in adapters:
                all_entries.extend(a.get_address_list())
            if not all_entries:
                import mikrotik_sync
                all_entries = mikrotik_sync.get_mikrotik_address_list()
            if all_entries:
                targets = [e["address"] for e in all_entries if "address" in e]
                add_targets_to_local_cache(targets, updated_by="router_sync_seed")
                logger.info(f"Seeded local block cache with {len(targets)} existing router entries.")
        except Exception as e:
            logger.warning(f"Could not seed local block cache: {e}")

# 1. ClickHouse Candidate Extraction (High-Speed Pre-Aggregation)
# ==============================================================================
def extract_candidate_threats(hours: float = 0.5, router_ip: Optional[str] = None, limit: int = 40) -> List[Dict[str, Any]]:
    """Extracts top destination subnet & IP candidate clusters with rich traffic vectors."""
    try:
        import clickhouse_connect
        client = clickhouse_connect.get_client(
            host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
            database=CLICKHOUSE_DB, username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD
        )
    except Exception as e:
        logger.error(f"ClickHouse connection failed: {e}")
        return []

    interval_minutes = int(hours * 60) if hours < 1 else int(hours * 60)
    router_label = router_ip if (router_ip and router_ip != "all") else "All Fleet Routers"
    logger.info(f"Aggregating destination traffic clusters from router {router_label} (Window: {interval_minutes} minutes)...")

    router_clause = f"AND router_ip = '{router_ip}'" if (router_ip and router_ip != "all") else ""
    
    # High-Speed 2-Step Subquery (0.2s for 15-30m window)
    sql_subnets = f"""
    WITH top_subnets AS (
        SELECT 
            bitAnd(toUInt32(dst_ip), 4294967040) as subnet_int
        FROM {CLICKHOUSE_DB}.translations
        WHERE toDate(timestamp) >= today() - 1 AND timestamp >= now() - INTERVAL {interval_minutes} MINUTE
          {router_clause}
          AND NOT (dst_ip >= IPv4StringToNum('103.155.20.0') AND dst_ip <= IPv4StringToNum('103.155.21.255'))
          AND NOT (dst_ip >= IPv4StringToNum('100.64.0.0') AND dst_ip <= IPv4StringToNum('100.127.255.255'))
          AND NOT (dst_ip >= IPv4StringToNum('100.100.48.0') AND dst_ip <= IPv4StringToNum('100.100.51.255'))
          AND NOT (dst_ip >= IPv4StringToNum('10.0.0.0') AND dst_ip <= IPv4StringToNum('10.255.255.255'))
        GROUP BY subnet_int
        ORDER BY count() DESC
        LIMIT {limit}
    )
    SELECT 
        concat(toString(IPv4NumToString(bitAnd(toUInt32(dst_ip), 4294967040))), '/24') as subnet_cidr,
        count() as total_flows,
        uniq(dst_ip) as distinct_host_ips,
        uniq(dst_port) as distinct_ports,
        uniq(src_ip) as subscriber_count,
        round(count() / uniq(src_ip), 1) as avg_flows_per_sub,
        topK(5)(dst_port) as sample_ports,
        topK(2)(protocol) as protocols,
        min(timestamp) as first_seen,
        max(timestamp) as last_seen,
        topK(1)(router_ip)[1] as origin_router
    FROM {CLICKHOUSE_DB}.translations
    WHERE toDate(timestamp) >= today() - 1 AND timestamp >= now() - INTERVAL {interval_minutes} MINUTE
      {router_clause}
      AND bitAnd(toUInt32(dst_ip), 4294967040) IN (SELECT subnet_int FROM top_subnets)
    GROUP BY subnet_cidr
    ORDER BY total_flows DESC
    SETTINGS max_threads = 8, max_execution_time = 60;
    """
    
    rows = client.query(sql_subnets).result_rows
    client.close()

    candidates = []
    blocked_cache = get_local_blocked_cache()
    skipped_already_blocked = 0

    for r in rows:
        cidr = str(r[0])
        if is_whitelisted(cidr):
            continue

        # ZERO-SSH DEDUPLICATION: Skip if already blocked in local cache
        if is_target_locally_blocked(cidr, blocked_cache):
            skipped_already_blocked += 1
            continue
            
        origin_ip = str(r[10]) if len(r) > 10 and r[10] else (router_ip or MIKROTIK_IP)
        candidates.append({
            "target": cidr,
            "target_type": "SUBNET_24",
            "origin_router_ip": origin_ip,
            "total_flows": int(r[1]),
            "distinct_host_ips": int(r[2]),
            "host_saturation_pct": round((int(r[2]) / 256.0) * 100, 1),
            "distinct_ports": int(r[3]),
            "distinct_subscribers": int(r[4]),
            "avg_flows_per_sub": float(r[5]),
            "sample_ports": list(r[6]),
            "protocols": list(r[7]),
            "duration": f"{r[8]} to {r[9]}"
        })

    if skipped_already_blocked > 0:
        logger.info(f"[ZERO-SSH DEDUP] Skipped {skipped_already_blocked} candidate clusters that are ALREADY in local blocklist cache.")
    logger.info(f"Extracted {len(candidates)} brand-new candidate threat clusters for AI analysis.")
    return candidates

# ==============================================================================
# 2. ASN & Organization Enrichment
# ==============================================================================
def enrich_candidates_with_intel(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Enriches candidate targets with ISP / ASN / Organization metadata."""
    try:
        import clickhouse_connect
        client = clickhouse_connect.get_client(
            host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
            database=CLICKHOUSE_DB, username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD
        )
        for c in candidates:
            sample_ip = c["target"].split("/")[0]
            q = f"SELECT asn_number, org_name, category FROM {CLICKHOUSE_DB}.destination_intel WHERE ip = IPv4StringToNum('{sample_ip}') LIMIT 1"
            res = client.query(q).result_rows
            if res:
                c["asn"] = f"AS{res[0][0]}"
                c["org_name"] = str(res[0][1])
                c["intel_category"] = str(res[0][2])
            else:
                c["asn"] = "Unknown"
                c["org_name"] = "External ISP"
                c["intel_category"] = "General Internet"
        client.close()
    except Exception:
        for c in candidates:
            c["asn"] = "Unknown"
            c["org_name"] = "External ISP"
            c["intel_category"] = "General Internet"

    return candidates

# ==============================================================================
# 3. Gemini AI Decision Reasoner (Ordered Key Vault Failover)
# ==============================================================================
AI_SYSTEM_INSTRUCTION = """
You are an expert Autonomous ISP Network Security Engineer and CGNAT Firewall Architect.
Analyze candidate traffic clusters on an ISP border router and output strict JSON verdicts.

Decision Rules:
1. ALLOW: Legitimate CDNs/Services (Akamai, Cloudflare, Google, Apple, ByteDance/TikTok, Meta, Microsoft, AWS, Fastly, Steam, Garena) with high subscriber count (>100) and low avg flows/sub (<500).
2. BLOCK: Coordinated Botnet Sweeps hitting all 256 host IPs, port sweeps (>10,000 ports), or abusive traffic (>50k flows/sub).

Return ONLY valid JSON matching this schema:
{
  "verdicts": [
    {
      "target": "<CIDR>",
      "action": "BLOCK" | "ALLOW" | "MONITOR",
      "confidence": <float between 0.0 and 1.0>,
      "threat_type": "<threat description>",
      "rationale": "<1-2 sentence technical explanation>",
      "mikrotik_comment": "<Max 80 chars comment for firewall address-list>"
    }
  ]
}
"""

def evaluate_threats_with_ai(candidates: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], str]:
    """Sends candidate threat features to Google Gemini AI API in strict Key Vault priority order."""
    if not candidates:
        return [], "No candidates"

    keys_in_order = key_vault.get_raw_keys_in_order() if key_vault else []
    if not keys_in_order:
        # Fallback default key if vault unavailable
        env_key = os.getenv("GEMINI_API_KEY", "")
        keys_in_order = [("Environment Key", env_key)] if env_key else []

    prompt_payload = {
        "system_instruction": {
            "parts": [{"text": AI_SYSTEM_INSTRUCTION}]
        },
        "contents": [
            {
                "parts": [
                    {
                        "text": f"Evaluate the following network traffic clusters and return JSON verdicts:\n{json.dumps(candidates, indent=2)}"
                    }
                ]
            }
        ],
        "generationConfig": {
            "response_mime_type": "application/json",
            "temperature": 0.1
        }
    }

    for key_idx, (key_name, api_key) in enumerate(keys_in_order, 1):
        masked_key = f"{api_key[:12]}...{api_key[-6:]}" if len(api_key) > 18 else "***"
        logger.info(f"Trying Priority #{key_idx} Key: '{key_name}' ({masked_key}) for {len(candidates)} candidates...")

        for model_name in GEMINI_MODELS:
            api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
            try:
                req = urllib.request.Request(
                    api_url,
                    data=json.dumps(prompt_payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=25) as resp:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    text_content = resp_data["candidates"][0]["content"]["parts"][0]["text"]
                    verdict_obj = json.loads(text_content)
                    used_account_info = f"{key_name} ({model_name})"
                    logger.info(f"✅ Success with Priority #{key_idx} '{key_name}' using model '{model_name}'.")
                    return verdict_obj.get("verdicts", []), used_account_info
            except urllib.error.HTTPError as e:
                err_body = e.read().decode("utf-8", errors="ignore")
                logger.warning(f"Key #{key_idx} ('{key_name}') model {model_name} HTTP {e.code}: {err_body[:90]}")
                if e.code == 429:
                    logger.warning(f"Key #{key_idx} ('{key_name}') quota exceeded. Failing over to next key...")
                    break
            except Exception as e:
                logger.warning(f"Key #{key_idx} ('{key_name}') model {model_name} error: {e}")

    # Check if offline fallback heuristic rule engine is permitted
    offline_fallback = getattr(config, "AI_OFFLINE_FALLBACK_ENABLED", False)
    if not offline_fallback:
        logger.warning("All Gemini AI keys in vault are exhausted or unconfigured, and offline heuristic engine is DISABLED. Skipping classification.")
        return [], "None (Offline Rules Disabled - Requires Cloud AI)"

    logger.warning("All Gemini API keys in vault exhausted. Falling back to embedded AI deterministic rule engine.")

    # Embedded AI Semantic Reasoning Engine (Fallback / Offline Mode)
    verdicts = []
    for c in candidates:
        target = c["target"]
        flows = c["total_flows"]
        host_ips = c["distinct_host_ips"]
        ports = c["distinct_ports"]
        subs = c["distinct_subscribers"]
        avg_flows = c["avg_flows_per_sub"]
        org = c.get("org_name", "External ISP")
        
        is_known_cdn = any(cdn in org.lower() for cdn in ["akamai", "cloudflare", "google", "apple", "bytedance", "meta", "fastly", "amazon", "garena"])
        is_full_host_saturation = host_ips >= 200
        is_full_port_sweep = ports >= 10000
        is_extreme_sub_intensity = avg_flows >= 10000
        
        if is_known_cdn and not is_full_port_sweep:
            verdicts.append({
                "target": target,
                "action": "ALLOW",
                "confidence": 0.98,
                "threat_type": "LEGITIMATE_CDN_SERVICE",
                "rationale": f"High subscriber volume ({subs:,} users) accessing verified CDN provider ({org}) with low avg flows ({avg_flows} flows/sub).",
                "mikrotik_comment": ""
            })
        elif is_full_host_saturation and is_full_port_sweep:
            verdicts.append({
                "target": target,
                "action": "BLOCK",
                "confidence": 0.99,
                "threat_type": "COORDINATED_BOTNET_SWEEP",
                "rationale": f"Systematic sweep of all {host_ips}/256 host IPs across {ports:,} ports ({flows:,} flows) with {avg_flows:,.0f} flows/sub intensity on {org}.",
                "mikrotik_comment": f"AI-Block: Botnet Sweep ({host_ips} IPs | {ports//1000}k Ports | {org[:20]})"
            })
        elif is_full_port_sweep or is_extreme_sub_intensity:
            verdicts.append({
                "target": target,
                "action": "BLOCK",
                "confidence": 0.95,
                "threat_type": "UDP_REFLECTION_FLOOD" if "UDP" in c.get("protocols", []) else "PORT_SCAN",
                "rationale": f"Anomalous traffic flood of {flows:,} flows probing {ports:,} ports across {subs} internal subscribers.",
                "mikrotik_comment": f"AI-Block: Traffic Flood ({flows//1000}k flows | {ports:,} ports | {org[:20]})"
            })
        else:
            verdicts.append({
                "target": target,
                "action": "MONITOR",
                "confidence": 0.70,
                "threat_type": "UNKNOWN",
                "rationale": f"Moderate activity ({flows:,} flows, {host_ips} IPs). Recommended for observation.",
                "mikrotik_comment": ""
            })

    return verdicts, "Offline Embedded Engine"

# ==============================================================================
# 4. MikroTik Router Synchronization & Pruning
# ==============================================================================
def apply_verdicts_to_mikrotik(verdicts: List[Dict[str, Any]], dry_run: bool = True, force: bool = False) -> Dict[str, Any]:
    """Applies AI-approved block verdicts based on the configured enforcement_scope (fleet_wide, originating_router, hybrid)."""
    blocks_to_apply = [v for v in verdicts if v.get("action") == "BLOCK" and not is_whitelisted(v.get("target"))]
    logger.info(f"AI Engine recommended {len(blocks_to_apply)} targets for blocking (Dry Run: {dry_run}, Force: {force}).")

    if not force and not is_threat_sync_enabled():
        logger.warning("Threat Shield sync is currently STOPPED (Paused). Skipping address-list / prefix-list push.")
        return {"applied": 0, "status": "paused", "message": "Threat Shield sync is paused. No router changes made."}

    if dry_run or not blocks_to_apply:
        return {"applied": len(blocks_to_apply), "dry_run": True, "blocks": blocks_to_apply}

    try:
        from router_registry import router_registry
        from threat_shield_engine import get_threat_config
        
        cfg = get_threat_config()
        enforcement_scope = cfg.get("enforcement_scope", "fleet_wide")
        logger.info(f"[ENFORCEMENT DISPATCHER] Active scope mode: '{enforcement_scope}'")

        all_enabled_adapters = router_registry.get_adapters(enabled_only=True)
        if not all_enabled_adapters:
            import mikrotik_sync
            applied_results = []
            for b in blocks_to_apply:
                target = b["target"]
                comment = b.get("mikrotik_comment", "AI-Blocked Threat")
                success, msg = mikrotik_sync.add_to_mikrotik(target, comment=comment, list_name=ADDRESS_LIST_NAME, notify_discord=False)
                applied_results.append({"target": target, "success": success, "msg": msg})
            prune_result = mikrotik_sync.prune_redundant_single_ips(address_list=ADDRESS_LIST_NAME, dry_run=False)
            add_targets_to_local_cache(blocks_to_apply, updated_by="ai_threat_classifier")
            return {"applied": len(applied_results), "dry_run": False, "results": applied_results, "pruned": prune_result}

        fleet_results = {}
        total_applied = 0

        for b in blocks_to_apply:
            target = b["target"]
            comment = b.get("mikrotik_comment", "AI-Blocked Threat")
            origin_ip = b.get("origin_router_ip") or MIKROTIK_IP
            threat_type = b.get("threat_type", "")
            host_sat = b.get("host_saturation_pct", 0)

            # Resolve target adapters based on enforcement_scope
            target_adapters = []
            if enforcement_scope == "originating_router":
                adapter = router_registry.get_adapter_by_ip(origin_ip)
                if adapter and getattr(adapter, "sync_enabled", True):
                    target_adapters = [adapter]
                else:
                    target_adapters = all_enabled_adapters
            elif enforcement_scope == "hybrid":
                is_severe_sweep = (
                    "BOTNET" in threat_type.upper() or 
                    "SWEEP" in threat_type.upper() or 
                    "FLOOD" in threat_type.upper() or 
                    host_sat >= 80.0
                )
                if is_severe_sweep:
                    logger.info(f"[HYBRID SCOPE] Threat '{target}' is severe ({threat_type}, Sat: {host_sat}%). Dispatching FLEET-WIDE.")
                    target_adapters = all_enabled_adapters
                else:
                    logger.info(f"[HYBRID SCOPE] Threat '{target}' is local ({threat_type}). Dispatching ORIGINATING ROUTER ONLY ({origin_ip}).")
                    adapter = router_registry.get_adapter_by_ip(origin_ip)
                    if adapter and getattr(adapter, "sync_enabled", True):
                        target_adapters = [adapter]
                    else:
                        target_adapters = all_enabled_adapters
            else:  # fleet_wide
                target_adapters = all_enabled_adapters

            # Apply to resolved adapters
            for adapter in target_adapters:
                ok, msg = adapter.add_entry(target, comment=comment)
                if adapter.name not in fleet_results:
                    fleet_results[adapter.name] = {"added": 0, "messages": []}
                fleet_results[adapter.name]["messages"].append(msg)
                if ok:
                    fleet_results[adapter.name]["added"] += 1
                    total_applied += 1

        # Cache new blocks immediately in local storage (Zero-SSH for future runs)
        add_targets_to_local_cache(blocks_to_apply, updated_by="ai_threat_classifier")
        return {"applied": total_applied, "dry_run": False, "scope": enforcement_scope, "fleet_results": fleet_results}
    except Exception as e:
        logger.error(f"Router fleet synchronization error: {e}")
        return {"applied": 0, "error": str(e)}

# 5. Threat Shield Real-Time State# 5. Threat Shield Real-Time State & Discord Reporting
# ==============================================================================
def save_latest_threat_stream(verdicts: List[Dict[str, Any]], account_used: str, window_minutes: int):
    """Saves the latest 15-minute AI threat evaluations for Threat Shield Web UI display."""
    try:
        os.makedirs(os.path.dirname(LATEST_THREATS_FILE) or ".", exist_ok=True)
        data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "window_minutes": window_minutes,
            "account_used": account_used,
            "router_ip": MIKROTIK_IP,
            "total_evaluated": len(verdicts),
            "blocked_count": sum(1 for v in verdicts if v.get("action") == "BLOCK"),
            "allowed_count": sum(1 for v in verdicts if v.get("action") == "ALLOW"),
            "monitored_count": sum(1 for v in verdicts if v.get("action") == "MONITOR"),
            "verdicts": verdicts
        }
        with open(LATEST_THREATS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved latest AI threat stream to {LATEST_THREATS_FILE}")
    except Exception as e:
        logger.error(f"Failed to save latest threat stream: {e}")

def send_discord_ai_report(verdicts: List[Dict[str, Any]], account_used: str, dry_run: bool = True) -> bool:
    """Delivers rich AI threat intelligence report to Discord operations channel."""
    if not DISCORD_WEBHOOK_URL:
        return False
    scope_map = {
        "fleet_wide": "🌐 All Fleet Routers",
        "originating_router": "🎯 Originating Router Only",
        "hybrid": "⚡ Smart Hybrid Mode"
    }
    from threat_shield_engine import get_threat_config
    enforcement_scope = get_threat_config().get("enforcement_scope", "fleet_wide")
    scope_display = scope_map.get(enforcement_scope, "🌐 All Fleet Routers")


    blocks = [v for v in verdicts if v.get("action") == "BLOCK"]
    allows = [v for v in verdicts if v.get("action") == "ALLOW"]
    monitored = [v for v in verdicts if v.get("action") == "MONITOR"]
    
    fields = []
    for b in blocks[:10]:
        fields.append({
            "name": f"🛡️ `{b['target']}` — {b.get('threat_type', 'Threat')}",
            "value": f"**Verdict:** {b['action']} (Confidence: {int(b['confidence']*100)}%)\n**Rationale:** {b['rationale']}",
            "inline": False
        })

    if not blocks and monitored:
        for m in monitored[:4]:
            fields.append({
                "name": f"👁️ `{m['target']}` — {m.get('threat_type', 'Observed Traffic')}",
                "value": f"**Verdict:** MONITOR (Confidence: {int(m.get('confidence', 0.7)*100)}%)\n**Rationale:** {m['rationale']}",
                "inline": False
            })
        
    mode_text = "[DRY-RUN AUDIT]" if dry_run else "[ACTIVE ENFORCEMENT]"
    payload = {
        "username": "Antigravity AI Threat Classifier",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/2040/2040946.png",
        "embeds": [
            {
                "title": f"🧠 AI Threat Intelligence Report {mode_text}",
                "description": f"Analyzed real-time destination clusters on router `{MIKROTIK_IP}` using LLM Contextual Reasoning.",
                "color": 15158332 if blocks else (15844367 if monitored else 3066993),
                "fields": [
                    {"name": "Enforcement Scope", "value": f"`{scope_display}`", "inline": True},
                    {"name": "Total Evaluated", "value": f"`{len(verdicts)} clusters`", "inline": True},
                    {"name": "Threats Blocked", "value": f"`{len(blocks)} targets`", "inline": True},
                    {"name": "Legitimate Passed", "value": f"`{len(allows)} services`", "inline": True},
                    {"name": "Under Observation", "value": f"`{len(monitored)} targets`", "inline": True},
                    {"name": "AI Engine Account", "value": f"`{account_used}`", "inline": True}
                ] + fields,
                "footer": {"text": f"Evaluated by Gemini AI • Account: {account_used}"},
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        ]
    }
    
    try:
        req = urllib.request.Request(
            DISCORD_WEBHOOK_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "Antigravity-AI-Agent"}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            logger.info("Discord AI report delivered successfully.")
            return True
    except Exception as e:
        logger.warning(f"Failed to post to Discord: {e}")
        return False

# ==============================================================================
# Main CLI Entry Point
# ==============================================================================
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Antigravity AI Threat Classifier Engine")
    parser.add_argument("hours_pos", type=float, nargs="?", default=None, help="Positional window in hours")
    parser.add_argument("--hours", type=float, default=None, help="Analysis window in hours (default: 0.25 = 15m)")
    parser.add_argument("--limit", type=int, default=30, help="Max candidate clusters to analyze (default: 30)")
    parser.add_argument("--router", type=str, default=None, help="Filter to specific router IP or 'all' for fleet-wide (default: all)")
    parser.add_argument("--apply", action="store_true", default=False, help="Apply changes to router fleet")
    parser.add_argument("--discord", action="store_true", default=False, help="Send report to Discord")
    parser.add_argument("--force", action="store_true", default=False, help="Force AI evaluation and sync even if Threat Shield is paused")
    args = parser.parse_args()

    analysis_hours = args.hours if args.hours is not None else (args.hours_pos if args.hours_pos is not None else 0.25)
    apply_mode = args.apply or (args.hours_pos is not None)
    discord_mode = args.discord or (args.hours_pos is not None)

    # Check if Threat Shield sync is paused
    if not args.force and not is_threat_sync_enabled():
        print("=" * 85)
        print("⏸️  THREAT SHIELD IS CURRENTLY STOPPED / PAUSED")
        print("AI threat reasoning and address-list/prefix-list sync are paused by administrator.")
        print("Automatic background reasoning cycles and router pushes are paused.")
        print("Run with '--force' to perform a one-off manual run, or click Resume in Web UI.")
        print("=" * 85)
        logger.info("Threat Shield is STOPPED (Paused). Skipping AI reasoning and router sync cycle.")
        return

    router_scope_label = args.router if args.router else "ALL FLEET ROUTERS (Aggregated)"
    print("=" * 85)
    print("🚀 ANTIGRAVITY AI THREAT CLASSIFIER (15-MIN REAL-TIME / 3-AM ENGINE)")
    print(f"Scope: {router_scope_label} | Window: {analysis_hours}h ({int(analysis_hours*60)}m) | Mode: {'ACTIVE APPLY' if apply_mode else 'DRY RUN'} | Force: {args.force}")
    print("=" * 85)

    # 1. ClickHouse Extraction
    candidates = extract_candidate_threats(hours=analysis_hours, router_ip=args.router, limit=args.limit)
    if not candidates:
        print("No suspicious candidate clusters found in time window.")
        return

    # 2. Enrichment
    enriched = enrich_candidates_with_intel(candidates)

    # 3. AI Reasoning with Key Vault
    verdicts, account_used = evaluate_threats_with_ai(enriched)

    # 4. Save Stream for Threat Shield UI
    save_latest_threat_stream(verdicts, account_used=account_used, window_minutes=int(analysis_hours*60))

    # 5. Display Results
    print("\n" + "=" * 105)
    print(f"{'#':<3} | {'TARGET':<18} | {'ACTION':<8} | {'CONF':<5} | {'THREAT TYPE':<24} | {'RATIONALE':<40}")
    print("=" * 105)
    
    for idx, v in enumerate(verdicts, 1):
        action_icon = "🛑" if v["action"] == "BLOCK" else ("✅" if v["action"] == "ALLOW" else "👁️")
        print(f"{idx:<3} | {v['target']:<18} | {action_icon} {v['action']:<6} | {int(v['confidence']*100)}% | {v['threat_type'][:24]:<24} | {v['rationale'][:40]}...")

    # 6. Router Fleet Enforcement
    if apply_mode:
        res = apply_verdicts_to_mikrotik(verdicts, dry_run=False, force=args.force)
        print(f"\n[OK] Enforced {res.get('applied', 0)} block rules across router fleet.")
    else:
        print("\n[INFO] Dry-run complete. Run with '--apply' to enforce blocks on router fleet.")

    # 7. Discord Alert
    if discord_mode:
        send_discord_ai_report(verdicts, account_used=account_used, dry_run=not apply_mode)

if __name__ == '__main__':
    main()
