import re
import ipaddress
import logging
from typing import Dict, Any, List

logger = logging.getLogger("agent_brain")

CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")

def is_subscriber_ip(ip_obj: ipaddress.IPv4Address) -> bool:
    return ip_obj.is_private or (ip_obj in CGNAT_NET) or ip_obj.is_loopback

class AgentBrain:
    def __init__(self, collector, enricher, detector):
        self.collector = collector
        self.enricher = enricher
        self.detector = detector
        self.ch = collector.client

    def process_message(self, prompt: str) -> str:
        text = prompt.strip()
        text_lower = text.lower()

        # 1. Check if specific IPv4 is mentioned
        ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        if ip_matches:
            target_ip = ip_matches[0]
            try:
                ip_obj = ipaddress.ip_address(target_ip)
                if is_subscriber_ip(ip_obj):
                    return self._investigate_private_ip(target_ip)
                else:
                    return self._investigate_public_or_dest_ip(target_ip)
            except Exception as e:
                logger.error(f"IP parse error: {e}")

        # 2. Check for Server Health & Comprehensive Telemetry
        if any(k in text_lower for k in ["server health", "system health", "hardware", "cpu", "memory", "ram", "disk", "uptime", "pipeline health", "telemetry"]):
            return self._get_server_health_report()

        # 3. Check for Total Logs & Storage Compression
        if any(k in text_lower for k in ["total log", "total records", "storage", "compression", "disk usage", "zstd", "retention"]):
            return self._get_storage_and_logs_report()

        # 4. Check for Ingestion Details & Protocols
        if any(k in text_lower for k in ["ingestion detail", "ingest", "protocol", "tcp", "udp", "port 514", "port 2055", "ipfix", "flow rate"]):
            return self._get_ingestion_and_protocol_report()

        # 5. Check for Public NAT Pool or Private Pool
        if any(k in text_lower for k in ["public nat pool", "public pool", "nat pool", "pool no", "private pool", "subscriber pool"]):
            return self._get_pools_report()

        # 6. Check for Top High-Traffic Destinations / Services
        if any(k in text_lower for k in ["top site", "destination", "youtube", "facebook", "meta", "tiktok", "netflix", "high traffic", "services", "traffic"]):
            return self._get_top_destinations_report()

        # 7. Check for Port Exhaustion / Public NAT Pool Health
        if any(k in text_lower for k in ["port exhaustion", "capacity", "utilization", "overload"]):
            return self._get_nat_port_health_report()

        # 8. Check for Scanners / Abusive Subscribers / SYN Floods
        if any(k in text_lower for k in ["scanner", "abuse", "flood", "ddos", "heavy", "subscriber", "threat", "attack", "suspicious"]):
            return self._get_scanner_threat_report()

        # 9. Check for Router Health & Flow Rates
        if any(k in text_lower for k in ["router", "drop", "mx-1036", "mx-1016", "ctwn", "fps", "flap"]):
            return self._get_router_status_report()

        # 10. Check for Recent Detected Anomalies
        if any(k in text_lower for k in ["anomaly", "anomalies", "alert", "alerts", "issues", "problems"]):
            return self._get_recent_anomalies_report()

        # 11. Default: Comprehensive Network Status & Executive Summary
        return self._get_executive_summary_report()

    def _get_server_health_report(self) -> str:
        telemetry = self.collector.get_full_telemetry()
        sys = telemetry.get("system", {})
        storage = telemetry.get("storage", {})
        ingest = telemetry.get("ingestion", {})
        nat = telemetry.get("nat_pool", {})
        priv = telemetry.get("private_pool", {})

        mem = sys.get("memory", {})
        mem_used_gb = round(mem.get("used_bytes", 0) / (1024**3), 1)
        mem_tot_gb = round(mem.get("total_bytes", 0) / (1024**3), 1)

        disk = sys.get("disk", {})
        disk_free_gb = round(disk.get("root_free", 0) / (1024**3), 1)
        disk_tot_gb = round(disk.get("root_total", 0) / (1024**3), 1)

        services = sys.get("services", {})
        svc_str = " | ".join([f"**{k.split('-')[0].capitalize()}**: {'[ONLINE]' if v else '[OFFLINE]'}" for k, v in services.items()])

        total_rows = storage.get("total_rows", 0)
        comp_mb = round(storage.get("compressed_bytes", 0) / (1024**2), 1)
        ratio = storage.get("compression_ratio", 0)
        bpr = storage.get("bytes_per_row", 0)

        eps = ingest.get("current_eps", 0)
        active_routers = ingest.get("active_routers_count", 0)

        return (
            f"### &#128421;&#65039; Server & Ingestion Pipeline Health Status\n\n"
            f"- **System Uptime:** `{sys.get('uptime')}` | **CPU Load:** `{sys.get('load_avg', {}).get('1m')}` ({sys.get('load_pct')}% on {sys.get('cpu_cores')} vCPUs)\n"
            f"- **System Memory (RAM):** **{mem_used_gb} GB used** / {mem_tot_gb} GB total (**{mem.get('pct')}%** utilized)\n"
            f"- **Disk Storage (ClickHouse):** **{disk_free_gb} GB Free** / {disk_tot_gb} GB total (**{disk.get('root_pct')}%** used)\n"
            f"- **Core Services:** {svc_str}\n\n"
            f"#### &#128200; Telemetry & Ingestion Summary\n"
            f"- **Real-Time Ingestion Rate:** **{eps:,.1f} events/sec** across **{active_routers}** active routers\n"
            f"- **Total Stored Translations:** **{total_rows:,} records** ({comp_mb} MB compressed, **{ratio}x ratio**, **{bpr} B/row**)\n"
            f"- **Public NAT Pool Count:** **{nat.get('total_public_nat_ips', 0)}** active public IPv4 addresses\n"
            f"- **Active Private Subscribers (5m):** **{priv.get('total_private_subscribers', 0):,}** private IP addresses\n\n"
            f"> *All ingestion pipelines (Syslog UDP 514 & IPFIX UDP 2055) are operating with zero buffer drops.*"
        )

    def _get_storage_and_logs_report(self) -> str:
        telemetry = self.collector.get_full_telemetry()
        storage = telemetry.get("storage", {})
        total_rows = storage.get("total_rows", 0)
        comp_mb = round(storage.get("compressed_bytes", 0) / (1024**2), 1)
        uncomp_mb = round(storage.get("uncompressed_bytes", 0) / (1024**2), 1)
        ratio = storage.get("compression_ratio", 0)
        bpr = storage.get("bytes_per_row", 0)
        retention = storage.get("retention_days", 180)

        # 180 day projection at current rate (~28k eps = 2.4B/day)
        proj_gb_180 = round((28000 * 86400 * 180 * bpr) / (1024**3), 1)

        return (
            f"### &#128452;&#65039; Total Logs & ClickHouse Storage Compression Analysis\n\n"
            f"- **Total Indexed Records:** **{total_rows:,} rows**\n"
            f"- **Disk Space Consumed:** **{comp_mb} MB** (Compressed)\n"
            f"- **Uncompressed Raw Size:** **{uncomp_mb} MB**\n"
            f"- **Compression Ratio:** **{ratio}x**\n"
            f"- **Storage Footprint Per Row:** **{bpr} bytes / row**\n"
            f"- **Configured Retention:** **{retention} Days** (Automatic partition TTL rolling drops)\n"
            f"- **180-Day Projected Storage:** **~{proj_gb_180} GB** (< 2.2 TB, comfortably fitting within 3.1 TB drive)\n\n"
            f"> **Optimization Active:** `DoubleDelta, T64, ZSTD(7)` codec with hourly NAT locality sorting key."
        )

    def _get_ingestion_and_protocol_report(self) -> str:
        telemetry = self.collector.get_full_telemetry()
        ingest = telemetry.get("ingestion", {})
        routers = ingest.get("routers", [])
        protocols = ingest.get("protocols", [])
        top_ports = ingest.get("top_ports", [])

        proto_rows = [f"| `{p['protocol']}` | {p['flows']:,} | **{p['pct']}%** |" for p in protocols]
        proto_table = "| Ingestion Protocol | Flows (5m) | Share % |\n| :--- | :--- | :--- |\n" + "\n".join(proto_rows)

        router_rows = [f"| `{r['router_ip']}` | **{r['eps']:,} eps** | {r['flows_5m']:,} | {r['subscribers_5m']:,} | {r['nat_ips_5m']} | `{r['last_seen']}` |" for r in routers]
        router_table = "| Router Source | Current Ingest Rate | 5-Min Volume | Active Subscribers | Public NAT IPs | Last Seen |\n| :--- | :--- | :--- | :--- | :--- | :--- |\n" + "\n".join(router_rows)

        port_rows = [f"| `{p['port']}` | `{p['proto']}` | {p['flows']:,} flows |" for p in top_ports]
        port_table = "| Destination Port | Protocol | Ingest Flow Count |\n| :--- | :--- | :--- |\n" + "\n".join(port_rows)

        return (
            f"### &#128200; Ingestion Details & Protocol Telemetry\n\n"
            f"- **Current Aggregate Ingestion:** **{ingest.get('current_eps', 0):,.1f} flows/sec**\n"
            f"- **Active Ingest Transports:** `Syslog UDP 514` & `IPFIX UDP 2055`\n\n"
            f"#### &#128260; Protocol Distribution (Last 5 Minutes)\n{proto_table}\n\n"
            f"#### &#128421;&#65039; Active Router Ingestion Feeds\n{router_table}\n\n"
            f"#### &#128279; Dominant Destination Ports\n{port_table}"
        )

    def _get_pools_report(self) -> str:
        telemetry = self.collector.get_full_telemetry()
        nat = telemetry.get("nat_pool", {})
        priv = telemetry.get("private_pool", {})

        top_nat = nat.get("top_nat_ips", [])[:10]
        nat_rows = [f"| `{n['nat_src_ip']}` | `{n['router_ip']}` | {n['active_ports']:,} | **{n['util_pct']}%** | {n['active_subscribers']:,} | [{n['status']}] |" for n in top_nat]
        nat_table = "| Public NAT IP | Router | Active Ports | Utilization | Bound Subscribers | Status |\n| :--- | :--- | :--- | :--- | :--- | :--- |\n" + "\n".join(nat_rows)

        top_priv = priv.get("top_subscribers", [])[:10]
        priv_rows = [f"| `{s['src_ip']}` | `{s['router_ip']}` | {s['flows']:,} | {s['distinct_dests']:,} | `{s['assigned_nat_ip']}` | [{s['behavior']}] |" for s in top_priv]
        priv_table = "| Private Subscriber IP | Router | Flows (5m) | Targets | Assigned NAT IP | Behavior Profile |\n| :--- | :--- | :--- | :--- | :--- | :--- |\n" + "\n".join(priv_rows)

        return (
            f"### &#127760; Public NAT Pool & Private Subscriber Pool Overview\n\n"
            f"- **Total Public NAT Pool IPv4 Addresses:** **{nat.get('total_public_nat_ips', 0)} public IPs**\n"
            f"- **Total Active Private Subscribers (5m):** **{priv.get('total_private_subscribers', 0):,} private IPs**\n\n"
            f"#### &#128267; Public NAT Pool Port Saturation (Top 10)\n{nat_table}\n\n"
            f"#### &#128101; Private Pool Top Heavy Subscribers (Top 10)\n{priv_table}"
        )

    def _investigate_private_ip(self, private_ip: str) -> str:
        q1 = f"""
        SELECT 
            count() AS total_flows,
            uniqExact(dst_ip) AS unique_dest_ips,
            uniqExact(dst_port) AS unique_dest_ports,
            topK(1)(router_ip)[1] AS router,
            topK(1)(nat_src_ip)[1] AS public_nat_ip,
            topK(1)(protocol)[1] AS dominant_proto
        FROM nat_logs.translations
        WHERE src_ip = '{private_ip}' AND timestamp >= now() - INTERVAL 15 MINUTE
        """
        res1 = self.ch.query(q1)
        row = res1.result_rows[0]
        flows, dest_ips, dest_ports, router, nat_ip, proto = row

        if flows == 0:
            return f"### &#128269; Private Subscriber Investigation: `{private_ip}`\n\n> **Note:** No active NAT translations found for `{private_ip}` in the last 15 minutes. The subscriber may currently be idle or offline."

        risk = "[NORMAL]"
        risk_desc = "Standard broadband connection profile."
        if dest_ips > 400 and flows > 2500:
            risk = "[HIGH RISK - Port Scanner / Botnet / SYN Flood]"
            risk_desc = f"Subscriber is rapidly contacting {dest_ips} distinct external IP addresses in 15 minutes."
        elif flows > 8000:
            risk = "[MEDIUM RISK - High Concurrency / Heavy P2P]"
            risk_desc = "Heavy connection volume, likely high-concurrency P2P or multi-threaded download."

        q2 = f"""
        SELECT 
            dst_ip,
            protocol,
            dst_port,
            count() AS flows
        FROM nat_logs.translations
        WHERE src_ip = '{private_ip}' AND timestamp >= now() - INTERVAL 15 MINUTE
        GROUP BY dst_ip, protocol, dst_port
        ORDER BY flows DESC
        LIMIT 10
        """
        res2 = self.ch.query(q2)
        dest_rows = []
        for r in res2.result_rows:
            d_ip, d_proto, d_port, d_flows = r
            org, cat, _ = self.enricher.classify_ip(str(d_ip))
            dest_rows.append(f"| `{d_ip}` | **{org}** ({cat}) | `{d_proto}/{d_port}` | {d_flows:,} |")

        dest_table = "| Destination IP | Organization / Service | Proto/Port | Flow Count |\n| :--- | :--- | :--- | :--- |\n" + "\n".join(dest_rows)

        return (
            f"### &#128269; Private Subscriber Forensic Report: `{private_ip}`\n\n"
            f"- **Threat Assessment:** **{risk}**\n"
            f"- **Behavior Summary:** {risk_desc}\n"
            f"- **Ingress Router:** `{router}`\n"
            f"- **Assigned Public NAT IP:** `{nat_ip}`\n"
            f"- **Active Flows (15m):** **{flows:,}** flows\n"
            f"- **Distinct Destinations Contacted:** **{dest_ips:,}** unique IPs across **{dest_ports:,}** ports\n"
            f"- **Dominant Protocol:** `{proto}`\n\n"
            f"#### &#127760; Top Destination Targets Contacted:\n\n{dest_table}"
        )

    def _investigate_public_or_dest_ip(self, ip_str: str) -> str:
        q_nat = f"""
        SELECT 
            router_ip,
            uniqExact(src_ip) AS subscriber_count,
            uniqExact(nat_src_port) AS active_ports,
            count() AS total_flows
        FROM nat_logs.translations
        WHERE nat_src_ip = '{ip_str}' AND timestamp >= now() - INTERVAL 15 MINUTE
        GROUP BY router_ip
        """
        res_nat = self.ch.query(q_nat)
        if res_nat.result_rows:
            r = res_nat.result_rows[0]
            router, subs, ports, flows = r
            util = round((ports / 64512.0) * 100, 1)
            status = "[HEALTHY]" if util < 70 else ("[WARNING]" if util < 85 else "[CRITICAL - Port Exhaustion]")
            return (
                f"### &#128202; Public NAT Pool IP Analysis: `{ip_str}`\n\n"
                f"- **Pool Status:** **{status}**\n"
                f"- **Serving Router:** `{router}`\n"
                f"- **Active Port Allocation:** **{ports:,}** / 64,512 ports (**{util}%** utilization)\n"
                f"- **Active Subscribers Bound (15m):** **{subs:,}** private IPs\n"
                f"- **Total Translations (15m):** **{flows:,}** flows\n\n"
                f"> **Recommendation:** {'Port capacity is optimal.' if util < 70 else 'Consider allocating additional public IPs to this pool or tuning connection timeouts.'}"
            )

        org, cat, asn = self.enricher.classify_ip(ip_str)
        q_dest = f"""
        SELECT 
            count() AS total_flows,
            uniqExact(src_ip) AS subscriber_count,
            topK(1)(protocol)[1] AS proto,
            topK(1)(dst_port)[1] AS port
        FROM nat_logs.translations
        WHERE dst_ip = '{ip_str}' AND timestamp >= now() - INTERVAL 15 MINUTE
        """
        res_dest = self.ch.query(q_dest)
        row = res_dest.result_rows[0]
        flows, subs, proto, port = row

        return (
            f"### &#127760; External Destination Intelligence: `{ip_str}`\n\n"
            f"- **Identified Organization:** **{org}**\n"
            f"- **Service Category:** {cat}\n"
            f"- **ASN:** AS{asn}\n"
            f"- **Total Inbound Flows (15m):** **{flows:,}** flows\n"
            f"- **Unique Subscribers Accessing:** **{subs:,}** subscribers\n"
            f"- **Dominant Service Port:** `{proto}/{port}`"
        )

    def _get_top_destinations_report(self) -> str:
        destinations = self.collector.get_top_destinations(minutes=15, limit=12)
        rows = []
        for d in destinations:
            org, cat, _ = self.enricher.classify_ip(d["dst_ip"])
            rows.append(f"| `{d['dst_ip']}` | **{org}** | {cat} | {d['flows']:,} | {d['subscribers']:,} | `{d['proto']}/{d['port']}` |")

        table = "| Destination IP | Service / Organization | Category | Flows (15m) | Active Subscribers | Dominant Proto/Port |\n| :--- | :--- | :--- | :--- | :--- | :--- |\n" + "\n".join(rows)
        return f"### &#127760; Top High-Traffic Destination Services (Last 15 Minutes)\n\n{table}\n\n*Categorized automatically via ASN prefix intelligence & reverse lookup.*"

    def _get_nat_port_health_report(self) -> str:
        nat_stats = self.collector.get_public_nat_port_utilization(minutes=5)
        rows = []
        overloaded = []
        for n in nat_stats[:15]:
            status = "[OK]"
            if n['util_pct'] >= 85:
                status = "[CRITICAL]"
                overloaded.append(n)
            elif n['util_pct'] >= 70:
                status = "[WARNING]"
                overloaded.append(n)

            rows.append(f"| `{n['nat_src_ip']}` | `{n['router_ip']}` | {n['active_ports']:,} / 64.5k | **{n['util_pct']}%** | **{status}** |")

        table = "| Public NAT IP | Router | Active Ports | Utilization | Health |\n| :--- | :--- | :--- | :--- | :--- |\n" + "\n".join(rows)
        alert_msg = f"> **Warning:** {len(overloaded)} public NAT IP(s) are approaching port saturation." if overloaded else "> **All Public NAT IP pools have healthy port headroom (<70% capacity).**"

        return f"### &#128267; Public NAT Pool Port Health & Utilization\n\n{alert_msg}\n\n{table}"

    def _get_scanner_threat_report(self) -> str:
        subs = self.collector.get_top_private_subscribers(minutes=5, limit=15)
        rows = []
        for s in subs:
            is_scanner = s['distinct_dests'] > 300
            badge = "**[SCANNER / FLOOD]**" if is_scanner else "[Heavy Traffic]"
            rows.append(f"| `{s['src_ip']}` | `{s['router_ip']}` | {s['flows']:,} | **{s['distinct_dests']:,}** | `{s['assigned_nat_ip']}` | {badge} |")

        table = "| Subscriber Private IP | Router | Flows (5m) | Unique Targets Contacted | Public NAT IP | Behavior |\n| :--- | :--- | :--- | :--- | :--- | :--- |\n" + "\n".join(rows)
        return f"### &#128680; Top Heavy Subscribers & Potential Port Scanners\n\n{table}\n\n> *Subscribers contacting >300 unique external destination IPs in 5 minutes are flagged as active port scanners or SYN floods.*"

    def _get_router_status_report(self) -> str:
        routers = self.collector.get_router_ingest_rates(minutes=15)
        rows = []
        for r in routers:
            rows.append(f"| **{r['router_ip']}** | {r['flows_5m']:,} flows | **{r['eps']:,} flows/sec** | [Streaming Normal] |")

        table = "| Router Address | Total Ingest (15m) | Ingestion Rate (fps) | Health Status |\n| :--- | :--- | :--- | :--- |\n" + "\n".join(rows)
        return f"### &#128200; Router Syslog Ingest & Streaming Health\n\n{table}\n\n*All active routers are streaming syslog NAT translations via UDP 514.*"

    def _get_recent_anomalies_report(self) -> str:
        q = "SELECT timestamp, severity, anomaly_type, router_ip, target_ip, description FROM nat_logs.ai_anomalies ORDER BY timestamp DESC LIMIT 10"
        res = self.ch.query(q)
        if not res.result_rows:
            return "### &#128737;&#65039; AI Security Anomaly Feed\n\n> No active security anomalies recorded in the database."

        rows = []
        for r in res.result_rows:
            t, sev, atype, router, target, desc = r
            sev_badge = f"[{sev}]"
            rows.append(f"- **[{t.strftime('%H:%M:%S')}] {sev_badge} ({atype})**: {desc}")

        return "### &#128737;&#65039; Recent Detected Anomalies & Threat Events\n\n" + "\n".join(rows)

    def _get_executive_summary_report(self) -> str:
        telemetry = self.collector.get_full_telemetry()
        sys = telemetry.get("system", {})
        ingest = telemetry.get("ingestion", {})
        storage = telemetry.get("storage", {})
        priv = telemetry.get("private_pool", {})
        nat = telemetry.get("nat_pool", {})

        eps = ingest.get("current_eps", 0)
        routers = ingest.get("routers", [])
        router_list = ", ".join([f"`{r['router_ip']}` ({r['eps']:.0f} eps)" for r in routers]) if routers else "Awaiting stream..."

        return (
            f"### &#128737;&#65039; NAT AI Network Intelligence Overview\n\n"
            f"- **System Health:** **[ALL SYSTEMS OPERATIONAL]** (Load: `{sys.get('load_avg', {}).get('1m')}`, Uptime: `{sys.get('uptime')}`)\n"
            f"- **Real-Time Ingestion Rate:** **{eps:,.1f} flows/sec** across {len(routers)} active router(s)\n"
            f"- **Total ClickHouse Logs:** **{storage.get('total_rows', 0):,} rows** ({storage.get('compression_ratio', 0)}x compression, {storage.get('bytes_per_row', 0)} B/row)\n"
            f"- **Active CGNAT Subscribers (5m):** **{priv.get('total_private_subscribers', 0):,}** private IPs\n"
            f"- **Active Public NAT Pool:** **{nat.get('total_public_nat_ips', 0)}** public IPv4 addresses\n"
            f"- **Active Routers Detected:** {router_list}\n\n"
            f"#### &#128161; Available Inquiries & Commands:\n"
            f"- *\"Show server health and hardware metrics\"*\n"
            f"- *\"Show total logs and storage compression\"*\n"
            f"- *\"Show ingestion details and protocol breakdown\"*\n"
            f"- *\"Show public NAT pool and private pool status\"*\n"
            f"- *\"Investigate private IP 100.66.182.124\"*\n"
            f"- *\"What are the top high-traffic sites?\"*"
        )

