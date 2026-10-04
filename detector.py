import json
import logging
import config

logger = logging.getLogger("detector")

class AnomalyDetector:
    def __init__(self, collector, enricher):
        self.collector = collector
        self.enricher = enricher
        self.ch = collector.client

    def run_detection_cycle(self):
        logger.info("Executing AI anomaly and traffic intelligence scan...")
        anomalies = []
        
        try:
            import mikrotik_sync
            cfg = mikrotik_sync.get_threat_config()
        except Exception:
            cfg = {}

        port_exhaustion_th = cfg.get("port_exhaustion_threshold", config.PORT_EXHAUSTION_THRESHOLD)
        priv_flow_th = cfg.get("private_ip_flow_threshold", config.PRIVATE_IP_FLOW_THRESHOLD)
        priv_target_th = cfg.get("private_ip_target_threshold", config.PRIVATE_IP_TARGET_THRESHOLD)
        priv_port_th = cfg.get("private_ip_port_threshold", 1000)
        dest_spike_th = cfg.get("destination_spike_flows", 150000)

        # 1. Check Public NAT IP Port Exhaustion
        nat_stats = self.collector.get_public_nat_port_utilization(minutes=5)
        for item in nat_stats:
            ports = item.get("active_ports", 0)
            nat_ip = item.get("nat_src_ip", "0.0.0.0")
            router = item.get("router_ip", "UNKNOWN")
            util_pct = item.get("util_pct") or item.get("utilization_pct", 0)

            if ports >= port_exhaustion_th:
                severity = "CRITICAL" if ports >= 55000 else "WARNING"
                desc = f"Public NAT IP {nat_ip} on router {router} is experiencing high port allocation: {ports:,} active ports ({util_pct}% capacity)."
                anomalies.append({
                    "severity": severity,
                    "anomaly_type": "PORT_EXHAUSTION",
                    "router_ip": router,
                    "target_ip": nat_ip,
                    "metric_value": float(ports),
                    "description": desc,
                    "details": item
                })

        # 2. Check Suspicious Subscriber Behavior (Flooding / Scanners / Heavy P2P)
        subscribers = self.collector.get_top_private_subscribers(minutes=5, limit=30)
        for sub in subscribers:
            flows = sub.get("flow_count") or sub.get("flows", 0)
            dest_ips = sub.get("distinct_dest_ips") or sub.get("distinct_dests", 0)
            dest_ports = sub.get("distinct_dest_ports") or sub.get("distinct_ports", 0)
            src_ip = sub.get("src_ip", "0.0.0.0")
            router = sub.get("router_ip", "UNKNOWN")

            if flows >= priv_flow_th or dest_ports >= priv_port_th or dest_ips >= 300:
                if dest_ips >= priv_target_th or dest_ports >= priv_port_th:
                    # Mass scanning, vertical sweeping or SYN flood behavior
                    if dest_ports >= priv_port_th and dest_ips >= priv_target_th:
                        desc = f"Subscriber {src_ip} on {router} is executing dual-vector botnet scan ({dest_ips} destination IPs, {dest_ports} ports) across {flows:,} flows in 5 min."
                    elif dest_ports >= priv_port_th:
                        desc = f"Subscriber {src_ip} on {router} is executing vertical port sweep across {dest_ports:,} distinct ports ({flows:,} flows in 5 min)."
                    else:
                        desc = f"Subscriber {src_ip} on {router} is scanning/flooding {dest_ips} unique destination IPs across {flows:,} flows in 5 min."
                    anomalies.append({
                        "severity": "WARNING",
                        "anomaly_type": "ABUSE_SCANNER",
                        "router_ip": router,
                        "target_ip": src_ip,
                        "metric_value": float(flows),
                        "description": desc,
                        "details": sub
                    })
                elif flows >= 10000:
                    # Extreme single subscriber consumption
                    desc = f"Subscriber {src_ip} on {router} is generating massive connection volume ({flows:,} flows in 5 min)."
                    anomalies.append({
                        "severity": "INFO",
                        "anomaly_type": "HEAVY_SUBSCRIBER",
                        "router_ip": router,
                        "target_ip": src_ip,
                        "metric_value": float(flows),
                        "description": desc,
                        "details": sub
                    })

        # 3. Classify Top Destinations & Detect Destination Spikes
        destinations = self.collector.get_top_destinations(minutes=5, limit=25)
        for dst in destinations:
            dst_ip = dst["dst_ip"]
            flows = dst["flows"]
            subs = dst["subscribers"]
            org, cat, asn = self.enricher.classify_ip(dst_ip)
            dst["org_name"] = org
            dst["category"] = cat
            dst["asn"] = asn

            if flows >= dest_spike_th and subs < 5:
                # Sudden massive flow burst to single target from very few subscribers
                desc = f"Unusual traffic concentration: {flows:,} flows targeted to {dst_ip} ({org}) from only {subs} subscriber(s)."
                anomalies.append({
                    "severity": "WARNING",
                    "anomaly_type": "DESTINATION_SPIKE",
                    "router_ip": "GLOBAL",
                    "target_ip": dst_ip,
                    "metric_value": float(flows),
                    "description": desc,
                    "details": dst
                })

        # Persist anomalies to ClickHouse
        self._record_anomalies(anomalies)
        return anomalies, destinations, nat_stats, subscribers

    def _record_anomalies(self, anomalies):
        if not anomalies:
            return
        rows = []
        for a in anomalies:
            details_str = json.dumps(a["details"]).replace("'", "''")
            desc_str = a["description"].replace("'", "''")
            rows.append(
                f"(now(), '{a['severity']}', '{a['anomaly_type']}', '{a['router_ip']}', '{a['target_ip']}', {a['metric_value']}, '{desc_str}', '{details_str}')"
            )
        try:
            sql = f"INSERT INTO nat_logs.ai_anomalies (timestamp, severity, anomaly_type, router_ip, target_ip, metric_value, description, details_json) VALUES " + ",".join(rows)
            self.ch.command(sql)
            logger.info(f"Recorded {len(anomalies)} anomalies into nat_logs.ai_anomalies.")
        except Exception as e:
            logger.error(f"Failed to record anomalies to ClickHouse: {e}")
