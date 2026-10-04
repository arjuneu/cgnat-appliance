import logging
from datetime import datetime

logger = logging.getLogger("engine")

class DiagnosticEngine:
    def __init__(self, collector, enricher, detector):
        self.collector = collector
        self.enricher = enricher
        self.detector = detector

    def generate_executive_summary(self):
        try:
            telemetry = self.collector.get_full_telemetry(minutes=5)
            flow_rate_fps = telemetry.get("flow_rate_eps", 0)
            active_subs = telemetry.get("active_subscribers_estimate", 0)
            routers = telemetry.get("active_routers", [])
            top_dest = telemetry.get("top_destinations", [])[:10]
            nat_pools = telemetry.get("public_nat_pools", [])
            
            high_nat = [n for n in nat_pools if isinstance(n, dict) and n.get("utilization_pct", 0) > 85]

            summary = {
                "status": "HEALTHY" if not high_nat else "WARNING",
                "timestamp": datetime.now().isoformat(),
                "flow_rate_fps": flow_rate_fps,
                "active_subscribers_5m": active_subs,
                "unique_destinations_5m": len(top_dest),
                "active_routers": len(routers),
                "router_rates": routers,
                "top_services": top_dest,
                "nat_pool_warnings": high_nat
            }
            return summary
        except Exception as e:
            logger.error(f"Error generating executive summary: {e}", exc_info=True)
            return {
                "status": "HEALTHY",
                "timestamp": datetime.now().isoformat(),
                "flow_rate_fps": 0,
                "active_subscribers_5m": 0,
                "unique_destinations_5m": 0,
                "active_routers": 0,
                "router_rates": [],
                "top_services": [],
                "nat_pool_warnings": []
            }
