import os
import time
import threading
import logging
import uvicorn
import config
from collector import MetricsCollector
from enricher import DestinationEnricher
from detector import AnomalyDetector
from engine import DiagnosticEngine
from agent_brain import AgentBrain
import api

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("main")

def anomaly_scanner_loop(detector):
    """Periodic anomaly scan cycle (default every 5 min)."""
    time.sleep(10)
    while True:
        try:
            detector.run_detection_cycle()
        except Exception as e:
            logger.error(f"Error in anomaly scanner cycle: {e}", exc_info=True)
        time.sleep(getattr(config, "SCAN_INTERVAL_SECONDS", 300))

def main():
    logger.info("=" * 65)
    logger.info(f"Starting CGNAT & Threat Intelligence Assistant: {getattr(config, 'ISP_NAME', 'Golden Master')}")
    logger.info(f"ClickHouse Target: {config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT} (DB: {config.CLICKHOUSE_DB})")
    logger.info("=" * 65)

    collector = MetricsCollector()
    enricher = DestinationEnricher(collector.client)
    detector = AnomalyDetector(collector, enricher)
    engine = DiagnosticEngine(collector, enricher, detector)
    brain = AgentBrain(collector, enricher, detector)

    api.collector = collector
    api.enricher = enricher
    api.detector = detector
    api.engine = engine
    api.brain = brain

    # Background anomaly scanner
    scanner_thread = threading.Thread(target=anomaly_scanner_loop, args=(detector,), daemon=True)
    scanner_thread.start()
    logger.info("Background AI anomaly scanner worker initialized.")

    # Start FastAPI server
    logger.info(f"Serving Web UI & API at http://{config.API_HOST}:{config.API_PORT}")
    uvicorn.run(api.app, host=config.API_HOST, port=config.API_PORT, log_level="warning")

if __name__ == "__main__":
    main()
