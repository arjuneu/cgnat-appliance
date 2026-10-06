# 🛡️ Antigravity CGNAT AI Threat Shield & Network Intelligence Platform

An enterprise-grade, autonomous network defense and CGNAT intelligence platform designed for Internet Service Providers (ISPs), telcos, and carrier networks. Integrates real-time NetFlow/IPFIX/Syslog aggregation in **ClickHouse**, contextual **Google Gemini AI reasoning**, and multi-vendor edge firewall mitigation (**MikroTik RouterOS**, **Juniper Junos**, and more).

---

## 🚀 Key Architecture & Features

```
 ┌──────────────────────┐      ┌──────────────────────┐      ┌──────────────────────┐
 │  Live NetFlow/Syslog │ ──►  │ ClickHouse Columnar  │ ──►  │  Google Gemini AI    │
 │  (Ingress Gateways)  │      │  (High-Speed ZSTD)   │      │  (Context Reasoning) │
 └──────────────────────┘      └──────────────────────┘      └──────────┬───────────┘
                                                                        │
                                   ┌────────────────────────────────────┘
                                   ▼
 ┌──────────────────────────────────────────────────────────────────────────────────┐
 │                     Multi-Vendor Automated Fleet Dispatcher                      │
 ├────────────────────────────────┬─────────────────────────────────────────────────┤
 │  MikroTik RouterOS (/ip fw)    │  Juniper Junos (policy-options prefix-list)     │
 │  • Dynamic Address-Lists       │  • Atomic Configuration Commits                 │
 │  • Zero-SSH Deduplication      │  • Redundant Prefix Pruning                     │
 └────────────────────────────────┴─────────────────────────────────────────────────┘
```

### ⚡ Core Highlights
* **Contextual AI Threat Classifier**: Uses Google Gemini LLMs to evaluate candidate destination clusters with rich traffic vectors (host saturation %, distinct port variance, flows-per-subscriber), distinguishing legitimate CDNs (Google, Apple, Cloudflare, Akamai) from abusive botnet sweeps and DDoS reflection attacks.
* **Multi-Vendor Router Fleet (`router_sync`)**: Generalized driver architecture supporting MikroTik RouterOS and Juniper Junos with extensible adapters for Cisco and Huawei.
* **Managed Router Targeting**: Automatically confines active AI scans and automated mitigations to configured routers, eliminating unmanaged cross-router leaks while maintaining full forensic visibility across all streaming gateways.
* **Zero-SSH Local Cache Deduplication**: Sub-millisecond candidate filtering prevents redundant SSH polling, protecting edge router control planes from CPU overload.
* **3-Mode Enforcement Scope**:
  * 🌐 **All Fleet Routers**: Autonomous AS-wide perimeter defense.
  * 🎯 **Originating Router Only**: Keeps individual edge gateway firewall tables isolated and lean.
  * ⚡ **Smart Hybrid Mode**: Local scans stay on the originating router; massive /24 sweeps and volumetric floods trigger fleet-wide mitigation.
* **180-Day Regulatory NAT Compliance**: High-throughput ClickHouse table schema featuring automated two-tier data retention (1-day hot tier + 180-day `ZSTD(19)` ultra-compressed storage) with RADIUS subscriber enrichment.
* **AI Key Vault with Failover**: Encrypted multi-key vault supporting hot key rotation, priority ordering, and automatic quota failover across Gemini API keys.
* **Dual Theme Modern Web Console**: Real-time traffic analytics, Light and Dark mode UI, interactive "+ Block" modal with TTL timeouts, lawful interception search, and Discord operations alerting.

---

## 🛠️ Quickstart & Deployment

### 1. Requirements
* Linux (Debian 12+ / Ubuntu 22.04+ recommended)
* Python 3.10+
* ClickHouse Server 23+
* Vector (for high-speed Syslog/IPFIX ingestion)

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/arjuneu/cgnat-appliance.git
cd cgnat-appliance

# Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure environment
cp .env.example .env
cp data/routers.example.json data/routers.json
```

### 3. Running the Service
```bash
# Start backend API & Web UI
python3 main.py

# Or manage via systemd
sudo cp scripts/nat-ai-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nat-ai-agent
```

### 4. Background Sync Services
Threat Shield runs automated periodic scans via systemd timers:
* `nat-ai-threat-sync.timer`: 15-minute real-time threat classifier and firewall sync.
* `nat-daily-threat-sync.timer`: Nightly 03:00 deep scan and subnet consolidation.

### 5. Automated Updates
To pull the latest updates cleanly:
```bash
./scripts/auto-update.sh
```

---

## 📜 License
Licensed under the [Apache License, Version 2.0](LICENSE).
