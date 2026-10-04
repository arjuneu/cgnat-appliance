# 🛡️ Antigravity CGNAT AI Threat Shield & Network Intelligence Platform

An enterprise-grade, autonomous network defense and CGNAT intelligence platform designed for Internet Service Providers (ISPs), telcos, and carrier networks. Integrates real-time NetFlow/IPFIX aggregation in **ClickHouse**, contextual **Google Gemini AI contextual reasoning**, and multi-vendor firewall mitigation (**MikroTik RouterOS**, **Juniper Junos**, and more).

---

## 🚀 Key Architecture & Features

```
 ┌──────────────────────┐      ┌──────────────────────┐      ┌──────────────────────┐
 │  Live NetFlow/IPFIX  │ ──►  │ ClickHouse Columnar  │ ──►  │  Google Gemini AI    │
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
* **Zero-SSH Local Cache Deduplication**: Sub-millisecond candidate filtering prevents redundant SSH polling, protecting edge router control planes from CPU overload.
* **3-Mode Enforcement Scope**:
  * 🌐 **All Fleet Routers**: Autonomous AS-wide perimeter defense.
  * 🎯 **Originating Router Only**: Keeps individual edge gateway firewall tables isolated and lean.
  * ⚡ **Smart Hybrid Mode**: Local scans stay on the originating router; massive /24 sweeps and volumetric floods trigger fleet-wide mitigation.
* **180-Day Regulatory NAT Compliance**: High-throughput ClickHouse table schema featuring automated two-tier data retention (1-day hot tier + 180-day `ZSTD(19)` ultra-compressed storage).
* **Multi-Vendor Driver Abstraction**: Unified driver interface for MikroTik RouterOS and Juniper Junos with extensible support for Huawei VRP and Cisco IOS-XR.
* **AES-256 Configuration Vault**: Secure key management for API keys, billing credentials, and router administrative passwords.
* **Modern Web Console**: Real-time traffic analytics, interactive "+ Block" modal with TTL timeouts, lawful interception search, and Discord operations alerting.

---

## 🛠️ Quickstart & Deployment

### 1. Requirements
* Linux (Debian 12+ / Ubuntu 22.04+ recommended)
* Python 3.10+
* ClickHouse Server 23+

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/your-org/cgnat-ai-threat-shield.git
cd cgnat-ai-threat-shield

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

# Or run via systemd
sudo cp scripts/nat-ai-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nat-ai-agent
```

---

## 📜 License
Licensed under the [Apache License, Version 2.0](LICENSE).
