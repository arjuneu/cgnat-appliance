#!/bin/bash
set -e
echo "=========================================================="
echo "  CGNAT TURNKEY MASTER APPLIANCE - SYSPREP & CLEANING"
echo "=========================================================="

# 1. Stop background services during sysprep
systemctl stop nat-ai-agent.service vector.service || true

# 2. Reset ClickHouse database tables
echo "[1] Truncating ClickHouse flow logs..."
clickhouse-client --multiquery --query "
TRUNCATE TABLE IF EXISTS nat_logs.translations;
TRUNCATE TABLE IF EXISTS nat_logs.minute_rollups;
TRUNCATE TABLE IF EXISTS nat_logs.destination_intel;
" 2>/dev/null || true

# 3. Clean temporary files and downloads
echo "[2] Cleaning temporary files & caches..."
rm -rf /opt/nat-ai-agent/downloads/* /tmp/test_* /tmp/verify_* /tmp/*.py /var/log/vector/* 2>/dev/null || true
rm -f /opt/nat-ai-agent/data/.turnkey_initialized 2>/dev/null || true

# 4. Clean machine-id for cloning
echo "[3] Resetting machine-id..."
truncate -s 0 /etc/machine-id 2>/dev/null || true

# 5. Clean shell history
echo "[4] Clearing bash history..."
cat /dev/null > /root/.bash_history 2>/dev/null || true
history -c 2>/dev/null || true

# 6. Restart services
systemctl start vector.service nat-ai-agent.service || true

echo "=========================================================="
echo "  APPLIANCE IS READY FOR PROXMOX CLONING / TEMPLATE EXPORT"
echo "=========================================================="
