#!/bin/bash
INIT_FLAG="/opt/nat-ai-agent/data/.turnkey_initialized"

if [ ! -f "$INIT_FLAG" ]; then
    echo "=========================================================="
    echo "  INITIALIZING CGNAT TURNKEY MASTER APPLIANCE ON FIRST BOOT"
    echo "=========================================================="
    
    # Generate unique machine-id if missing
    if [ ! -s /etc/machine-id ]; then
        systemd-machine-id-setup
    fi

    # Generate SSH Host Keys if missing
    ssh-keygen -A 2>/dev/null || true

    # Initialize Vault if missing
    /opt/nat-ai-agent/venv/bin/python3 -c "
import sys; sys.path.insert(0, '/opt/nat-ai-agent')
from config_vault import ConfigVault
vault = ConfigVault()
vault.load()
" 2>/dev/null || true

    # Ensure ClickHouse tables exist
    clickhouse-client --query "CREATE DATABASE IF NOT EXISTS nat_logs;" 2>/dev/null || true

    chmod 600 /etc/cgnat.key /opt/nat-ai-agent/data/appliance.vault 2>/dev/null || true
    chmod -R 755 /opt/nat-ai-agent/static /opt/nat-ai-agent/templates 2>/dev/null || true

    touch "$INIT_FLAG"
    echo "TurnKey Appliance Initialized Successfully."
fi
