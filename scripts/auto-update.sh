#!/usr/bin/env bash
# ==============================================================================
# CGNAT AI Threat Shield - Automated Update Script
# Updates repository from GitHub, installs new requirements, and restarts daemon.
# ==============================================================================
set -e

APP_DIR="/opt/nat-ai-agent"
cd "$APP_DIR"

echo "Checking for updates from GitHub..."
git fetch origin main --quiet

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" = "$REMOTE" ]; then
    echo "Appliance is already up to date (commit: ${LOCAL:0:8})."
    exit 0
fi

echo "New update found! (${LOCAL:0:8} -> ${REMOTE:0:8})"
echo "Pulling updates..."
git pull --rebase origin main

# Check if requirements changed
if git diff --name-only "$LOCAL" HEAD | grep -q "requirements.txt"; then
    echo "Updating Python virtual environment packages..."
    if [ -f "$APP_DIR/venv/bin/pip" ]; then
        "$APP_DIR/venv/bin/pip" install -q -r requirements.txt
    fi
fi

# Restart service if running
if systemctl is-active --quiet nat-ai-agent; then
    echo "Restarting nat-ai-agent service..."
    systemctl restart nat-ai-agent
fi

echo "Successfully updated to commit $(git rev-parse --short HEAD)!"
