#!/usr/bin/env python3
"""
Legacy Backward Compatibility Shim
==================================
mikrotik_sync.py has been refactored and generalized to router_sync.py to support
multi-vendor fleet routers (MikroTik, Juniper, Cisco, Huawei).

This module re-exports all functions, classes, and constants from router_sync for
seamless backward compatibility with existing services, scripts, and endpoints.
"""
from router_sync import *
import router_sync

if __name__ == "__main__":
    if hasattr(router_sync, "main"):
        router_sync.main()
