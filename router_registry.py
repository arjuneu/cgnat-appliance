"""
Router Registry & Fleet Configuration Manager
=============================================
Manages multi-vendor routers (MikroTik, Juniper, Huawei, Cisco) across the ISP network.
Passwords and credentials are encrypted securely in the Configuration Vault.
Supports multi-list and router-wise address-list/prefix-list policies.
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from config_vault import ConfigVault
from router_adapters import BaseRouterAdapter, create_router_adapter

logger = logging.getLogger("router_registry")

ROUTERS_FILE = os.getenv("ROUTERS_FILE", "/opt/nat-ai-agent/data/routers.json")
FALLBACK_ROUTERS_FILE = os.path.join(os.path.dirname(__file__), "data", "routers.json")

class RouterRegistry:
    def __init__(self, filepath: Optional[str] = None):
        self.filepath = filepath or (ROUTERS_FILE if os.path.exists(os.path.dirname(ROUTERS_FILE)) else FALLBACK_ROUTERS_FILE)
        self.vault = ConfigVault()
        self._ensure_storage()

    def _ensure_storage(self):
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        if not os.path.exists(self.filepath):
            default_routers = []
            self._write_routers(default_routers)

    def _read_routers(self) -> List[Dict[str, Any]]:
        try:
            if not os.path.exists(self.filepath):
                self._ensure_storage()
            with open(self.filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception as e:
            logger.error(f"Failed to read routers file {self.filepath}: {e}")
            return []

    def _write_routers(self, routers: List[Dict[str, Any]]) -> bool:
        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump(routers, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to write routers file {self.filepath}: {e}")
            return False

    def list_routers(self, mask_passwords: bool = True) -> List[Dict[str, Any]]:
        routers = self._read_routers()
        result = []
        for r in routers:
            r_copy = dict(r)
            router_id = r_copy.get("router_id") or r_copy.get("ip", "").replace(".", "_")
            r_copy["router_id"] = router_id
            
            # Normalize fields
            ip = r_copy.get("ip") or r_copy.get("router_ip", "")
            r_copy["ip"] = ip
            r_copy["router_ip"] = ip
            r_copy["status"] = r_copy.get("status", "online")
            r_copy["vendor"] = r_copy.get("vendor", "mikrotik").lower()
            r_copy["role"] = r_copy.get("role", "cgnat")
            default_list = r_copy.get("address_list") or ("THREAT-SHIELD-PREFIXES" if r_copy["vendor"] == "juniper" else "scanner")
            r_copy["address_list"] = default_list
            
            # Normalize supported_lists
            raw_supp = r_copy.get("supported_lists")
            if isinstance(raw_supp, list) and raw_supp:
                r_copy["supported_lists"] = [str(x).strip() for x in raw_supp if str(x).strip()]
            elif isinstance(raw_supp, str) and raw_supp.strip():
                r_copy["supported_lists"] = [x.strip() for x in raw_supp.split(",") if x.strip()]
            else:
                r_copy["supported_lists"] = [default_list]

            if default_list not in r_copy["supported_lists"]:
                r_copy["supported_lists"].insert(0, default_list)

            vault_key = r.get("password_vault_key") or f"ROUTER_PASS_{router_id.upper()}"
            stored_pwd = self.vault.get(vault_key, "")
            
            if mask_passwords:
                r_copy["password_masked"] = ConfigVault.mask_value(vault_key, stored_pwd) if stored_pwd else "(Not set)"
                if "password" in r_copy:
                    del r_copy["password"]
            else:
                r_copy["password"] = stored_pwd
            result.append(r_copy)
        return result

    def get_router(self, router_id: str) -> Optional[Dict[str, Any]]:
        for r in self.list_routers(mask_passwords=False):
            if r.get("router_id") == router_id or r.get("ip") == router_id:
                return r
        return None

    def add_router(self, router_data: Dict[str, Any], allow_update: bool = True) -> Tuple[bool, str]:
        routers = self._read_routers()
        ip = router_data.get("ip") or router_data.get("router_ip", "")
        router_data["ip"] = ip
        router_id = router_data.get("router_id", "").strip().lower()
        if not router_id:
            router_id = ip.replace(".", "_")
        
        for r in routers:
            if r.get("router_id") == router_id or r.get("ip") == ip or r.get("router_ip") == ip:
                if allow_update:
                    target_id = r.get("router_id") or router_id
                    return self.update_router(target_id, router_data)
                return False, f"Router with ID '{router_id}' or IP '{ip}' already exists"

        password = router_data.pop("password", None)
        vault_key = router_data.get("password_vault_key") or f"ROUTER_PASS_{router_id.upper()}"
        router_data["password_vault_key"] = vault_key
        router_data["router_id"] = router_id
        
        # Normalize supported_lists
        if "supported_lists" in router_data:
            if isinstance(router_data["supported_lists"], str):
                router_data["supported_lists"] = [x.strip() for x in router_data["supported_lists"].split(",") if x.strip()]

        if password:
            self.vault.set(vault_key, password)

        routers.append(router_data)
        self._write_routers(routers)
        return True, f"Router '{router_data.get('name', router_id)}' successfully registered."

    def update_router(self, router_id: str, update_data: Dict[str, Any]) -> Tuple[bool, str]:
        routers = self._read_routers()
        target_idx = None
        for i, r in enumerate(routers):
            if r.get("router_id") == router_id or r.get("ip") == router_id:
                target_idx = i
                break
        if target_idx is None:
            return False, f"Router '{router_id}' not found"

        password = update_data.pop("password", None)
        vault_key = routers[target_idx].get("password_vault_key") or f"ROUTER_PASS_{router_id.upper()}"
        
        if password:
            self.vault.set(vault_key, password)

        if "supported_lists" in update_data:
            if isinstance(update_data["supported_lists"], str):
                update_data["supported_lists"] = [x.strip() for x in update_data["supported_lists"].split(",") if x.strip()]

        for k, v in update_data.items():
            if k != "router_id":
                routers[target_idx][k] = v

        self._write_routers(routers)
        return True, f"Router '{router_id}' updated successfully."

    def delete_router(self, router_id: str) -> Tuple[bool, str]:
        routers = self._read_routers()
        new_routers = [r for r in routers if r.get("router_id") != router_id and r.get("ip") != router_id]
        if len(new_routers) == len(routers):
            return False, f"Router '{router_id}' not found"
        self._write_routers(new_routers)
        return True, f"Router '{router_id}' removed from fleet."

    def get_adapters(self, enabled_only: bool = False) -> List[BaseRouterAdapter]:
        adapters = []
        for r in self.list_routers(mask_passwords=False):
            if enabled_only and not r.get("sync_enabled", True):
                continue
            adapters.append(create_router_adapter(r))
        return adapters

    def get_adapter_by_ip(self, ip_str: str) -> Optional[BaseRouterAdapter]:
        if not ip_str:
            return None
        for r in self.list_routers(mask_passwords=False):
            if r.get("ip") == ip_str or r.get("router_ip") == ip_str or r.get("router_id") == ip_str:
                return create_router_adapter(r)
        return None

    def get_adapter(self, router_id: str) -> Optional[BaseRouterAdapter]:
        r = self.get_router(router_id)
        if r:
            return create_router_adapter(r)
        return None

router_registry = RouterRegistry()
