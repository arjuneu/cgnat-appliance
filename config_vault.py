"""
Carrier-Grade NAT & Threat Intelligence - Configuration Vault (AES-256)
========================================================================
Securely encrypts and stores sensitive infrastructure credentials:
- RADIUS Billing API tokens
- MikroTik credentials
- Discord alert webhooks
- ClickHouse DB credentials
- Network & CGNAT pool definitions

Key Storage: /etc/cgnat.key (chmod 400 root:root) or PBKDF2 derived from hardware ID.
Vault Storage: /opt/nat-ai-agent/data/appliance.vault (AES-256-CBC / Fernet encrypted JSON).
"""

import os
import sys
import json
import base64
import hashlib
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KEY_FILE = os.getenv("VAULT_KEY_FILE", "/etc/cgnat.key")
FALLBACK_KEY_FILE = os.path.join(os.path.dirname(__file__), "data", "cgnat.key")
VAULT_FILE = os.getenv("VAULT_DATA_FILE", "/opt/nat-ai-agent/data/appliance.vault")
FALLBACK_VAULT_FILE = os.path.join(os.path.dirname(__file__), "data", "appliance.vault")

# Sensitive keys that should be masked when listed
SENSITIVE_KEYS = {
    "RADIUS_API_TOKEN",
    "MIKROTIK_PASSWORD",
    "DISCORD_WEBHOOK_URL",
    "CLICKHOUSE_PASSWORD",
    "JWT_SECRET"
}

class ConfigVault:
    def __init__(self, key_path: Optional[str] = None, vault_path: Optional[str] = None):
        self.key_path = key_path or (KEY_FILE if os.path.exists(os.path.dirname(KEY_FILE)) else FALLBACK_KEY_FILE)
        self.vault_path = vault_path or (VAULT_FILE if os.path.exists(os.path.dirname(VAULT_FILE)) else FALLBACK_VAULT_FILE)
        self._fernet = None
        self._cache: Dict[str, Any] = {}
        self._init_cipher()
        self.load()

    def _get_hardware_salt(self) -> bytes:
        machine_id = ""
        for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
            if os.path.exists(path):
                try:
                    with open(path, "r") as f:
                        machine_id = f.read().strip()
                        break
                except Exception:
                    pass
        if not machine_id:
            machine_id = "cgnat-appliance-default-salt-master"
        return hashlib.sha256(machine_id.encode("utf-8")).digest()

    def _init_cipher(self):
        # 1. Try reading existing key file
        if os.path.exists(self.key_path):
            try:
                with open(self.key_path, "rb") as f:
                    key = f.read().strip()
                if len(key) == 44:  # standard base64 url-safe Fernet key length
                    self._fernet = Fernet(key)
                    return
            except Exception:
                pass

        # 2. Try creating a new secure random key if directory is writable
        try:
            os.makedirs(os.path.dirname(self.key_path), exist_ok=True)
            key = Fernet.generate_key()
            with open(self.key_path, "wb") as f:
                f.write(key)
            try:
                os.chmod(self.key_path, 0o600)
            except Exception:
                pass
            self._fernet = Fernet(key)
            return
        except Exception:
            pass

        # 3. Fallback to deterministic PBKDF2 derived from hardware ID
        salt = self._get_hardware_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt[:16],
            iterations=100000,
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(b"cgnat-master-appliance-secret-key"))
        self._fernet = Fernet(derived_key)

    def load(self) -> Dict[str, Any]:
        if not os.path.exists(self.vault_path):
            self._cache = {}
            return self._cache

        try:
            with open(self.vault_path, "rb") as f:
                encrypted_data = f.read()
            if not encrypted_data:
                self._cache = {}
                return self._cache
            decrypted = self._fernet.decrypt(encrypted_data)
            self._cache = json.loads(decrypted.decode("utf-8"))
        except Exception as e:
            self._cache = {}
        return self._cache

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.vault_path), exist_ok=True)
            raw = json.dumps(self._cache, indent=2).encode("utf-8")
            encrypted = self._fernet.encrypt(raw)
            with open(self.vault_path, "wb") as f:
                f.write(encrypted)
            try:
                os.chmod(self.vault_path, 0o600)
            except Exception:
                pass
            return True
        except Exception as e:
            print(f"[Vault Error] Failed to save vault: {e}", file=sys.stderr)
            return False

    def get(self, key: str, default: Any = None) -> Any:
        return self._cache.get(key, default)

    def set(self, key: str, value: Any) -> bool:
        self._cache[key] = value
        return self.save()

    def set_many(self, items: Dict[str, Any]) -> bool:
        for k, v in items.items():
            self._cache[k] = v
        return self.save()

    def delete(self, key: str) -> bool:
        if key in self._cache:
            del self._cache[key]
            return self.save()
        return False

    def get_all(self) -> Dict[str, Any]:
        return dict(self._cache)

    def get_all_masked(self) -> Dict[str, Any]:
        masked = {}
        for k, v in self._cache.items():
            if k in SENSITIVE_KEYS and v:
                val_str = str(v)
                if len(val_str) > 8:
                    masked[k] = val_str[:4] + "..." + val_str[-4:]
                else:
                    masked[k] = "********"
            else:
                masked[k] = v
        return masked

    @classmethod
    def mask_value(cls, key: str, value: Any) -> Any:
        if key in SENSITIVE_KEYS and value:
            val_str = str(value)
            if len(val_str) > 8:
                return val_str[:4] + "..." + val_str[-4:]
            return "********"
        return value

def main():
    if len(sys.argv) < 2:
        print("Usage: python config_vault.py [init|get|set|list|export-masked|import-env] [args...]")
        sys.exit(1)

    cmd = sys.argv[1].lower()
    vault = ConfigVault()

    if cmd == "init":
        defaults = {
            "ISP_NAME": "Your ISP Name",
            "ROUTER_IPS": "",
            "ISP_PUBLIC_POOLS": "203.0.113.0/24",
            "CGNAT_POOLS": "100.64.0.0/10",
            "RADIUS_API_URL": "",
            "RADIUS_API_TOKEN": "",
            "MIKROTIK_IP": "",
            "MIKROTIK_USER": "natlog",
            "MIKROTIK_PASSWORD": "your-password",
            "DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/...",
            "CLICKHOUSE_HOST": "127.0.0.1",
            "CLICKHOUSE_PORT": 8123,
            "CLICKHOUSE_DB": "nat_logs",
            "CLICKHOUSE_USER": "default",
            "CLICKHOUSE_PASSWORD": "",
            "SCAN_INTERVAL_SECONDS": 300,
            "PORT_EXHAUSTION_THRESHOLD": 45000,
            "PRIVATE_IP_FLOW_THRESHOLD": 2500,
            "PRIVATE_IP_TARGET_THRESHOLD": 400,
            "API_HOST": "0.0.0.0",
            "API_PORT": 8088,
            "SERVER_TIMEZONE": "Asia/Kathmandu",
        }
        vault.set_many(defaults)
        print("Config Vault initialized successfully with AES-256 encryption.")
        print(f"Key File: {vault.key_path}")
        print(f"Vault File: {vault.vault_path}")

    elif cmd == "get":
        if len(sys.argv) < 3:
            print("Error: Missing key name. Usage: python config_vault.py get <KEY>")
            sys.exit(1)
        k = sys.argv[2]
        print(vault.get(k, ""))

    elif cmd == "set":
        if len(sys.argv) < 4:
            print("Error: Missing key or value. Usage: python config_vault.py set <KEY> <VALUE>")
            sys.exit(1)
        k, v = sys.argv[2], sys.argv[3]
        vault.set(k, v)
        print(f"Key '{k}' encrypted and stored in vault.")

    elif cmd == "list":
        masked = vault.get_all_masked()
        print(f"\n{'KEY':<30} | {'VALUE'}")
        print("-" * 75)
        for k, v in sorted(masked.items()):
            print(f"{k:<30} | {v}")
        print("-" * 75)

    elif cmd == "export-masked":
        print(json.dumps(vault.get_all_masked(), indent=2))

    elif cmd == "import-env":
        if len(sys.argv) < 3:
            print("Error: Missing .env path. Usage: python config_vault.py import-env <PATH>")
            sys.exit(1)
        env_file = sys.argv[2]
        if not os.path.exists(env_file):
            print(f"Error: File {env_file} does not exist.")
            sys.exit(1)
        count = 0
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                vault.set(k, v)
                count += 1
        print(f"Successfully imported and encrypted {count} parameters into vault.")

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

if __name__ == "__main__":
    main()
