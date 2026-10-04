#!/usr/bin/env python3
"""
Encrypted AI Key Vault Manager
==============================
Handles encryption at rest, custom naming, and priority reordering (Up/Down) for Gemini API keys.
"""

import os
import json
import time
import base64
import logging
import urllib.request
import urllib.error
from typing import Dict, List, Tuple, Any, Optional

try:
    from cryptography.fernet import Fernet
except ImportError:
    Fernet = None

logger = logging.getLogger("ai_key_vault")

KEY_FILE = os.getenv("CGNAT_KEY_PATH", "/etc/cgnat.key")
VAULT_FILE = os.getenv("AI_KEYS_VAULT_PATH", "/opt/nat-ai-agent/data/ai_keys.vault")

# Default Initial Seed Keys
INITIAL_SEED_KEYS: List[Dict[str, Any]] = []

class AIKeyVault:
    def __init__(self, key_path: str = KEY_FILE, vault_path: str = VAULT_FILE):
        self.key_path = key_path
        self.vault_path = vault_path
        self.cipher = None
        self._init_cipher()
        self._init_vault_if_missing()

    def _init_cipher(self):
        if not Fernet:
            logger.warning("cryptography package not found, fallback to base64 obfuscation.")
            return

        key = None
        if os.path.exists(self.key_path):
            try:
                with open(self.key_path, "rb") as f:
                    key = f.read().strip()
            except Exception as e:
                logger.error(f"Error reading key file {self.key_path}: {e}")

        if not key:
            try:
                key = Fernet.generate_key()
                os.makedirs(os.path.dirname(self.key_path) or ".", exist_ok=True)
                with open(self.key_path, "wb") as f:
                    f.write(key)
                os.chmod(self.key_path, 0o600)
            except Exception as e:
                logger.error(f"Failed to generate key file {self.key_path}: {e}")
                key = Fernet.generate_key()

        self.cipher = Fernet(key)

    def _encrypt(self, data_str: str) -> str:
        if self.cipher:
            return self.cipher.encrypt(data_str.encode("utf-8")).decode("utf-8")
        return base64.b64encode(data_str.encode("utf-8")).decode("utf-8")

    def _decrypt(self, enc_str: str) -> str:
        if self.cipher:
            return self.cipher.decrypt(enc_str.encode("utf-8")).decode("utf-8")
        return base64.b64decode(enc_str.encode("utf-8")).decode("utf-8")

    def _read_vault(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.vault_path):
            return []
        try:
            with open(self.vault_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return []
                dec_json = self._decrypt(content)
                return json.loads(dec_json)
        except Exception as e:
            logger.error(f"Failed to read encrypted vault: {e}")
            return []

    def _write_vault(self, keys_list: List[Dict[str, Any]]):
        try:
            os.makedirs(os.path.dirname(self.vault_path) or ".", exist_ok=True)
            enc_data = self._encrypt(json.dumps(keys_list, indent=2))
            with open(self.vault_path, "w", encoding="utf-8") as f:
                f.write(enc_data)
            try: os.chmod(self.vault_path, 0o600)
            except: pass
        except Exception as e:
            logger.error(f"Failed to write encrypted vault: {e}")

    def _init_vault_if_missing(self):
        if not os.path.exists(self.vault_path) or os.path.getsize(self.vault_path) == 0:
            logger.info("Initializing AI Key Vault with default ordered seed keys...")
            self._write_vault(INITIAL_SEED_KEYS)

    def get_keys(self, masked: bool = True) -> List[Dict[str, Any]]:
        """Returns all keys in current priority order."""
        keys = self._read_vault()
        results = []
        for idx, k in enumerate(keys, 1):
            raw = k.get("key", "")
            masked_str = f"{raw[:12]}...{raw[-6:]}" if len(raw) > 18 else "***"
            results.append({
                "id": k.get("id"),
                "priority": idx,
                "name": k.get("name", f"Account {idx}"),
                "key": masked_str if masked else raw,
                "status": k.get("status", "active"),
                "created_at": k.get("created_at", ""),
                "last_used": k.get("last_used", "")
            })
        return results

    def get_raw_keys_in_order(self) -> List[Tuple[str, str]]:
        """Returns list of (key_name, raw_key) in exact priority order."""
        keys = self._read_vault()
        return [(k.get("name", "Unknown Account"), k.get("key", "")) for k in keys if k.get("key")]

    def add_key(self, name: str, raw_key: str) -> Dict[str, Any]:
        """Adds a new key to the bottom of the priority pool."""
        keys = self._read_vault()
        new_id = f"key_{int(time.time())}_{len(keys)+1}"
        new_entry = {
            "id": new_id,
            "name": name.strip() or f"Account {len(keys)+1}",
            "key": raw_key.strip(),
            "status": "active",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        keys.append(new_entry)
        self._write_vault(keys)
        return new_entry

    def rename_key(self, key_id: str, new_name: str) -> bool:
        """Renames an existing key."""
        keys = self._read_vault()
        found = False
        for k in keys:
            if k.get("id") == key_id:
                k["name"] = new_name.strip()
                found = True
                break
        if found:
            self._write_vault(keys)
        return found

    def delete_key(self, key_id: str) -> bool:
        """Deletes a key from the pool."""
        keys = self._read_vault()
        new_keys = [k for k in keys if k.get("id") != key_id]
        if len(new_keys) != len(keys):
            self._write_vault(new_keys)
            return True
        return False

    def move_key(self, key_id: str, direction: str) -> bool:
        """Moves a key 'up' or 'down' in priority order."""
        keys = self._read_vault()
        idx = -1
        for i, k in enumerate(keys):
            if k.get("id") == key_id:
                idx = i
                break
        if idx == -1:
            return False

        if direction == "up" and idx > 0:
            keys[idx - 1], keys[idx] = keys[idx], keys[idx - 1]
            self._write_vault(keys)
            return True
        elif direction == "down" and idx < len(keys) - 1:
            keys[idx + 1], keys[idx] = keys[idx], keys[idx + 1]
            self._write_vault(keys)
            return True
        return False

    def reorder_keys(self, ordered_ids: List[str]) -> bool:
        """Reorders keys according to a specific list of IDs."""
        keys = self._read_vault()
        key_map = {k["id"]: k for k in keys}
        new_keys = []
        for kid in ordered_ids:
            if kid in key_map:
                new_keys.append(key_map[kid])
        # Append any missing
        for k in keys:
            if k["id"] not in ordered_ids:
                new_keys.append(k)
        self._write_vault(new_keys)
        return True

    def test_key(self, raw_key: str) -> Tuple[bool, str]:
        """Tests live authentication of a key against Gemini API."""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent?key={raw_key}"
        payload = {
            "contents": [{"parts": [{"text": "Ping"}]}],
            "generationConfig": {"maxOutputTokens": 5}
        }
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                if resp.status == 200:
                    return True, "Authentication Successful (200 OK)"
                return False, f"Unexpected Status {resp.status}"
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode("utf-8", errors="ignore")
            if e.code == 429:
                return False, "Rate Limit / Quota Exceeded (HTTP 429)"
            return False, f"HTTP Error {e.code}: {err_msg[:80]}"
        except Exception as e:
            return False, f"Connection Failed: {str(e)}"

# Singleton Instance
key_vault = AIKeyVault()

if __name__ == "__main__":
    print("=== AI KEY VAULT TEST ===")
    keys = key_vault.get_keys(masked=True)
    for k in keys:
        print(f"#{k['priority']} | {k['id']} | {k['name']} | {k['key']} | {k['status']}")
