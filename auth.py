import os
import json
import time
import base64
import hmac
import hashlib
import secrets
import threading
from typing import Optional, Dict, List, Any
from fastapi import Header, HTTPException, Depends

SECRET_KEY = os.environ.get("NAT_AI_SECRET_KEY", "cgnat-appliance-secret-key-2026")
DATA_DIR = os.environ.get("NAT_AI_DATA_DIR", "/opt/nat-ai-agent/data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")

def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return key.hex(), salt

def verify_password(password: str, password_hash: str, salt: str) -> bool:
    expected_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(expected_hash, password_hash)

class UserManager:
    def __init__(self, filepath: str = USERS_FILE):
        self.filepath = filepath
        self.lock = threading.Lock()
        self.active_sessions: Dict[str, float] = {}
        self._ensure_storage()

    def record_activity(self, username: str):
        if username:
            with self.lock:
                self.active_sessions[username.strip().lower()] = time.time()

    def _ensure_storage(self):
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        if not os.path.exists(self.filepath):
            # Create default admin user
            pwd_hash, salt = hash_password("admin")
            initial_users = {
                "admin": {
                    "username": "admin",
                    "password_hash": pwd_hash,
                    "salt": salt,
                    "role": "admin",
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "last_login": None
                }
            }
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump(initial_users, f, indent=2)

    def _read_users(self) -> Dict[str, Dict[str, Any]]:
        with self.lock:
            try:
                if not os.path.exists(self.filepath):
                    self._ensure_storage()
                with open(self.filepath, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}

    def _write_users(self, users: Dict[str, Dict[str, Any]]):
        with self.lock:
            temp_path = self.filepath + ".tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(users, f, indent=2)
            os.replace(temp_path, self.filepath)

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        username = username.strip().lower()
        users = self._read_users()
        user = users.get(username)
        
        if not user:
            return None
        if verify_password(password, user["password_hash"], user["salt"]):
            user["last_login"] = time.strftime("%Y-%m-%d %H:%M:%S")
            users[username] = user
            self._write_users(users)
            self.record_activity(username)
            return {"username": user["username"], "role": user.get("role", "operator")}
        return None

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        users = self._read_users()
        user = users.get(username)
        if user:
            uname = user["username"].lower()
            last_seen = self.active_sessions.get(uname, 0)
            is_online = (time.time() - last_seen) <= 900
            return {
                "username": user["username"],
                "role": user.get("role", "operator"),
                "created_at": user.get("created_at"),
                "last_login": user.get("last_login"),
                "is_online": is_online
            }
        return None

    def list_users(self) -> List[Dict[str, Any]]:
        users = self._read_users()
        result = []
        now = time.time()
        for u in users.values():
            uname = u["username"].lower()
            last_seen = self.active_sessions.get(uname, 0)
            is_online = (now - last_seen) <= 900
            result.append({
                "username": u["username"],
                "role": u.get("role", "operator"),
                "created_at": u.get("created_at"),
                "last_login": u.get("last_login"),
                "is_online": is_online
            })
        return sorted(result, key=lambda x: x["username"])

    def create_user(self, username: str, password: str, role: str = "operator") -> Dict[str, Any]:
        username = username.strip().lower()
        if not username or len(username) < 3:
            raise ValueError("Username must be at least 3 characters long")
        if not password or len(password) < 4:
            raise ValueError("Password must be at least 4 characters long")
        if role not in ("admin", "operator", "viewer"):
            role = "operator"

        users = self._read_users()
        if username in users:
            raise ValueError(f"User '{username}' already exists")

        pwd_hash, salt = hash_password(password)
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        user_record = {
            "username": username,
            "password_hash": pwd_hash,
            "salt": salt,
            "role": role,
            "created_at": now_str,
            "last_login": None
        }
        users[username] = user_record
        self._write_users(users)
        return {"username": username, "role": role, "created_at": now_str}

    def change_password(self, username: str, current_password: str, new_password: str) -> bool:
        if not new_password or len(new_password) < 4:
            raise ValueError("New password must be at least 4 characters long")
        users = self._read_users()
        user = users.get(username)
        if not user:
            raise ValueError("User not found")
        if not verify_password(current_password, user["password_hash"], user["salt"]):
            raise ValueError("Incorrect current password")

        pwd_hash, salt = hash_password(new_password)
        user["password_hash"] = pwd_hash
        user["salt"] = salt
        users[username] = user
        self._write_users(users)
        return True

    def admin_reset_password(self, target_username: str, new_password: str) -> bool:
        if not new_password or len(new_password) < 4:
            raise ValueError("New password must be at least 4 characters long")
        users = self._read_users()
        user = users.get(target_username)
        if not user:
            raise ValueError("User not found")

        pwd_hash, salt = hash_password(new_password)
        user["password_hash"] = pwd_hash
        user["salt"] = salt
        users[target_username] = user
        self._write_users(users)
        return True

    def update_user_role(self, target_username: str, new_role: str, requester_username: str) -> bool:
        target = target_username.strip().lower()
        if target == "admin":
            raise ValueError("The 'admin' user role cannot be modified")
        if new_role not in ("admin", "operator", "viewer"):
            raise ValueError("Invalid role specified. Must be 'admin', 'operator', or 'viewer'")
        
        users = self._read_users()
        user = users.get(target)
        if not user:
            raise ValueError("User not found")
        
        user["role"] = new_role
        users[target] = user
        self._write_users(users)
        return True

    def delete_user(self, target_username: str, requester_username: str) -> bool:
        if target_username == requester_username:
            raise ValueError("You cannot delete your own account")
        users = self._read_users()
        if target_username not in users:
            raise ValueError("User not found")

        # Ensure we don't delete the last admin
        admin_count = sum(1 for u in users.values() if u.get("role") == "admin")
        if users[target_username].get("role") == "admin" and admin_count <= 1:
            raise ValueError("Cannot delete the last remaining administrator account")

        del users[target_username]
        self._write_users(users)
        return True

user_manager = UserManager()

def create_access_token(username: str, role: str = "operator", expires_in_seconds: int = 86400 * 7) -> str:
    exp = int(time.time()) + expires_in_seconds
    payload = {"sub": username, "role": role, "exp": exp}
    payload_bytes = json.dumps(payload).encode('utf-8')
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode('utf-8').rstrip("=")
    
    signature = hmac.new(SECRET_KEY.encode('utf-8'), payload_b64.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{signature}"

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        if "." not in token:
            return None
        payload_b64, signature = token.split(".", 1)
        expected_sig = hmac.new(SECRET_KEY.encode('utf-8'), payload_b64.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            return None
        
        padding = 4 - (len(payload_b64) % 4)
        if padding != 4:
            payload_b64 += "=" * padding
            
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode('utf-8'))
        if payload.get("exp", 0) < time.time():
            return None
        return {"username": payload.get("sub"), "role": payload.get("role", "operator")}
    except Exception:
        return None

def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization:
        raise HTTPException(status_code=401, detail="Authentication required")
    token = authorization.replace("Bearer ", "").strip()
    user_info = verify_token(token)
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid or expired session token")
    user_manager.record_activity(user_info.get("username", ""))
    return user_info

def require_admin(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Administrator privileges required")
    return current_user

def require_operator(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if current_user.get("role") not in ("admin", "operator"):
        raise HTTPException(status_code=403, detail="Operator or Administrator privileges required")
    return current_user

def get_optional_user(authorization: Optional[str] = Header(None)) -> Optional[Dict[str, Any]]:
    if not authorization:
        return None
    token = authorization.replace("Bearer ", "").strip()
    return verify_token(token)
