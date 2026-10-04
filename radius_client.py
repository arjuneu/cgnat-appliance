import time
import json
import logging
import requests
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
import config

logger = logging.getLogger("radius_client")

def extract_json_path(data_dict: Any, path: str, default: str = "") -> str:
    """Safely extracts nested JSON values via dotted path notation (e.g. 'customer.name')."""
    if not isinstance(data_dict, dict) or not path:
        return default
    keys = path.strip().split(".")
    val = data_dict
    for k in keys:
        if isinstance(val, dict) and k in val:
            val = val[k]
        else:
            return default
    return str(val) if val is not None else default

class RadiusClient:
    def __init__(self):
        self.cache: Dict[str, List[Dict[str, Any]]] = {}
        self.cache_ttl_seconds = 600  # 10 min cache
        self.max_workers = 15
        self.reload_config()

    def reload_config(self):
        self.enabled = getattr(config, "RADIUS_ENABLED", True)
        self.api_url = getattr(config, "RADIUS_API_URL", "")
        self.token = getattr(config, "RADIUS_API_TOKEN", "")
        self.auth_type = getattr(config, "RADIUS_AUTH_TYPE", "bearer")  # bearer, header, basic, query, none
        self.auth_header = getattr(config, "RADIUS_AUTH_HEADER", "Authorization")
        self.http_method = getattr(config, "RADIUS_HTTP_METHOD", "GET").upper()
        self.param_ip = getattr(config, "RADIUS_PARAM_IP", "ip")
        self.param_time = getattr(config, "RADIUS_PARAM_TIME", "timestamp")
        
        # Default JSON field paths
        self.field_username = getattr(config, "RADIUS_FIELD_USERNAME", "customer.pppoe_username")
        self.field_name = getattr(config, "RADIUS_FIELD_NAME", "customer.name")
        self.field_code = getattr(config, "RADIUS_FIELD_CODE", "customer.customer_code")
        self.field_phone = getattr(config, "RADIUS_FIELD_PHONE", "customer.contact.primary")
        self.field_address = getattr(config, "RADIUS_FIELD_ADDRESS", "customer.address")
        self.field_branch = getattr(config, "RADIUS_FIELD_BRANCH", "customer.branch")
        self.field_mac = getattr(config, "RADIUS_FIELD_MAC", "session.mac_address")
        self.field_start = getattr(config, "RADIUS_FIELD_START", "session.session_start_time")
        self.field_stop = getattr(config, "RADIUS_FIELD_STOP", "session.session_stop_time")

    def _parse_datetime(self, dt_str: Optional[str]) -> Optional[datetime]:
        if not dt_str:
            return None
        dt_str = str(dt_str).strip().replace("T", " ")
        if "." in dt_str:
            dt_str = dt_str.split(".")[0]
        if "+" in dt_str:
            dt_str = dt_str.split("+")[0]
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                return datetime.strptime(dt_str, fmt)
            except ValueError:
                pass
        return None

    def lookup_subscriber(self, ip: str, timestamp_str: Optional[str] = None) -> Optional[Dict[str, Any]]:
        ip = str(ip).strip()
        if not ip or not self.api_url:
            return None

        event_dt = self._parse_datetime(timestamp_str) or datetime.now()
        now_ts = time.time()

        # Check in-memory cache
        if ip in self.cache:
            for entry in self.cache[ip]:
                if now_ts - entry["cached_at"] > self.cache_ttl_seconds:
                    continue
                start_dt = entry["start_dt"]
                stop_dt = entry["stop_dt"]
                if start_dt and event_dt >= start_dt:
                    if stop_dt is None or event_dt <= stop_dt:
                        return entry["normalized"]
                elif not start_dt and not stop_dt:
                    return entry["normalized"]

        formatted_ts = event_dt.strftime("%Y-%m-%d %H:%M:%S")
        headers = {"Accept": "application/json"}
        params = {}
        json_body = None

        if self.auth_type == "bearer" and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        elif self.auth_type == "header" and self.token:
            headers[self.auth_header] = self.token
        elif self.auth_type == "query" and self.token:
            params["token"] = self.token

        if self.http_method == "GET":
            params[self.param_ip] = ip
            params[self.param_time] = formatted_ts
        else:
            json_body = {
                self.param_ip: ip,
                self.param_time: formatted_ts
            }

        try:
            if self.http_method == "GET":
                resp = requests.get(self.api_url, headers=headers, params=params, timeout=5)
            else:
                resp = requests.post(self.api_url, headers=headers, json=json_body, timeout=5)

            if resp.status_code == 200:
                body = resp.json()
                data_payload = body.get("data") if (isinstance(body, dict) and "data" in body) else body

                cust = data_payload.get("customer") if isinstance(data_payload, dict) else {}
                sess = data_payload.get("session") if isinstance(data_payload, dict) else {}
                contact = cust.get("contact") if isinstance(cust, dict) else {}
                email = cust.get("email") if isinstance(cust, dict) else {}

                username = cust.get("pppoe_username") or sess.get("username") or extract_json_path(data_payload, self.field_username, default="")
                name = cust.get("name") or extract_json_path(data_payload, self.field_name, default="")
                customer_code = cust.get("customer_code") or extract_json_path(data_payload, self.field_code, default="")
                
                phone = (contact.get("primary") if isinstance(contact, dict) else "") or cust.get("phone") or extract_json_path(data_payload, self.field_phone, default="")
                sec_phone = contact.get("secondary", "") if isinstance(contact, dict) else ""
                
                address = cust.get("address") or extract_json_path(data_payload, self.field_address, default="")
                branch = cust.get("branch") or extract_json_path(data_payload, self.field_branch, default="")
                mac_address = sess.get("mac_address") or extract_json_path(data_payload, self.field_mac, default="")
                account_type = cust.get("account_type") or "Personal"

                session_start = sess.get("session_start_time") or extract_json_path(data_payload, self.field_start, default="")
                session_stop = sess.get("session_stop_time") or extract_json_path(data_payload, self.field_stop, default="")

                normalized = {
                    "username": username or "--",
                    "name": name or "N/A",
                    "customer_name": name or "N/A",
                    "customer_code": customer_code or "",
                    "account_type": account_type or "Personal",
                    "phone": phone or "N/A",
                    "primary_contact": phone or "N/A",
                    "secondary_contact": sec_phone or "",
                    "primary_email": email.get("primary", "") if isinstance(email, dict) else (cust.get("email", "") or ""),
                    "secondary_email": email.get("secondary", "") if isinstance(email, dict) else "",
                    "address": address or "N/A",
                    "branch": branch or "N/A",
                    "mac_address": mac_address or "",
                    "session_start": session_start or "N/A",
                    "session_stop": session_stop or "N/A",
                    "session_start_time": session_start or "N/A",
                    "session_stop_time": session_stop or "N/A",
                    "customer": cust,
                    "session": sess,
                    "raw": data_payload
                }

                start_dt = self._parse_datetime(session_start)
                stop_dt = self._parse_datetime(session_stop)

                cache_item = {
                    "start_dt": start_dt,
                    "stop_dt": stop_dt,
                    "normalized": normalized,
                    "cached_at": now_ts
                }
                if ip not in self.cache:
                    self.cache[ip] = []
                self.cache[ip].append(cache_item)

                return normalized
            else:
                logger.warning(f"RADIUS lookup for {ip} returned HTTP {resp.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error querying RADIUS API for {ip}: {e}")
            return None

    def batch_lookup_records(self, records: Any, full_details: bool = False) -> Any:
        """
        Enriches records with RADIUS subscriber metadata.
        Supports:
        - List of dicts (from collector.py query_forensics or export_forensic_records)
        - List of (ip, timestamp) tuples
        """
        if not records:
            return records

        if not self.enabled or not self.api_url:
            return records

        # Case 1: List of Dictionaries (Collector preview rows & export records)
        if isinstance(records, list) and len(records) > 0 and isinstance(records[0], dict):
            ip_ts_map = {}
            for r in records:
                ip = r.get("src_ip") or (r.get("subscriber", "").split(":")[0] if ":" in r.get("subscriber", "") else r.get("subscriber", ""))
                ts = r.get("timestamp") or r.get("time_str") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if ip and ip not in ip_ts_map:
                    ip_ts_map[ip] = ts

            def _fetch(item):
                _ip, _ts = item
                return _ip, self.lookup_subscriber(_ip, _ts)

            results = {}
            with ThreadPoolExecutor(max_workers=min(self.max_workers, len(ip_ts_map) or 1)) as executor:
                for _ip, sub_data in executor.map(_fetch, ip_ts_map.items()):
                    if sub_data:
                        results[_ip] = sub_data

            for r in records:
                ip = r.get("src_ip") or (r.get("subscriber", "").split(":")[0] if ":" in r.get("subscriber", "") else r.get("subscriber", ""))
                sub_info = results.get(ip)
                if sub_info:
                    r["username"] = sub_info.get("username") or "--"
                    if full_details:
                        r["session_start_time"] = sub_info.get("session_start_time") or "N/A"
                        r["session_stop_time"] = sub_info.get("session_stop_time") or "N/A"
                        r["account_type"] = sub_info.get("account_type") or "Personal"
                        r["customer_name"] = sub_info.get("customer_name") or sub_info.get("name") or "N/A"
                        r["primary_contact"] = sub_info.get("primary_contact") or sub_info.get("phone") or "N/A"
                        r["secondary_contact"] = sub_info.get("secondary_contact") or ""
                        r["primary_email"] = sub_info.get("primary_email") or ""
                        r["secondary_email"] = sub_info.get("secondary_email") or ""
                        r["address"] = sub_info.get("address") or "N/A"
                        r["branch"] = sub_info.get("branch") or "N/A"
                        r["customer_code"] = sub_info.get("customer_code") or ""
                        r["mac_address"] = sub_info.get("mac_address") or ""
                else:
                    if full_details:
                        r.setdefault("session_start_time", "N/A")
                        r.setdefault("session_stop_time", "N/A")
                        r.setdefault("account_type", "N/A")
                        r.setdefault("customer_name", "N/A")
                        r.setdefault("primary_contact", "N/A")
                        r.setdefault("secondary_contact", "")
                        r.setdefault("primary_email", "")
                        r.setdefault("secondary_email", "")
                        r.setdefault("address", "N/A")

            return records

        # Case 2: List of (ip, ts) Tuples
        elif isinstance(records, list) and len(records) > 0 and isinstance(records[0], (tuple, list)):
            return self.bulk_lookup(records)

        return records

    def bulk_lookup(self, ip_timestamp_tuples: List[Tuple[str, str]]) -> Dict[str, Dict[str, Any]]:
        results = {}
        unique_queries = {}
        for ip, ts in ip_timestamp_tuples:
            if ip and ip not in unique_queries:
                unique_queries[ip] = ts

        def _fetch(item):
            _ip, _ts = item
            return _ip, self.lookup_subscriber(_ip, _ts)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = executor.map(_fetch, unique_queries.items())
            for ip_res, sub_info in futures:
                if sub_info:
                    results[ip_res] = sub_info

        return results

radius_client = RadiusClient()
