"""
Multi-Vendor Router Threat Shield Adapters
==========================================
Provides unified driver abstraction for network routing & firewall equipment:
- MikroTik RouterOS (v6 and v7 address-list management with timeout & custom lists)
- Juniper Junos (MX, SRX, QFX policy-options prefix-list / firewall filters)
- Extensible base for Cisco, Huawei, Linux iptables/nftables
"""

import os
import re
import time
import ipaddress
import logging
import subprocess
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Any, Optional
import paramiko

logger = logging.getLogger("router_adapters")

class BaseRouterAdapter(ABC):
    def __init__(self, router_id: str, name: str, ip: str, port: int = 22, 
                 user: str = "natlog", password: str = "", address_list: str = "scanner", 
                 supported_lists: Optional[List[str]] = None, role: str = "cgnat", **kwargs):
        self.router_id = router_id
        self.name = name
        self.ip = ip
        self.port = port
        self.user = user
        self.password = password
        self.address_list = address_list
        self.supported_lists = supported_lists or [address_list]
        self.role = role
        self.extra = kwargs

    @abstractmethod
    def test_connection(self) -> Tuple[bool, str, Dict[str, Any]]:
        """Test SSH connectivity and return (success, message, info_dict)."""
        pass

    @abstractmethod
    def get_address_list(self, list_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve all blacklisted/threat entries currently active on this router."""
        pass

    @abstractmethod
    def add_entry(self, address: str, comment: str, list_name: Optional[str] = None, timeout: Optional[str] = None) -> Tuple[bool, str]:
        """Add a single IP or CIDR subnet to the router blacklist."""
        pass

    @abstractmethod
    def add_entries_batch(self, entries: List[Dict[str, str]], list_name: Optional[str] = None) -> Tuple[int, List[str]]:
        """Add multiple entries in batch. Returns (added_count, log_messages)."""
        pass

    @abstractmethod
    def remove_entry(self, address: str, list_name: Optional[str] = None) -> Tuple[bool, str]:
        """Remove an IP or CIDR subnet from the router blacklist."""
        pass

    @abstractmethod
    def prune_redundant_entries(self, active_subnets: List[str], list_name: Optional[str] = None) -> Tuple[int, List[str]]:
        """Prune single host /32 IPs that are already covered by wider /24 subnets."""
        pass


# =========================================================================
# MIKROTIK ROUTEROS ADAPTER
# =========================================================================
class MikrotikAdapter(BaseRouterAdapter):
    def exec_cmd(self, cmd_str: str, timeout: int = 8) -> Tuple[str, str]:
        """Execute RouterOS command via SSH."""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.ip, port=self.port, username=self.user, password=self.password, timeout=timeout)
            stdin, stdout, stderr = ssh.exec_command(cmd_str, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            ssh.close()
            return out, err
        except Exception as pe:
            try:
                escaped = cmd_str.replace("'", "'\\''")
                full_cmd = f"sshpass -p '{self.password}' ssh -p {self.port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {self.user}@{self.ip} '{escaped}'"
                proc = subprocess.run(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
                return proc.stdout, proc.stderr
            except Exception as se:
                return "", f"MikroTik SSH Error ({self.ip}): {pe} / {se}"

    def test_connection(self) -> Tuple[bool, str, Dict[str, Any]]:
        out, err = self.exec_cmd(":put [/system identity get name]; :put [/system resource get version]")
        if out and not err:
            lines = [l.strip() for l in out.strip().split("\n") if l.strip()]
            identity = lines[0] if len(lines) > 0 else "MikroTik"
            version = lines[1] if len(lines) > 1 else "RouterOS"
            return True, f"Connected to {identity} ({version})", {"identity": identity, "version": version, "vendor": "mikrotik"}
        return False, f"Connection failed: {err or 'No response'}", {"vendor": "mikrotik"}

    def get_address_list(self, list_name: Optional[str] = None) -> List[Dict[str, Any]]:
        target_list = list_name or self.address_list
        cmd = f"/ip firewall address-list print detail without-paging where list={target_list}"
        out, err = self.exec_cmd(cmd)
        if not out:
            return []

        entries = []
        raw_items = out.split("\n\n") if "\n\n" in out else [out]
        for raw in raw_items:
            for line in raw.split("\n"):
                line = line.strip()
                if not line or "Flags:" in line:
                    continue
                addr_match = re.search(r'address=([0-9a-fA-F\.\:/]+)', line)
                if not addr_match:
                    addr_match = re.search(r'\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:/\d+)?)\s+', line)
                if not addr_match:
                    continue
                address = addr_match.group(1).strip()
                comment_match = re.search(r'comment="([^"]+)"', line)
                comment = comment_match.group(1) if comment_match else ""
                creation_match = re.search(r'creation-time=([^\s]+)', line)
                creation_time = creation_match.group(1) if creation_match else ""
                timeout_match = re.search(r'timeout=([^\s]+)', line)
                timeout_val = timeout_match.group(1) if timeout_match else ""

                entries.append({
                    "router_id": self.router_id,
                    "router_ip": self.ip,
                    "address": address,
                    "comment": comment,
                    "list": target_list,
                    "creation_time": creation_time,
                    "timeout": timeout_val,
                    "vendor": "mikrotik"
                })
        return entries

    def add_entry(self, address: str, comment: str = "NAT-AI-Auto", list_name: Optional[str] = None, timeout: Optional[str] = None) -> Tuple[bool, str]:
        target_list = list_name or self.address_list
        safe_comment = comment.replace('"', '\\"').replace("'", "")
        timeout_clause = f" timeout={timeout.strip()}" if timeout and timeout.strip() and timeout.strip().lower() != "permanent" else ""
        cmd = f"/ip firewall address-list add list={target_list} address={address}{timeout_clause} comment=\"{safe_comment}\""
        out, err = self.exec_cmd(cmd)
        if "failure" in err.lower() or "already exists" in err.lower():
            return False, err.strip()
        dur_str = f" [TTL: {timeout}]" if timeout and timeout.strip() and timeout.strip().lower() != "permanent" else ""
        return True, f"Added {address} to MikroTik {self.name} (list: {target_list}{dur_str})"

    def add_entries_batch(self, entries: List[Dict[str, str]], list_name: Optional[str] = None) -> Tuple[int, List[str]]:
        if not entries:
            return 0, []
        target_list = list_name or self.address_list
        commands = []
        for e in entries:
            addr = e.get("address")
            cmt = e.get("comment", "NAT-AI-Auto").replace('"', '\\"').replace("'", "")
            tout = e.get("timeout")
            t_clause = f" timeout={tout.strip()}" if tout and tout.strip() and tout.strip().lower() != "permanent" else ""
            commands.append(f"/ip firewall address-list add list={target_list} address={addr}{t_clause} comment=\"{cmt}\"")
        
        batch_script = " ; ".join(commands)
        out, err = self.exec_cmd(batch_script, timeout=60)
        added_count = len(entries)
        return added_count, [f"Pushed {added_count} threat rules to {self.name} (list: {target_list})"]

    def remove_entry(self, address: str, list_name: Optional[str] = None) -> Tuple[bool, str]:
        target_list = list_name or self.address_list
        cmd = f"/ip firewall address-list remove [find list={target_list} address={address}]"
        out, err = self.exec_cmd(cmd)
        if err:
            return False, err.strip()
        return True, f"Removed {address} from MikroTik {self.name} (list: {target_list})"

    def prune_redundant_entries(self, active_subnets: List[str], list_name: Optional[str] = None) -> Tuple[int, List[str]]:
        if not active_subnets:
            return 0, []
        target_list = list_name or self.address_list
        
        sub_nets = []
        for s in active_subnets:
            try: sub_nets.append(ipaddress.ip_network(s.strip()))
            except: pass
            
        current = self.get_address_list(list_name=target_list)
        to_remove = []
        for item in current:
            addr = item.get("address", "")
            if "/" in addr and not addr.endswith("/32"):
                continue
            try:
                ip_obj = ipaddress.ip_address(addr.replace("/32", ""))
                if any(ip_obj in sn for sn in sub_nets):
                    to_remove.append(addr)
            except Exception:
                pass

        if not to_remove:
            return 0, []

        remove_cmds = [f"/ip firewall address-list remove [find list={target_list} address={a}]" for a in to_remove]
        self.exec_cmd(" ; ".join(remove_cmds), timeout=60)
        return len(to_remove), [f"Pruned {len(to_remove)} redundant host IPs covered by subnets on {self.name} (list: {target_list})"]


# =========================================================================
# JUNIPER JUNOS ADAPTER (MX, SRX, QFX, EX)
# =========================================================================
class JuniperAdapter(BaseRouterAdapter):
    """
    Manages Junos prefix-lists (e.g. policy-options prefix-list THREAT-SHIELD-PREFIXES).
    Uses transactional CLI configuration with atomic commits.
    """
    def exec_cli_commands(self, commands: List[str], timeout: int = 10) -> Tuple[str, str]:
        """Execute Junos CLI commands via SSH channel."""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.ip, port=self.port, username=self.user, password=self.password, timeout=timeout)
            
            chan = ssh.invoke_shell()
            chan.settimeout(timeout)
            
            full_input = "set cli screen-length 0\n"
            for cmd in commands:
                full_input += f"{cmd}\n"
            full_input += "exit\n"
            
            chan.send(full_input)
            
            output = ""
            start_time = time.time()
            while time.time() - start_time < timeout:
                if chan.recv_ready():
                    chunk = chan.recv(8192).decode("utf-8", errors="replace")
                    output += chunk
                    if "exit" in chunk and chan.exit_status_ready():
                        break
                elif chan.closed or (output and output.strip().endswith("%") or output.strip().endswith(">")):
                    break
                time.sleep(0.2)
                
            ssh.close()
            return output, ""
        except Exception as e:
            return "", f"Juniper SSH Error ({self.ip}): {e}"

    def test_connection(self) -> Tuple[bool, str, Dict[str, Any]]:
        out, err = self.exec_cli_commands(["show version", "show system uptime"])
        if out and "JUNOS" in out.upper():
            version_match = re.search(r'Junos:\s*([^\s\n]+)', out, re.IGNORECASE)
            model_match = re.search(r'Model:\s*([^\s\n]+)', out, re.IGNORECASE)
            hostname_match = re.search(r'Hostname:\s*([^\s\n]+)', out, re.IGNORECASE)
            
            version = version_match.group(1) if version_match else "Junos OS"
            model = model_match.group(1) if model_match else "Juniper Router"
            hostname = hostname_match.group(1) if hostname_match else self.name
            
            return True, f"Connected to Juniper {hostname} ({model} - {version})", {
                "identity": hostname,
                "model": model,
                "version": version,
                "vendor": "juniper"
            }
        return False, f"Juniper connection failed: {err or out or 'No Junos signature detected'}", {"vendor": "juniper"}

    def get_address_list(self, list_name: Optional[str] = None) -> List[Dict[str, Any]]:
        target_list = list_name or self.address_list
        cmd = f"show configuration policy-options prefix-list {target_list} | display set"
        out, err = self.exec_cli_commands([cmd])
        if not out:
            return []

        entries = []
        for line in out.split("\n"):
            line = line.strip()
            if f"prefix-list {target_list}" in line and line.startswith("set"):
                parts = line.split()
                if len(parts) >= 5:
                    address = parts[4].strip()
                    entries.append({
                        "router_id": self.router_id,
                        "router_ip": self.ip,
                        "address": address,
                        "comment": "Junos Prefix-List Policy",
                        "list": target_list,
                        "creation_time": "Junos Committed",
                        "vendor": "juniper"
                    })
        return entries

    def add_entry(self, address: str, comment: str = "NAT-AI-Threat", list_name: Optional[str] = None, timeout: Optional[str] = None) -> Tuple[bool, str]:
        target_list = list_name or self.address_list
        formatted_addr = address if "/" in address else f"{address}/32"
        safe_comment = comment.replace('"', '').replace("'", "")[:40]
        commands = [
            "configure",
            f"set policy-options prefix-list {target_list} {formatted_addr}",
            f"commit comment \"NAT-AI Threat: {formatted_addr} ({safe_comment})\" and-quit"
        ]
        out, err = self.exec_cli_commands(commands)
        if "commit complete" in out.lower():
            return True, f"Added {formatted_addr} to Juniper {self.name} (prefix-list: '{target_list}')"
        return False, f"Junos commit failed: {out}"

    def add_entries_batch(self, entries: List[Dict[str, str]], list_name: Optional[str] = None) -> Tuple[int, List[str]]:
        if not entries:
            return 0, []
        target_list = list_name or self.address_list
        commands = ["configure"]
        for e in entries:
            addr = e.get("address", "")
            formatted_addr = addr if "/" in addr else f"{addr}/32"
            commands.append(f"set policy-options prefix-list {target_list} {formatted_addr}")
        commands.append("commit comment \"NAT-AI Batch Threat Sync\" and-quit")

        out, err = self.exec_cli_commands(commands, timeout=60)
        if "commit complete" in out.lower():
            return len(entries), [f"Committed {len(entries)} threat prefixes to Juniper {self.name} (prefix-list: '{target_list}')"]
        return 0, [f"Failed to commit batch to Juniper {self.name}: {out[:200]}"]

    def remove_entry(self, address: str, list_name: Optional[str] = None) -> Tuple[bool, str]:
        target_list = list_name or self.address_list
        formatted_addr = address if "/" in address else f"{address}/32"
        commands = [
            "configure",
            f"delete policy-options prefix-list {target_list} {formatted_addr}",
            f"commit comment \"NAT-AI Unblock: {formatted_addr}\" and-quit"
        ]
        out, err = self.exec_cli_commands(commands)
        if "commit complete" in out.lower():
            return True, f"Removed {formatted_addr} from Juniper {self.name} (prefix-list: '{target_list}')"
        return False, f"Junos commit failed: {out}"

    def prune_redundant_entries(self, active_subnets: List[str], list_name: Optional[str] = None) -> Tuple[int, List[str]]:
        if not active_subnets:
            return 0, []
        target_list = list_name or self.address_list

        sub_nets = []
        for s in active_subnets:
            try: sub_nets.append(ipaddress.ip_network(s.strip()))
            except: pass

        current = self.get_address_list(list_name=target_list)
        to_remove = []
        for item in current:
            addr = item.get("address", "")
            if "/" in addr and not addr.endswith("/32"):
                continue
            try:
                ip_obj = ipaddress.ip_address(addr.replace("/32", ""))
                if any(ip_obj in sn for sn in sub_nets):
                    to_remove.append(addr)
            except Exception:
                pass

        if not to_remove:
            return 0, []

        commands = ["configure"]
        for a in to_remove:
            commands.append(f"delete policy-options prefix-list {target_list} {a}")
        commands.append("commit comment \"NAT-AI Pruned redundant prefixes\" and-quit")

        out, err = self.exec_cli_commands(commands, timeout=60)
        return len(to_remove), [f"Pruned {len(to_remove)} redundant prefixes on Juniper {self.name} (prefix-list: '{target_list}')"]


# Factory for Router Adapters
def create_router_adapter(router_dict: Dict[str, Any]) -> BaseRouterAdapter:
    vendor = router_dict.get("vendor", "mikrotik").lower()
    if vendor == "juniper":
        return JuniperAdapter(**router_dict)
    else:
        return MikrotikAdapter(**router_dict)
