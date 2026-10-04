import socket
import ipaddress
import requests
import logging
from typing import Tuple, Dict

logger = logging.getLogger("enricher")

KNOWN_SERVICES = [
    # Google / YouTube
    ("172.217.0.0/16", "Google / YouTube", "Cloud & Video", 15169),
    ("142.250.0.0/15", "Google / YouTube", "Cloud & Video", 15169),
    ("216.58.192.0/19", "Google / YouTube", "Cloud & Video", 15169),
    ("173.194.0.0/16", "Google / YouTube", "Cloud & Video", 15169),
    ("74.125.0.0/16", "Google / YouTube", "Cloud & Video", 15169),
    ("8.8.8.0/24", "Google Public DNS", "DNS", 15169),
    ("8.8.4.0/24", "Google Public DNS", "DNS", 15169),
    # Meta (Facebook / Instagram / WhatsApp)
    ("157.240.0.0/16", "Meta (Facebook/Instagram/WhatsApp)", "Social Media", 32934),
    ("31.13.64.0/18", "Meta (Facebook/Instagram/WhatsApp)", "Social Media", 32934),
    ("129.134.0.0/16", "Meta (Facebook/Instagram/WhatsApp)", "Social Media", 32934),
    ("185.89.216.0/22", "Meta (WhatsApp)", "Social Media", 32934),
    ("69.171.224.0/19", "Meta (Facebook)", "Social Media", 32934),
    # Cloudflare
    ("104.16.0.0/12", "Cloudflare CDN", "CDN & Security", 13335),
    ("172.64.0.0/13", "Cloudflare CDN", "CDN & Security", 13335),
    ("162.158.0.0/15", "Cloudflare CDN", "CDN & Security", 13335),
    ("1.1.1.0/24", "Cloudflare DNS", "DNS", 13335),
    ("1.0.0.0/24", "Cloudflare DNS", "DNS", 13335),
    # ByteDance / TikTok
    ("130.44.0.0/16", "ByteDance (TikTok)", "Social & Video", 138699),
    ("143.244.0.0/16", "ByteDance (TikTok)", "Social & Video", 138699),
    ("161.117.0.0/16", "ByteDance (TikTok)", "Social & Video", 138699),
    # Akamai
    ("23.0.0.0/12", "Akamai CDN", "CDN", 20940),
    ("184.24.0.0/13", "Akamai CDN", "CDN", 20940),
    ("104.64.0.0/10", "Akamai CDN", "CDN", 20940),
    ("2.16.0.0/13", "Akamai CDN", "CDN", 20940),
    ("184.84.0.0/14", "Akamai CDN", "CDN", 20940),
    # Microsoft & Azure
    ("20.0.0.0/10", "Microsoft Azure", "Cloud Services", 8075),
    ("40.74.0.0/15", "Microsoft Azure", "Cloud Services", 8075),
    ("52.96.0.0/12", "Microsoft Office365 / Azure", "Cloud Services", 8075),
    ("13.64.0.0/11", "Microsoft Azure", "Cloud Services", 8075),
    # Amazon AWS
    ("3.0.0.0/9", "Amazon AWS", "Cloud Infrastructure", 16509),
    ("52.0.0.0/11", "Amazon AWS", "Cloud Infrastructure", 16509),
    ("54.0.0.0/11", "Amazon AWS", "Cloud Infrastructure", 16509),
    ("18.0.0.0/9", "Amazon AWS", "Cloud Infrastructure", 16509),
    # Fastly
    ("151.101.0.0/16", "Fastly CDN", "CDN", 54113),
    ("199.232.0.0/16", "Fastly CDN", "CDN", 54113),
    # Apple
    ("17.0.0.0/8", "Apple Services", "Mobile & Cloud", 714),
    # Valve / Steam
    ("162.254.192.0/21", "Valve (Steam Gaming)", "Gaming", 32590),
    ("155.133.224.0/19", "Valve (Steam Gaming)", "Gaming", 32590),
    # Telegram
    ("149.154.160.0/20", "Telegram Messenger", "Messaging", 62041),
    ("91.108.4.0/22", "Telegram Messenger", "Messaging", 62041),
    ("91.108.56.0/22", "Telegram Messenger", "Messaging", 62041),
    # Netflix
    ("198.38.96.0/19", "Netflix Open Connect", "Streaming Video", 2906),
    ("198.45.48.0/20", "Netflix Open Connect", "Streaming Video", 2906),
]

_NETWORK_CACHE = []
for cidr, org, cat, asn in KNOWN_SERVICES:
    _NETWORK_CACHE.append((ipaddress.ip_network(cidr), org, cat, asn))

class DestinationEnricher:
    def __init__(self, ch_client):
        self.ch = ch_client
        self.memory_cache: Dict[str, Tuple[str, str, int]] = {}
        self._load_cache_from_db()

    def _load_cache_from_db(self):
        try:
            res = self.ch.query("SELECT ip, org_name, category, asn_number FROM nat_logs.destination_intel")
            for row in res.result_rows:
                ip_str = str(row[0])
                self.memory_cache[ip_str] = (row[1], row[2], row[3])
            logger.info(f"Loaded {len(self.memory_cache)} cached IP intelligence records from ClickHouse.")
        except Exception as e:
            logger.warning(f"Could not load cache from DB: {e}")

    def classify_ip(self, ip_str: str) -> Tuple[str, str, int]:
        if ip_str in self.memory_cache:
            return self.memory_cache[ip_str]

        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private:
                return ("Private / CGNAT Subnet", "Internal", 0)

            # 1. Match known high-volume CIDRs
            for net, org, cat, asn in _NETWORK_CACHE:
                if ip_obj in net:
                    self.memory_cache[ip_str] = (org, cat, asn)
                    self._save_to_db(ip_str, org, cat, asn)
                    return (org, cat, asn)

            # 2. Reverse DNS lookup
            try:
                hostname, _, _ = socket.gethostbyaddr(ip_str)
                org = hostname
                cat = "Web / Service"
                asn = 0
                if "1e100.net" in hostname or "google" in hostname:
                    org, cat, asn = "Google / YouTube", "Cloud & Video", 15169
                elif "fbcdn" in hostname or "facebook" in hostname or "meta" in hostname:
                    org, cat, asn = "Meta Platforms", "Social Media", 32934
                elif "cloudflare" in hostname or "cf-" in hostname:
                    org, cat, asn = "Cloudflare CDN", "CDN & Security", 13335
                elif "akamaitechnologies" in hostname or "deploy.static.akamaitechnologies" in hostname:
                    org, cat, asn = "Akamai CDN", "CDN", 20940
                elif "awsglobalaccelerator" in hostname or "compute.amazonaws.com" in hostname:
                    org, cat, asn = "Amazon AWS", "Cloud Infrastructure", 16509
                
                self.memory_cache[ip_str] = (org, cat, asn)
                self._save_to_db(ip_str, org, cat, asn)
                return (org, cat, asn)
            except Exception:
                pass

            # 3. Fallback: Public IP-API query (throttled)
            try:
                resp = requests.get(f"http://ip-api.com/json/{ip_str}?fields=org,as,asname", timeout=1.5)
                if resp.status_code == 200:
                    data = resp.json()
                    org = data.get("asname") or data.get("org") or "Public Internet"
                    asn_str = data.get("as", "")
                    asn = int(asn_str.split()[0].replace("AS", "")) if "AS" in asn_str else 0
                    cat = "Internet Host"
                    self.memory_cache[ip_str] = (org, cat, asn)
                    self._save_to_db(ip_str, org, cat, asn)
                    return (org, cat, asn)
            except Exception:
                pass

            org, cat, asn = ("External IP", "Internet Host", 0)
            self.memory_cache[ip_str] = (org, cat, asn)
            return (org, cat, asn)

        except Exception as e:
            return ("Unknown Host", "Unclassified", 0)

    def _save_to_db(self, ip_str: str, org: str, cat: str, asn: int):
        try:
            safe_org = org.replace("'", "")
            sql = f"INSERT INTO nat_logs.destination_intel (ip, asn_number, org_name, category) VALUES ('{ip_str}', {asn}, '{safe_org}', '{cat}')"
            self.ch.command(sql)
        except Exception:
            pass

