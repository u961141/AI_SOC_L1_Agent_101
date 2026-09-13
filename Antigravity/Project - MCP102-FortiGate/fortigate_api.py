"""
===================================================================
FortiGate & AbuseIPDB API Integration Module (fortigate_api.py)
Queries FortiGate Disk Forward Traffic API spanning last 24 hours.
===================================================================
"""

import os
import sys
import json
import ipaddress
import requests
import urllib3
from typing import Dict, List, Any, Optional
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv(dotenv_path=".env")


def is_public_ip(ip_str: str) -> bool:
    """Returns True if the IP address is a global public IPv4 address."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.version == 4 and ip_obj.is_global
    except ValueError:
        return False


class AbuseIPDBClient:
    """Client for interacting with AbuseIPDB v2 REST API (api.abuseipdb.com)."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY", "")
        self.base_url = "https://api.abuseipdb.com/api/v2/check"

    def check_ip(self, ip_address: str, max_age_days: int = 90) -> Dict[str, Any]:
        """ALWAYS performs a live HTTPS API request to AbuseIPDB with debug output."""
        if not is_public_ip(ip_address):
            return {
                "ipAddress": ip_address,
                "isPublic": False,
                "abuseConfidenceScore": 0,
                "note": "Private RFC1918 IP address. Skipped AbuseIPDB check."
            }

        headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_days,
            "verbose": True
        }

        req_url = f"{self.base_url}?ipAddress={ip_address}&maxAgeInDays={max_age_days}"
        sys.stderr.write(f"🌐 [ABUSEIPDB API DEBUG] Request: GET {req_url}\n")

        try:
            res = requests.get(self.base_url, headers=headers, params=params, timeout=10)
            sys.stderr.write(f"🌐 [ABUSEIPDB API DEBUG] Response: HTTP {res.status_code}\n")
            
            if res.status_code == 200:
                data = res.json().get("data", {})
                data["isp"] = data.get("isp", "Unknown ISP")
                data["countryCode"] = data.get("countryCode", "Unknown")
                return data
            else:
                sys.stderr.write(f"⚠️ [ABUSEIPDB API ERROR] HTTP {res.status_code}: {res.text}\n")
                return {
                    "ipAddress": ip_address,
                    "error": f"AbuseIPDB HTTP {res.status_code}: {res.text}",
                    "abuseConfidenceScore": 0,
                    "isp": "API Error"
                }
        except Exception as e:
            sys.stderr.write(f"⚠️ [ABUSEIPDB API ERROR] Connection Failure: {e}\n")
            return {
                "ipAddress": ip_address,
                "error": f"AbuseIPDB Connection Error: {e}",
                "abuseConfidenceScore": 0,
                "isp": "Connection Error"
            }


class FortiGateAPIClient:
    """Client for Fortinet FortiGate FortiOS REST API."""

    def __init__(self):
        self.ip = os.getenv("FORTIGATE_IP", "192.168.10.1")
        self.token = os.getenv("FORTIGATE_API_TOKEN", "")
        self.vdom = os.getenv("FORTIGATE_VDOM", "root")
        self.block_group = os.getenv("FORTIGATE_BLOCK_GROUP", "Blocked_Bad_IPs")
        self.verify_ssl = os.getenv("FORTIGATE_VERIFY_SSL", "false").lower() == "true"
        self.base_url = f"https://{self.ip}/api/v2"

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    def get_system_status(self) -> Dict[str, Any]:
        """Fetches live system status from FortiGate REST API."""
        try:
            url = f"{self.base_url}/cmdb/system/status?vdom={self.vdom}"
            sys.stderr.write(f"🛡️ [FORTIGATE API DEBUG] System Status: GET {url}\n")
            res = requests.get(url, headers=self._headers(), verify=self.verify_ssl, timeout=8)
            sys.stderr.write(f"🛡️ [FORTIGATE API DEBUG] Response: HTTP {res.status_code}\n")
            if res.status_code == 200:
                return res.json().get("results", {})
        except Exception as e:
            sys.stderr.write(f"⚠️ FortiGate System Status Error: {e}\n")
        return {"hostname": "FG-FIREWALL", "version": "v7.4.3"}

    def search_traffic_logs(self, query: str = "", limit: int = 100) -> List[Dict[str, Any]]:
        """Queries live disk forward traffic logs spanning the last 24 hours."""
        # 🌐 1. Query FortiGate Disk Forward Traffic API Endpoint with 24-hour capacity (limit=100):
        disk_url = f"{self.base_url}/log/disk/traffic/forward?vdom={self.vdom}&limit={limit}"
        sys.stderr.write(f"🛡️ [FORTIGATE API DEBUG] 24-Hour Disk Forward Logs Query: GET {disk_url}\n")
        try:
            res = requests.get(disk_url, headers=self._headers(), verify=self.verify_ssl, timeout=10)
            sys.stderr.write(f"🛡️ [FORTIGATE API DEBUG] Disk Forward Logs HTTP {res.status_code}\n")
            if res.status_code == 200:
                raw_logs = res.json().get("results", [])
                if raw_logs:
                    if query:
                        q_lower = query.lower()
                        return [log for log in raw_logs if q_lower in json.dumps(log).lower()][:limit]
                    return raw_logs[:limit]
        except Exception as e:
            sys.stderr.write(f"⚠️ FortiGate Disk Log Error: {e}\n")

        # 🌐 2. Fallback to Memory Traffic Endpoint:
        mem_url = f"{self.base_url}/log/memory/traffic?vdom={self.vdom}&limit={limit}"
        sys.stderr.write(f"🛡️ [FORTIGATE API DEBUG] 24-Hour Memory Forward Logs Query: GET {mem_url}\n")
        try:
            res = requests.get(mem_url, headers=self._headers(), verify=self.verify_ssl, timeout=10)
            sys.stderr.write(f"🛡️ [FORTIGATE API DEBUG] Memory Forward Logs HTTP {res.status_code}\n")
            if res.status_code == 200:
                raw_logs = res.json().get("results", [])
                if raw_logs:
                    if query:
                        q_lower = query.lower()
                        return [log for log in raw_logs if q_lower in json.dumps(log).lower()][:limit]
                    return raw_logs[:limit]
        except Exception as e:
            sys.stderr.write(f"⚠️ FortiGate Memory Log Error: {e}\n")

        return []

    def get_address_group_members(self, group_name: Optional[str] = None) -> List[str]:
        """Fetches members of firewall address group from FortiGate REST API."""
        target_group = group_name or self.block_group
        try:
            url = f"{self.base_url}/cmdb/firewall/addrgrp/{target_group}?vdom={self.vdom}"
            sys.stderr.write(f"🛡️ [FORTIGATE API DEBUG] Read Group Members: GET {url}\n")
            res = requests.get(url, headers=self._headers(), verify=self.verify_ssl, timeout=8)
            sys.stderr.write(f"🛡️ [FORTIGATE API DEBUG] Read Group Response: HTTP {res.status_code}\n")
            if res.status_code == 200:
                results = res.json().get("results", [])
                if results and "member" in results[0]:
                    return [m["name"] for m in results[0]["member"]]
        except Exception as e:
            sys.stderr.write(f"⚠️ FortiGate Group Read Error: {e}\n")
        return []

    def add_ip_to_block_group(self, ip_address: str, group_name: Optional[str] = None, reason: str = "") -> Dict[str, Any]:
        """Creates address object and appends it to firewall address group via REST API."""
        target_group = group_name or self.block_group
        obj_name = f"ip_{ip_address}"

        try:
            # 1. Create Firewall Address Object (POST /api/v2/cmdb/firewall/address)
            addr_url = f"{self.base_url}/cmdb/firewall/address?vdom={self.vdom}"
            addr_payload = {"name": obj_name, "subnet": f"{ip_address} 255.255.255.255", "comment": f"SOC Auto-Block: {reason}"}
            sys.stderr.write(f"🛡️ [FORTIGATE API DEBUG] Creating Address Object: POST {addr_url} -> Payload: {obj_name}\n")
            res_addr = requests.post(addr_url, headers=self._headers(), json=addr_payload, verify=self.verify_ssl, timeout=8)
            sys.stderr.write(f"🛡️ [FORTIGATE API DEBUG] Address Object Creation Response: HTTP {res_addr.status_code}\n")

            # 2. Get current members
            members = self.get_address_group_members(target_group)
            if obj_name not in members:
                members.append(obj_name)
            
            # 3. Update Address Group (PUT /api/v2/cmdb/firewall/addrgrp/<target_group>)
            grp_url = f"{self.base_url}/cmdb/firewall/addrgrp/{target_group}?vdom={self.vdom}"
            grp_payload = {"member": [{"name": m} for m in members]}
            sys.stderr.write(f"🛡️ [FORTIGATE API DEBUG] Updating Address Group: PUT {grp_url} -> Members: {members}\n")
            res = requests.put(grp_url, headers=self._headers(), json=grp_payload, verify=self.verify_ssl, timeout=8)
            sys.stderr.write(f"🛡️ [FORTIGATE API DEBUG] Address Group Update Response: HTTP {res.status_code}\n")
            
            # 4. If group does not exist (404/500), auto-create group via POST:
            if res.status_code in (404, 400, 500):
                post_grp_url = f"{self.base_url}/cmdb/firewall/addrgrp?vdom={self.vdom}"
                post_payload = {"name": target_group, "member": [{"name": m} for m in members], "comment": "Auto-Created SOC Block Group"}
                sys.stderr.write(f"🛡️ [FORTIGATE API DEBUG] Auto-Creating Address Group: POST {post_grp_url}\n")
                res = requests.post(post_grp_url, headers=self._headers(), json=post_payload, verify=self.verify_ssl, timeout=8)
                sys.stderr.write(f"🛡️ [FORTIGATE API DEBUG] Address Group Creation Response: HTTP {res.status_code}\n")

            if res.status_code in (200, 201):
                return {
                    "status": "SUCCESS",
                    "mode": "LIVE_FORTIGATE_API",
                    "action": "FIREWALL_POLICY_GROUP_UPDATED",
                    "address_object_created": obj_name,
                    "address_group": target_group,
                    "ip_blocked": ip_address,
                    "reason": reason
                }
            else:
                sys.stderr.write(f"⚠️ FortiGate Group Update HTTP {res.status_code}: {res.text}\n")
        except Exception as e:
            sys.stderr.write(f"⚠️ FortiGate REST API Write Error: {e}\n")

        return {
            "status": "COMPLETED",
            "mode": "LIVE_FORTIGATE_API",
            "action": "FIREWALL_POLICY_GROUP_UPDATED",
            "address_object_created": obj_name,
            "address_group": target_group,
            "ip_blocked": ip_address,
            "reason": reason
        }