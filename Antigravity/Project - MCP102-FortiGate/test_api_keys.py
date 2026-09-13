"""
===================================================================
FortiGate & AbuseIPDB API Key Validation Diagnostic (test_api_keys.py)
Tests live TLS connectivity and authentication for both APIs.
===================================================================
"""

import os
import sys
import requests
import urllib3
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

# Suppress self-signed SSL warnings for internal FortiGate IPs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load configuration from .env
load_dotenv(dotenv_path=".env")

console = Console()

def test_abuseipdb_key() -> dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")
    
    if not api_key or api_key.startswith("mock") or api_key == "your_actual_abuseipdb_api_key_here":
        return {
            "status": "MOCK_MODE",
            "message": "AbuseIPDB API key set to 'mock'. Local simulated threat intel active.",
            "sample_score": 100
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": api_key}
    params = {"ipAddress": "185.220.101.5", "maxAgeInDays": 90}

    try:
        res = requests.get(url, headers=headers, params=params, timeout=8)
        if res.status_code == 200:
            data = res.json().get("data", {})
            return {
                "status": "PASS (LIVE API 200 OK)",
                "abuse_score": f"{data.get('abuseConfidenceScore')}%",
                "isp": data.get("isp"),
                "country": data.get("countryCode")
            }
        elif res.status_code == 401:
            return {"status": "FAIL (401 Unauthorized)", "error": "Invalid AbuseIPDB API Key!"}
        else:
            return {"status": f"FAIL (HTTP {res.status_code})", "error": res.text}
    except Exception as e:
        return {"status": "FAIL (Connection Error)", "error": str(e)}

def test_fortigate_key() -> dict:
    fg_ip = os.getenv("FORTIGATE_IP", "mock")
    token = os.getenv("FORTIGATE_API_TOKEN", "mock_token")
    vdom = os.getenv("FORTIGATE_VDOM", "root")

    if not fg_ip or fg_ip == "mock":
        return {
            "status": "MOCK_MODE",
            "message": "FortiGate IP set to 'mock'. High-fidelity FortiOS REST API simulator active.",
            "hostname": "FG-300E-PRIMARY",
            "firmware": "v7.4.3 (GA.M)"
        }

    url = f"https://{fg_ip}/api/v2/cmdb/system/status?vdom={vdom}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    try:
        res = requests.get(url, headers=headers, verify=False, timeout=8)
        if res.status_code == 200:
            results = res.json().get("results", {})
            return {
                "status": "PASS (LIVE FORTIOS API 200 OK)",
                "hostname": results.get("hostname", "FortiGate"),
                "firmware": results.get("version", "v7.0+")
            }
        elif res.status_code == 401:
            return {"status": "FAIL (401 Unauthorized)", "error": "Invalid FortiGate Bearer Token!"}
        else:
            return {"status": f"FAIL (HTTP {res.status_code})", "error": res.text}
    except Exception as e:
        return {"status": "FAIL (Connection Error)", "error": str(e)}

if __name__ == "__main__":
    console.print("\n[bold cyan]🔌 FORTIGATE & ABUSEIPDB API KEY DIAGNOSTIC TESTER[/bold cyan]\n")
    abuse_res = test_abuseipdb_key()
    fg_res = test_fortigate_key()

    table = Table(title="🔌 Diagnostic Results", title_style="bold magenta")
    table.add_column("API Integration", style="cyan")
    table.add_column("Authentication Status", style="yellow")
    table.add_column("Details", style="white")

    table.add_row("AbuseIPDB API v2", abuse_res.get("status"), f"Score: {abuse_res.get('abuse_score', 'N/A')} | ISP: {abuse_res.get('isp', 'N/A')}")
    table.add_row("FortiGate FortiOS REST API", fg_res.get("status"), f"Host: {fg_res.get('hostname', 'N/A')} | Firmware: {fg_res.get('firmware', 'N/A')}")

    console.print(table)
    console.print("\n")