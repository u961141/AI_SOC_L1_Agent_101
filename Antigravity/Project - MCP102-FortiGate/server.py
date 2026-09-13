"""
===================================================================
FortiGate & AbuseIPDB FastMCP Protocol Server (server.py)
Exposes Cybersecurity Tools, Log Resources, and Prompts over stdio
===================================================================
"""

import json
from fastmcp import FastMCP
from fortigate_api import FortiGateAPIClient, AbuseIPDBClient, is_public_ip

mcp = FastMCP("FortiGate SOC Threat Triage Server")
fortigate_client = FortiGateAPIClient()
abuseipdb_client = AbuseIPDBClient()


# ===================================================================
# 1. MCP RESOURCES (@mcp.resource)
# ===================================================================
@mcp.resource("fortigate://logs/traffic")
def get_live_traffic_logs() -> str:
    """Returns recent FortiGate firewall traffic & security event logs."""
    logs = fortigate_client.search_traffic_logs(limit=25)
    return json.dumps(logs, indent=2)


@mcp.resource("fortigate://firewall/address-group/Blocked_Bad_IPs")
def get_blocked_ips_resource() -> str:
    """Returns members of Blocked_Bad_IPs group."""
    members = fortigate_client.get_address_group_members()
    return json.dumps({"members": members}, indent=2)


# ===================================================================
# 2. MCP PROMPTS (@mcp.prompt)
# ===================================================================
@mcp.prompt()
def get_soc_triage_prompt(user_request: str, intel_data: str) -> str:
    """Returns a standardized MCP prompt template for GPU LLM SOC threat triage."""
    return (
        f"You are an expert SOC Security Triage Analyst. Evaluate the following threat context:\n"
        f"User Request: '{user_request}'\n"
        f"Threat Intel Data: {intel_data}\n\n"
        f"Return ONLY a valid JSON object in this format:\n"
        f"{{\n"
        f'  "risk_score": <number 0-100>,\n'
        f'  "reasoning": "<concise explanation>"\n'
        f"}}\n"
    )


# ===================================================================
# 3. MCP TOOLS (@mcp.tool)
# ===================================================================
@mcp.tool()
def search_fortigate_logs(query: str = "", limit: int = 20) -> str:
    """Searches FortiGate firewall traffic logs for IP addresses or keywords."""
    logs = fortigate_client.search_traffic_logs(query=query, limit=limit)
    return json.dumps({"logs": logs}, indent=2)


@mcp.tool()
def check_abuseipdb_reputation(ip_address: str) -> str:
    """Queries AbuseIPDB API v2 for abuse score, ISP, and country for a public IP."""
    res = abuseipdb_client.check_ip(ip_address)
    return json.dumps(res, indent=2)


@mcp.tool()
def block_ip_in_fortigate_group(ip_address: str, group_name: str = "Blocked_Bad_IPs", reason: str = "") -> str:
    """Creates FortiGate Address Object (ip_<IP>) and adds to Blocked_Bad_IPs group."""
    if not is_public_ip(ip_address):
        return json.dumps({"status": "REJECTED", "reason": "Private RFC1918 IP address. Skipped."})
    
    res = fortigate_client.add_ip_to_block_group(ip_address=ip_address, group_name=group_name, reason=reason)
    return json.dumps(res, indent=2)


@mcp.tool()
def get_blocked_bad_ips_group() -> str:
    """Lists all blocked address objects inside FortiGate Blocked_Bad_IPs group."""
    members = fortigate_client.get_address_group_members()
    return json.dumps({"blocked_objects": members}, indent=2)


if __name__ == "__main__":
    mcp.run()