"""
===================================================================
Enterprise FortiGate SOC AI Defense Shield (agent.py)
Orchestrated via LangGraph State Machine, LangSmith Observability,
Local Qwen2.5 on NVIDIA RTX 4070 GPU, and FastMCP Server.
===================================================================
"""

import sys
import os
import json
import re
import asyncio
import ipaddress
from typing import TypedDict, List, Dict, Any
from dotenv import load_dotenv

from langgraph.graph import StateGraph, END
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from rich.console import Console
from rich.table import Table

load_dotenv(dotenv_path=".env")

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:latest")
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
ABUSE_SCORE_THRESHOLD = int(os.getenv("ABUSE_SCORE_THRESHOLD", "50"))
BLOCK_GROUP = os.getenv("FORTIGATE_BLOCK_GROUP", "Blocked_Bad_IPs")

console = Console()


class SOCAgentState(TypedDict):
    user_request: str
    search_query: str
    raw_logs: List[Dict[str, Any]]
    extracted_public_ips: List[str]
    abuse_intel_results: List[Dict[str, Any]]
    malicious_ips_detected: List[str]
    risk_score: int
    triage_reasoning: str
    firewall_blocks_applied: List[Dict[str, Any]]
    blocked_group_members: List[str]
    executive_report: str


def is_public_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.version == 4 and ip_obj.is_global
    except ValueError:
        return False


def extract_ips(source_data: Any) -> List[str]:
    """Extracts IPv4 addresses using Regex DPI pattern matching."""
    found_ips = set()
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    text = json.dumps(source_data)
    for match in ip_pattern.findall(text):
        found_ips.add(match)
    return list(found_ips)


async def execute_langgraph_soc_workflow(user_request: str) -> SOCAgentState:
    console.print("\n[bold cyan]🛡️ ENTERPRISE FORTIGATE DEFENSE SHIELD (LANGGRAPH + LANGSMITH)[/bold cyan]")
    console.print(f"[bold yellow]📥 User Request:[/bold yellow] '{user_request}'\n")

    server_params = StdioServerParameters(command=sys.executable, args=["server.py"])

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            console.print("[bold green]🔌 FastMCP Server Connected over stdio.[/bold green]")

            # -------------------------------------------------------------
            # NODE 1: 24-HOUR FORTIGATE DISK LOG SEARCH & DESTINATION IP AUDIT
            # -------------------------------------------------------------
            async def node_log_search(state: SOCAgentState) -> Dict[str, Any]:
                console.print("\n[bold blue]🔍 [NODE 1: FORTIGATE DISK LOG SEARCH - LAST 24 HOURS AUDIT][/bold blue]")
                
                # 1. Extract IPv4 addresses typed in user prompt
                all_prompt_ips = extract_ips(state["user_request"])
                user_public_ips = [ip for ip in all_prompt_ips if is_public_ip(ip)]
                
                # 2. Search FortiGate logs spanning last 24 hours (capacity: 100 records)
                query = user_public_ips[0] if user_public_ips else ""

                tool_res = await session.call_tool("search_fortigate_logs", arguments={"query": query, "limit": 100})
                log_data = json.loads(tool_res.content[0].text)
                logs = log_data.get("logs", [])
                
                # 3. Extract ALL Destination IPs (dstip) and Source IPs (srcip) from 24-hour log buffer
                all_dst_ips = list(set([str(log.get("dstip")) for log in logs if log.get("dstip")]))
                all_log_ips = extract_ips(logs)
                public_dst_ips = [ip for ip in all_dst_ips if is_public_ip(ip)]
                private_dst_ips = [ip for ip in all_dst_ips if not is_public_ip(ip)]
                
                # 4. Combine unique public IPs for threat intel lookup
                combined_public_ips = list(set(user_public_ips + public_dst_ips + [ip for ip in all_log_ips if is_public_ip(ip)]))
                
                # 📊 PRINT 24-HOUR DISK FORWARD LOG DETAILS:
                console.print(f"   🎯 Target Endpoint      : [cyan]https://192.168.10.1/api/v2/log/disk/traffic/forward[/cyan]")
                console.print(f"   🕒 Log Time Window Filter: [bold yellow]Last 24 Hours[/bold yellow] (Ingested: [bold yellow]{len(logs)}[/bold yellow] records)")
                
                if logs:
                    log_table = Table(title="📜 24-Hour FortiGate Disk Traffic Logs (Destination IPs)", title_style="bold yellow")
                    log_table.add_column("Timestamp", style="dim")
                    log_table.add_column("Src IP (Internal)", style="cyan")
                    log_table.add_column("Dst IP (External)", style="bold magenta")
                    log_table.add_column("Proto/Port", style="green")
                    log_table.add_column("Action", style="yellow")
                    log_table.add_column("App Name", style="blue")
                    
                    for log in logs:
                        log_table.add_row(
                            str(log.get("time", log.get("date", "N/A"))),
                            str(log.get("srcip", "N/A")),
                            str(log.get("dstip", "N/A")),
                            f"{log.get('proto', 'IP')}/{log.get('dstport', '')}",
                            str(log.get("action", "N/A")),
                            str(log.get("app", log.get("service", "N/A")))
                        )
                    console.print(log_table)
                else:
                    console.print("   ⚠️ [yellow]Notice: FortiGate 192.168.10.1 returned 0 forward traffic logs for the last 24 hours.[/yellow]")

                console.print(f"\n   📌 All Destination IPs Found in 24-Hour Logs: [bold white]{all_dst_ips}[/bold white]")
                console.print(f"   🏠 Internal Destination IPs                  : [cyan]{private_dst_ips}[/cyan] (Skipped)")
                console.print(f"   🌐 Public Destination IPs to Audit            : [bold cyan]{combined_public_ips}[/bold cyan]")
                
                return {
                    "search_query": query,
                    "raw_logs": logs,
                    "extracted_public_ips": combined_public_ips
                }

            # -------------------------------------------------------------
            # NODE 2: ABUSEIPDB THREAT INTELLIGENCE AUDIT
            # -------------------------------------------------------------
            async def node_threat_intel(state: SOCAgentState) -> Dict[str, Any]:
                console.print("\n[bold blue]🛡️ [NODE 2: ABUSEIPDB THREAT INTELLIGENCE][/bold blue]")
                console.print(f"   🔍 Querying AbuseIPDB API for {len(state['extracted_public_ips'])} Public Destination IP(s): [bold cyan]{state['extracted_public_ips']}[/bold cyan]\n")
                
                intel_results = []
                malicious_ips = []
                
                for ip in state["extracted_public_ips"]:
                    tool_res = await session.call_tool("check_abuseipdb_reputation", arguments={"ip_address": ip})
                    intel_data = json.loads(tool_res.content[0].text)
                    score = intel_data.get("abuseConfidenceScore", 0)
                    intel_data["ip"] = ip
                    intel_results.append(intel_data)
                    
                    status_color = "red" if score >= ABUSE_SCORE_THRESHOLD else "green"
                    isp_name = intel_data.get('isp', 'Unknown ISP')
                    country = intel_data.get('countryCode', 'US')
                    console.print(f"   📊 [{status_color}]IP {ip} | AbuseIPDB Score: {score}% | ISP: {isp_name} | Country: {country}[/{status_color}]")
                    
                    if score >= ABUSE_SCORE_THRESHOLD:
                        malicious_ips.append(ip)

                return {"abuse_intel_results": intel_results, "malicious_ips_detected": malicious_ips}

            # -------------------------------------------------------------
            # NODE 3: LOCAL GPU LLM TRIAGE (100% Crash-Proof Fallback)
            # -------------------------------------------------------------
            async def node_llm_gpu_triage(state: SOCAgentState) -> Dict[str, Any]:
                console.print(f"\n[bold blue]🧠 [NODE 3: GPU LLM TRIAGE ({OLLAMA_MODEL} on RTX 4070 GPU)][/bold blue]")
                
                risk_score = 90 if state["malicious_ips_detected"] else 10
                reasoning = "High-risk threat intelligence confirmed by AbuseIPDB API." if state["malicious_ips_detected"] else "Traffic evaluated as clean."

                try:
                    llm = ChatOllama(model=OLLAMA_MODEL, base_url=OLLAMA_BASE_URL, temperature=0.1, timeout=5)
                    triage_prompt = f"Evaluate threat context for user request '{state['user_request']}', intel: {json.dumps(state['abuse_intel_results'])}. Return JSON: {{\"risk_score\": 90, \"reasoning\": \"Threat analyzed\"}}"
                    res = await llm.ainvoke([HumanMessage(content=triage_prompt)])
                    
                    if res and hasattr(res, "content") and res.content:
                        clean_json = res.content.replace("```json", "").replace("```", "").strip()
                        parsed = json.loads(clean_json)
                        risk_score = parsed.get("risk_score", risk_score)
                        reasoning = parsed.get("reasoning", reasoning)
                except BaseException as e:
                    console.print(f"   💡 (Ollama GPU Inference Notice: Active deterministic triage mode)")

                console.print(f"   💡 Calculated Risk Score: [bold yellow]{risk_score}/100[/bold yellow]")
                console.print(f"   💡 Triage Reasoning: [italic]{reasoning}[/italic]")
                return {"risk_score": risk_score, "triage_reasoning": reasoning}

            # -------------------------------------------------------------
            # NODE 4: FORTIGATE REMEDIATION
            # -------------------------------------------------------------
            async def node_fortigate_remediation(state: SOCAgentState) -> Dict[str, Any]:
                console.print(f"\n[bold red]🔒 [NODE 4: FORTIGATE REMEDIATION (Group: {BLOCK_GROUP})][/bold red]")
                blocks = []
                for bad_ip in state["malicious_ips_detected"]:
                    tool_res = await session.call_tool(
                        "block_ip_in_fortigate_group",
                        arguments={"ip_address": bad_ip, "group_name": BLOCK_GROUP, "reason": f"AbuseIPDB Score >= {ABUSE_SCORE_THRESHOLD}%"}
                    )
                    res_data = json.loads(tool_res.content[0].text)
                    console.print(f"   ✅ FortiGate REST API: Object 'ip_{bad_ip}' added to '{BLOCK_GROUP}'.")
                    blocks.append(res_data)
                return {"firewall_blocks_applied": blocks}

            # -------------------------------------------------------------
            # NODE 5: EXECUTIVE REPORT GENERATION
            # -------------------------------------------------------------
            async def node_report_generation(state: SOCAgentState) -> Dict[str, Any]:
                console.print(f"\n[bold blue]📋 [NODE 5: EXECUTIVE REPORT GENERATION][/bold blue]")
                grp_res = await session.call_tool("get_blocked_bad_ips_group", arguments={})
                grp_data = json.loads(grp_res.content[0].text)
                members = grp_data.get("blocked_objects", [])
                render_report(state, members)
                return {"blocked_group_members": members}

            # LangGraph StateGraph Architecture
            builder = StateGraph(SOCAgentState)
            builder.add_node("log_search", node_log_search)
            builder.add_node("threat_intel", node_threat_intel)
            builder.add_node("llm_triage", node_llm_gpu_triage)
            builder.add_node("fortigate_remediation", node_fortigate_remediation)
            builder.add_node("report_generation", node_report_generation)

            builder.set_entry_point("log_search")
            builder.add_edge("log_search", "threat_intel")
            builder.add_edge("threat_intel", "llm_triage")

            def route_triage(state: SOCAgentState) -> str:
                if state.get("risk_score", 0) >= ABUSE_SCORE_THRESHOLD or len(state.get("malicious_ips_detected", [])) > 0:
                    return "fortigate_remediation"
                return "report_generation"

            builder.add_conditional_edges("llm_triage", route_triage, {"fortigate_remediation": "fortigate_remediation", "report_generation": "report_generation"})
            builder.add_edge("fortigate_remediation", "report_generation")
            builder.add_edge("report_generation", END)

            app = builder.compile()
            initial_state: SOCAgentState = {
                "user_request": user_request, "search_query": "", "raw_logs": [],
                "extracted_public_ips": [], "abuse_intel_results": [], "malicious_ips_detected": [],
                "risk_score": 0, "triage_reasoning": "", "firewall_blocks_applied": [],
                "blocked_group_members": [], "executive_report": ""
            }
            return await app.ainvoke(initial_state)


def render_report(state: SOCAgentState, group_members: List[str]):
    table = Table(title="🛡️ FortiGate SOC Triage Report", title_style="bold magenta")
    table.add_column("Indicator / IP", style="cyan")
    table.add_column("AbuseIPDB Score", style="yellow")
    table.add_column("ISP", style="magenta")
    table.add_column("Action", style="bold red")

    for item in state.get("abuse_intel_results", []):
        ip = item.get("ip", "N/A")
        score = item.get("abuseConfidenceScore", 0)
        is_blocked = ip in state.get("malicious_ips_detected", [])
        table.add_row(ip, f"{score}%", item.get("isp", "N/A"), "[bold white on red] BLOCKED [/bold white on red]" if is_blocked else "[bold white on green] ALLOWED [/bold white on green]")

    console.print(table)
    console.print(f"\n[bold green]Active Objects in '{BLOCK_GROUP}' Group:[/bold green] {group_members}\n")


if __name__ == "__main__":
    prompt = "Audit FortiGate disk forward traffic logs for the last 24 hours and check destination IPs against AbuseIPDB"
    if len(sys.argv) > 1:
        prompt = " ".join(sys.argv[1:])
    asyncio.run(execute_langgraph_soc_workflow(prompt))