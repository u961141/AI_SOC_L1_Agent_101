"""
===================================================================
Interactive LLM SOC Analyst Command Shell (interactive_soc_shell.py)
===================================================================
"""

import sys
import os
import asyncio
from dotenv import load_dotenv
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel

# Import LangGraph State Machine Workflow Engine from agent.py
from agent import execute_langgraph_soc_workflow, BLOCK_GROUP, OLLAMA_MODEL

# Load Environment Configuration
load_dotenv(dotenv_path=".env")

console = Console()


def display_welcome_banner():
    """Displays the Masterclass SOC Analyst Terminal Banner."""
    banner_text = f"""
[bold cyan]🛡️ ENTERPRISE FORTIGATE DEFENSE SHIELD - SOC ANALYST SHELL[/bold cyan]
• Local GPU LLM Engine : [bold yellow]{OLLAMA_MODEL}[/bold yellow] (NVIDIA RTX 4070 GPU)
• Protocol Gateway      : [bold green]FastMCP Server over stdio[/bold green]
• State Machine Engine  : [bold magenta]LangGraph StateGraph[/bold magenta]
• Target Firewall Group : [bold red]{BLOCK_GROUP}[/bold red]
• Observability Cloud   : [bold blue]LangSmith Telemetry Tracing[/bold blue]

[dim]Type your natural language security request below (or type 'exit' / 'quit' to close).[/dim]
"""
    console.print(Panel(banner_text, border_style="bright_blue"))


async def main_interactive_loop():
    """Continuous REPL (Read-Eval-Print Loop) for SOC Analysts."""
    display_welcome_banner()

    console.print("[bold yellow]💡 Sample Prompts You Can Try:[/bold yellow]")
    console.print("  1. [italic]'Investigate traffic from host 10.0.1.50 over the last hour, check external IPs on AbuseIPDB API, and block malicious IPs in Blocked_Bad_IPs'[/italic]")
    console.print("  2. [italic]'Audit inbound SSH traffic on port3_dmz interface, check external source IPs with AbuseIPDB, and add threats to firewall group'[/italic]\n")

    while True:
        try:
            user_input = Prompt.ask("\n[bold cyan]💬 Enter SOC Analyst Query[/bold cyan]")
            
            if user_input.strip().lower() in ["exit", "quit", "q", "0"]:
                console.print("\n[bold red]🚪 Exiting FortiGate SOC Defense Shield. Stay secure![/bold red]\n")
                break

            if not user_input.strip():
                continue

            await execute_langgraph_soc_workflow(user_input)

        except KeyboardInterrupt:
            console.print("\n\n[bold red]⚠️ Session interrupted by user. Exiting...[/bold red]")
            break
        except Exception as e:
            console.print(f"\n[bold red]❌ Error executing workflow:[/bold red] {e}")


if __name__ == "__main__":
    asyncio.run(main_interactive_loop())