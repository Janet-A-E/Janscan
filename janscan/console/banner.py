"""JanScan ASCII banner."""

import os
import socket
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from janscan import __version__, IS_ROOT

console = Console()

BANNER = r"""
     ██╗ █████╗ ███╗  ██╗███████╗ ██████╗ █████╗ ███╗  ██╗
     ██║██╔══██╗████╗ ██║██╔════╝██╔════╝██╔══██╗████╗ ██║
     ██║███████║██╔██╗██║███████╗██║     ███████║██╔██╗██║
██   ██║██╔══██║██║╚████║╚════██║██║     ██╔══██║██║╚████║
╚█████╔╝██║  ██║██║ ╚███║███████║╚██████╗██║  ██║██║ ╚███║
 ╚════╝ ╚═╝  ╚═╝╚═╝  ╚══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝
"""


def print_banner():
    console.print(Text(BANNER, style="bold red"))

    try:
        user = os.getlogin()
    except Exception:
        user = os.environ.get("USER", "unknown")

    root_status = (
        "[green]Running as root — full audit enabled[/green]"
        if IS_ROOT
        else "[yellow]NOT ROOT — some checks will be skipped (run with sudo for full audit)[/yellow]"
    )

    info = (
        f"[bold cyan]Version:[/bold cyan]  {__version__}\n"
        f"[bold cyan]Host:[/bold cyan]     {socket.gethostname()}\n"
        f"[bold cyan]User:[/bold cyan]     {user}\n"
        f"[bold cyan]Status:[/bold cyan]   {root_status}\n"
        f"[bold cyan]DB:[/bold cyan]       ~/.janscan/data/scans.db\n"
        f"[bold cyan]Reports:[/bold cyan]  ~/.janscan/reports/\n"
        f"[dim]Type [bold]help[/bold] to see available commands.[/dim]"
    )

    console.print(Panel(info, title="[bold red]JanScan — Linux Security Audit[/bold red]", border_style="red"))
