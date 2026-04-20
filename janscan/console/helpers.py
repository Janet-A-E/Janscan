"""Rich helper utilities for JanScan console output."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim white",
    "PASS": "green",
}


def print_info(msg: str):
    console.print(f"[cyan]\\[*][/cyan] {msg}")


def print_success(msg: str):
    console.print(f"[green]\\[+][/green] {msg}")


def print_warning(msg: str):
    console.print(f"[yellow]\\[!][/yellow] {msg}")


def print_error(msg: str):
    console.print(f"[red]\\[-][/red] {msg}")


def print_progress(msg: str):
    console.print(f"[blue]\\[~][/blue] {msg}")


def severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(severity.upper(), "white")


def print_table(title: str, columns: list, rows: list, **kwargs):
    table = Table(title=title, border_style="dim", **kwargs)
    for col in columns:
        if isinstance(col, dict):
            table.add_column(**col)
        else:
            table.add_column(col)
    for row in rows:
        table.add_row(*[str(c) for c in row])
    console.print(table)


def print_panel(title: str, content: str, style: str = "cyan"):
    console.print(Panel(content, title=title, border_style=style))
