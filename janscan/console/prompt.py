"""Main interactive prompt loop — msfconsole style."""

import sys
from rich.console import Console
from janscan.console.banner import print_banner
from janscan.console.commands import dispatch

console = Console()


class ConsolePrompt:
    def start(self):
        print_banner()

        while True:
            try:
                raw = console.input("\n[bold red]janscan[/bold red] [dim white]>[/dim white] ")
            except KeyboardInterrupt:
                console.print("\n[cyan]\\[*][/cyan] Use [bold]exit[/bold] to quit.")
                continue
            except EOFError:
                console.print("\n[dim]Goodbye.[/dim]")
                sys.exit(0)

            raw = raw.strip()
            if not raw:
                continue

            dispatch(raw)
