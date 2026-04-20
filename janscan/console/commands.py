"""Command dispatcher for JanScan console."""

import sys
import shlex
import webbrowser
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from janscan.console.helpers import (
    print_info, print_success, print_warning, print_error, print_progress,
    severity_color, console
)

_console = Console()

HELP_TEXT = {
    "scan": (
        "Run a security audit of the local system.\n\n"
        "  scan                        Run all modules\n"
        "  scan --modules m1,m2        Run specific modules only\n"
        "  scan --output /path         Save reports to custom path\n"
        "  scan --no-report            Skip report generation\n"
        "  scan --quiet                Minimal output\n"
    ),
    "report": (
        "Generate or regenerate reports from scan data.\n\n"
        "  report                      Report from last scan\n"
        "  report --id 42              Report from scan ID 42\n"
        "  report --uuid abc123        Report from scan UUID\n"
        "  report --format html        Only generate HTML\n"
        "  report --open               Open HTML in browser after generating\n"
    ),
    "history": (
        "List past scans stored in the database.\n\n"
        "  history                     Show last 20 scans\n"
        "  history --limit 10          Show last N scans\n"
        "  history --full              Show all scans\n"
    ),
    "diff": (
        "Compare two scans.\n\n"
        "  diff 41 42                  Compare scan IDs 41 and 42\n"
        "  diff --uuid abc def         Compare by UUID\n"
        "  diff 41 42 --format html    Also generate HTML diff report\n"
    ),
    "modules": (
        "List all available audit modules.\n\n"
        "  modules                     Show module list\n"
        "  modules --verbose           Show module descriptions\n"
    ),
    "config": (
        "View or edit JanScan configuration.\n\n"
        "  config                      Show current config\n"
        "  config --edit               Open config in $EDITOR\n"
        "  config --reset              Restore defaults\n"
    ),
    "export": (
        "Export a report in a specific format.\n\n"
        "  export --format json        Export last scan as JSON\n"
        "  export --format pdf --id 42 Export scan 42 as PDF\n"
        "  export --output ~/audit.pdf Custom output path\n"
    ),
    "help": (
        "Show help information.\n\n"
        "  help                        Show command list\n"
        "  help <command>              Show detailed help for a command\n"
    ),
}

ALL_COMMANDS = list(HELP_TEXT.keys()) + ["exit", "quit"]


def parse_args(raw: str) -> tuple[str, dict]:
    """Parse a command line string into (command, args_dict)."""
    try:
        parts = shlex.split(raw.strip())
    except ValueError:
        parts = raw.strip().split()

    if not parts:
        return "", {}

    cmd = parts[0].lower()
    args = {}
    i = 1
    positional = []
    while i < len(parts):
        p = parts[i]
        if p.startswith("--"):
            key = p[2:]
            if i + 1 < len(parts) and not parts[i + 1].startswith("--"):
                args[key] = parts[i + 1]
                i += 2
            else:
                args[key] = True
                i += 1
        else:
            positional.append(p)
            i += 1
    if positional:
        args["_positional"] = positional
    return cmd, args


def handle_help(args: dict):
    topic = args.get("_positional", [None])[0]
    if topic and topic in HELP_TEXT:
        _console.print(f"\n[bold cyan]{topic}[/bold cyan]")
        _console.print(HELP_TEXT[topic])
        return

    table = Table(title="JanScan Commands", border_style="red", show_header=True)
    table.add_column("Command", style="bold cyan", width=12)
    table.add_column("Description")
    descs = {
        "scan":    "Run a full security audit of the system",
        "report":  "Generate/regenerate reports from a scan",
        "history": "List all past scans",
        "diff":    "Compare two scans (show new/resolved findings)",
        "modules": "List all available audit modules",
        "config":  "View or edit configuration",
        "export":  "Export a report in a specific format",
        "help":    "Show this help / help <command>",
        "exit":    "Exit JanScan",
    }
    for cmd, desc in descs.items():
        table.add_row(cmd, desc)
    _console.print(table)


def handle_scan(args: dict):
    from janscan.engine.loader import load_modules
    from janscan.engine.runner import run_scan
    from janscan.engine.scorer import calculate_score
    from janscan.storage.queries import save_scan, save_findings, save_module_results, get_latest_scan
    from janscan.reports.json_report import write_json_report
    from janscan.reports.html_report import write_html_report
    from janscan.reports.pdf_report import write_pdf_report
    from janscan.config.loader import load_config, REPORTS_DIR
    import uuid, socket
    from datetime import datetime

    cfg = load_config()
    only_modules = None
    if "modules" in args:
        only_modules = [m.strip() for m in args["modules"].split(",")]

    print_info("Loading audit modules...")
    all_modules = load_modules()

    if only_modules:
        all_modules = [m for m in all_modules if m.name in only_modules]
        if not all_modules:
            print_error(f"No modules matched: {only_modules}")
            return

    disabled = cfg.get("modules", {}).get("disabled", [])
    if disabled:
        all_modules = [m for m in all_modules if m.name not in disabled]

    print_info(f"Running [bold]{len(all_modules)}[/bold] modules...")

    scan_uuid = str(uuid.uuid4())
    started_at = datetime.now()

    results = run_scan(all_modules, cfg)

    finished_at = datetime.now()
    duration = (finished_at - started_at).total_seconds()

    all_findings = [f for r in results for f in r.findings]
    score = calculate_score(all_findings)

    # Save to DB
    scan_data = {
        "scan_uuid": scan_uuid,
        "hostname": socket.gethostname(),
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": duration,
        "overall_score": score.overall,
        "grade": score.grade,
        "total_critical": score.total_critical,
        "total_high": score.total_high,
        "total_medium": score.total_medium,
        "total_low": score.total_low,
        "total_info": score.total_info,
        "total_pass": score.total_pass,
    }
    scan_id = save_scan(scan_data)
    save_findings(scan_id, all_findings, results)
    save_module_results(scan_id, results)

    # Reports
    no_report = args.get("no-report", False)
    report_dir = None
    if not no_report:
        ts = started_at.strftime("%Y-%m-%d_%H-%M-%S")
        report_dir = REPORTS_DIR / f"{ts}_{scan_uuid[:8]}"
        report_dir.mkdir(parents=True, exist_ok=True)

        scan_obj = {**scan_data, "scan_id": scan_id, "grade_label": score.grade_label, "modules": results}
        write_json_report(scan_obj, all_findings, results, report_dir)
        write_html_report(scan_obj, all_findings, results, score, report_dir)
        write_pdf_report(scan_obj, all_findings, results, score, report_dir)

    # Print summary
    _print_scan_summary(score, results, all_findings, duration, socket.gethostname(), started_at, report_dir)


def _print_scan_summary(score, results, all_findings, duration, hostname, started_at, report_dir):
    from rich.panel import Panel
    from rich.table import Table

    grade_colors = {"A": "green", "B": "cyan", "C": "yellow", "D": "red", "F": "bold red"}
    gc = grade_colors.get(score.grade, "white")

    summary = (
        f"[bold]Host:[/bold]     {hostname}\n"
        f"[bold]Date:[/bold]     {started_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"[bold]Duration:[/bold] {duration:.1f}s\n"
        f"[bold]Score:[/bold]    [{gc}]{score.overall}/100[/{gc}]   "
        f"Grade: [{gc}]{score.grade} — {score.grade_label}[/{gc}]"
    )
    _console.print(Panel(summary, title="[bold red]SCAN COMPLETE[/bold red]", border_style="red"))

    # Severity bar table
    table = Table(title="Scan Summary", border_style="dim", show_header=False)
    table.add_column("Severity", width=10)
    table.add_column("Bar")
    table.add_column("Count", justify="right")

    counts = [
        ("CRITICAL", score.total_critical, "bold red"),
        ("HIGH", score.total_high, "red"),
        ("MEDIUM", score.total_medium, "yellow"),
        ("LOW", score.total_low, "cyan"),
        ("PASS", score.total_pass, "green"),
        ("INFO", score.total_info, "dim"),
    ]
    max_count = max((c for _, c, _ in counts), default=1) or 1
    for sev, count, color in counts:
        bar_len = int((count / max_count) * 30)
        bar = "█" * bar_len
        table.add_row(f"[{color}]{sev}[/{color}]", f"[{color}]{bar}[/{color}]", f"[{color}]{count}[/{color}]")
    _console.print(table)

    # Top critical/high findings
    top = [f for f in all_findings if f.severity in ("CRITICAL", "HIGH") and not f.passed][:5]
    if top:
        _console.print("\n[bold red]Top Critical/High Findings:[/bold red]")
        for f in top:
            col = severity_color(f.severity)
            _console.print(f"  [{col}][{f.severity}][/{col}] {f.title}")
            if f.recommendation:
                _console.print(f"         [dim]→ {f.recommendation}[/dim]")

    if report_dir:
        _console.print(f"\n[dim]Reports saved to: {report_dir}[/dim]")
        _console.print(f"  [dim]JSON: {report_dir}/report.json[/dim]")
        _console.print(f"  [dim]HTML: {report_dir}/report.html[/dim]")
        _console.print(f"  [dim]PDF:  {report_dir}/report.pdf[/dim]")


def handle_history(args: dict):
    from janscan.storage.queries import list_scans

    limit = int(args.get("limit", 20)) if not args.get("full") else 9999
    scans = list_scans(limit=limit)

    if not scans:
        print_info("No scans found. Run 'scan' to start.")
        return

    table = Table(title=f"Scan History ({len(scans)} records)", border_style="red")
    table.add_column("ID", justify="right", style="bold cyan", width=5)
    table.add_column("UUID", width=10)
    table.add_column("Date", width=20)
    table.add_column("Score", justify="center")
    table.add_column("Grade", justify="center")
    table.add_column("Critical", justify="right", style="red")
    table.add_column("High", justify="right", style="yellow")
    table.add_column("Duration", justify="right")

    grade_colors = {"A": "green", "B": "cyan", "C": "yellow", "D": "red", "F": "bold red"}
    for s in scans:
        gc = grade_colors.get(s.get("grade", "?"), "white")
        table.add_row(
            str(s["id"]),
            s.get("scan_uuid", "")[:8],
            s.get("started_at", "")[:19],
            f"[{gc}]{s.get('overall_score', '?')}[/{gc}]",
            f"[{gc}]{s.get('grade', '?')}[/{gc}]",
            str(s.get("total_critical", 0)),
            str(s.get("total_high", 0)),
            f"{s.get('duration_seconds', 0):.1f}s",
        )
    _console.print(table)


def handle_report(args: dict):
    from janscan.storage.queries import get_scan_by_id, get_latest_scan, get_findings_for_scan, get_module_results_for_scan
    from janscan.reports.json_report import write_json_report
    from janscan.reports.html_report import write_html_report
    from janscan.reports.pdf_report import write_pdf_report
    from janscan.engine.scorer import calculate_score, _findings_from_db
    from janscan.config.loader import REPORTS_DIR
    from datetime import datetime

    if "id" in args:
        scan = get_scan_by_id(int(args["id"]))
    else:
        scan = get_latest_scan()

    if not scan:
        print_error("No scan found.")
        return

    findings_db = get_findings_for_scan(scan["id"])
    module_results_db = get_module_results_for_scan(scan["id"])

    ts = scan.get("started_at", "")[:19].replace(":", "-").replace(" ", "_")
    report_dir = REPORTS_DIR / f"{ts}_{scan.get('scan_uuid','')[:8]}"
    report_dir.mkdir(parents=True, exist_ok=True)

    from janscan.engine.scorer import ScanScore
    score = ScanScore(
        overall=scan.get("overall_score", 0),
        grade=scan.get("grade", "F"),
        grade_label={"A": "Excellent", "B": "Good", "C": "Fair", "D": "Poor", "F": "Critical Risk"}.get(scan.get("grade", "F"), "Unknown"),
        total_critical=scan.get("total_critical", 0),
        total_high=scan.get("total_high", 0),
        total_medium=scan.get("total_medium", 0),
        total_low=scan.get("total_low", 0),
        total_info=scan.get("total_info", 0),
        total_pass=scan.get("total_pass", 0),
    )

    fmt = args.get("format", "all")
    if fmt in ("all", "json"):
        write_json_report(scan, findings_db, module_results_db, report_dir, from_db=True)
    if fmt in ("all", "html"):
        write_html_report(scan, findings_db, module_results_db, score, report_dir, from_db=True)
    if fmt in ("all", "pdf"):
        write_pdf_report(scan, findings_db, module_results_db, score, report_dir, from_db=True)

    print_success(f"Reports written to: {report_dir}")

    if args.get("open"):
        html = report_dir / "report.html"
        if html.exists():
            webbrowser.open(f"file://{html}")


def handle_diff(args: dict):
    from janscan.storage.queries import diff_scans, get_scan_by_id

    positional = args.get("_positional", [])
    if len(positional) < 2:
        print_error("Usage: diff <id_a> <id_b>")
        return

    try:
        id_a, id_b = int(positional[0]), int(positional[1])
    except ValueError:
        print_error("Scan IDs must be integers.")
        return

    diff = diff_scans(id_a, id_b)
    if "error" in diff:
        print_error(diff["error"])
        return

    scan_a = diff["scan_a"]
    scan_b = diff["scan_b"]
    print_info(f"Comparing scan #{id_a} ({scan_a.get('started_at','')[:10]}) → scan #{id_b} ({scan_b.get('started_at','')[:10]})")

    resolved = diff["resolved"]
    new = diff["new"]
    unchanged = diff["unchanged_count"]
    delta = diff["score_delta"]

    if resolved:
        _console.print(f"\n[green]\\[+] RESOLVED ({len(resolved)} findings fixed):[/green]")
        for f in resolved:
            _console.print(f"    [green]✓[/green] {f.get('module_name','')}: {f.get('title','')}")

    if new:
        _console.print(f"\n[red]\\[-] NEW ISSUES ({len(new)} new findings):[/red]")
        for f in new:
            sev = f.get("severity", "")
            col = severity_color(sev)
            _console.print(f"    [red]✗[/red] [{col}][{sev}][/{col}] {f.get('module_name','')}: {f.get('title','')}")

    _console.print(f"\n[dim]\\[~] UNCHANGED: {unchanged} findings[/dim]")

    delta_str = f"+{delta}" if delta > 0 else str(delta)
    delta_color = "green" if delta > 0 else ("red" if delta < 0 else "white")
    _console.print(f"[*] Score: {scan_a.get('overall_score','?')} → {scan_b.get('overall_score','?')} ([{delta_color}]{delta_str} points[/{delta_color}])")

    if args.get("format") == "html":
        from janscan.reports.html_report import write_diff_html_report
        from janscan.config.loader import REPORTS_DIR
        report_dir = REPORTS_DIR / f"diff_{id_a}_vs_{id_b}"
        report_dir.mkdir(parents=True, exist_ok=True)
        write_diff_html_report(diff, report_dir)
        print_success(f"Diff report: {report_dir}/diff.html")


def handle_modules(args: dict):
    from janscan.engine.loader import load_modules

    mods = load_modules()
    table = Table(title="Available Modules", border_style="red")
    table.add_column("Name", style="bold cyan")
    table.add_column("Display Name")
    table.add_column("Root Required", justify="center")
    table.add_column("Description")

    for m in mods:
        root = "[red]Yes[/red]" if m.requires_root else "[green]No[/green]"
        table.add_row(m.name, m.display_name, root, m.description)
    _console.print(table)


def handle_config(args: dict):
    from janscan.config.loader import load_config, CONFIG_PATH, write_default_config
    import os, subprocess

    if args.get("reset"):
        write_default_config()
        print_success("Config reset to defaults.")
        return

    if args.get("edit"):
        editor = os.environ.get("EDITOR", "nano")
        try:
            subprocess.run([editor, str(CONFIG_PATH)])
        except Exception as e:
            print_error(f"Could not open editor: {e}")
        return

    cfg = load_config()
    _console.print_json(data=cfg)


def handle_export(args: dict):
    handle_report(args)


def dispatch(raw: str):
    cmd, args = parse_args(raw)
    if not cmd:
        return

    if cmd in ("exit", "quit"):
        _console.print("\n[dim]Goodbye.[/dim]")
        sys.exit(0)

    if "--help" in raw.split():
        args = {"_positional": [cmd]}
        handle_help(args)
        return

    handlers = {
        "scan": handle_scan,
        "report": handle_report,
        "history": handle_history,
        "diff": handle_diff,
        "modules": handle_modules,
        "config": handle_config,
        "export": handle_export,
        "help": handle_help,
    }

    if cmd in handlers:
        try:
            handlers[cmd](args)
        except KeyboardInterrupt:
            print_warning("Command interrupted.")
        except Exception as e:
            print_error(f"Command error: {e}")
            import traceback
            _console.print(f"[dim]{traceback.format_exc()}[/dim]")
    else:
        print_error(f"Unknown command: '{cmd}'. Type [bold]help[/bold] for commands.")
