"""Parallel module executor."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from janscan.modules.base import ModuleResult, Finding, Severity


def run_scan(modules: list, config: dict) -> list:
    results = []
    max_workers = config.get("general", {}).get("max_workers", 8)
    timeout = config.get("general", {}).get("scan_timeout", 30)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("[dim]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        transient=False,
    ) as progress:
        task = progress.add_task("Scanning...", total=len(modules))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(m.run): m for m in modules}
            for future in as_completed(futures):
                module = futures[future]
                try:
                    result = future.result(timeout=timeout)
                    results.append(result)
                except Exception as e:
                    results.append(ModuleResult(
                        module_name=module.name,
                        module_display_name=module.display_name,
                        findings=[Finding(
                            title=f"Module error: {module.name}",
                            description=str(e),
                            severity=Severity.INFO,
                            passed=False,
                            recommendation="Check module implementation for errors.",
                        )],
                        duration_seconds=0.0,
                        error=str(e),
                    ))
                progress.advance(task)
                progress.update(task, description=f"Scanning... [{module.display_name}]")

    return results
