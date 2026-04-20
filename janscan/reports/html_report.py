"""HTML report generator using Jinja2."""

from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader


def _sev_color(sev: str) -> str:
    return {
        "CRITICAL": "#ff2222",
        "HIGH": "#ff6644",
        "MEDIUM": "#ffb700",
        "LOW": "#44aaff",
        "INFO": "#888888",
        "PASS": "#00ff88",
    }.get(str(sev).upper(), "#aaaaaa")


def _finding_dict(f, module_name=""):
    if isinstance(f, dict):
        f["color"] = _sev_color(f.get("severity", "INFO"))
        return f
    return {
        "title": f.title,
        "description": f.description,
        "severity": str(f.severity.value) if hasattr(f.severity, "value") else str(f.severity),
        "passed": f.passed,
        "recommendation": f.recommendation,
        "raw_output": f.raw_output[:1000] if f.raw_output else "",
        "tags": f.tags,
        "module_name": module_name,
        "color": _sev_color(str(f.severity.value) if hasattr(f.severity, "value") else str(f.severity)),
    }


def write_html_report(scan_obj, findings, module_results, score, report_dir: Path, from_db=False):
    tmpl_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(tmpl_dir)), autoescape=True)
    template = env.get_template("report.html.j2")

    modules_out = []
    if from_db:
        by_module = {}
        for f in findings:
            mn = f.get("module_name", "unknown")
            by_module.setdefault(mn, []).append(_finding_dict(f))
        for mr in module_results:
            mn = mr.get("module_name", "unknown")
            modules_out.append({
                "module_name": mn,
                "display_name": mr.get("display_name", mn),
                "findings": by_module.get(mn, []),
            })
    else:
        for mr in module_results:
            modules_out.append({
                "module_name": mr.module_name,
                "display_name": mr.module_display_name,
                "findings": [_finding_dict(f, mr.module_name) for f in mr.findings],
            })

    grade_colors = {"A": "#00ff88", "B": "#44ffcc", "C": "#ffb700", "D": "#ff6644", "F": "#ff2222"}
    grade = scan_obj.get("grade", "F")

    top_issues = [f for f in (findings if from_db else [fd for mr in module_results for fd in mr.findings])
                  if (f.get("severity") if isinstance(f, dict) else str(f.severity.value)) in ("CRITICAL", "HIGH")
                  and not (f.get("passed") if isinstance(f, dict) else f.passed)]

    ctx = {
        "scan": scan_obj,
        "score": score.overall if hasattr(score, "overall") else score,
        "grade": grade,
        "grade_label": getattr(score, "grade_label", ""),
        "grade_color": grade_colors.get(grade, "#aaaaaa"),
        "modules": modules_out,
        "top_issues": [_finding_dict(f) if not isinstance(f, dict) else f for f in top_issues[:10]],
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_critical": scan_obj.get("total_critical", 0),
        "total_high": scan_obj.get("total_high", 0),
        "total_medium": scan_obj.get("total_medium", 0),
        "total_low": scan_obj.get("total_low", 0),
        "total_info": scan_obj.get("total_info", 0),
        "total_pass": scan_obj.get("total_pass", 0),
        "sev_color": _sev_color,
    }

    html = template.render(**ctx)
    (report_dir / "report.html").write_text(html)


def write_diff_html_report(diff: dict, report_dir: Path):
    tmpl_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(tmpl_dir)), autoescape=True)
    template = env.get_template("diff.html.j2")

    ctx = {
        "scan_a": diff["scan_a"],
        "scan_b": diff["scan_b"],
        "new": diff["new"],
        "resolved": diff["resolved"],
        "unchanged_count": diff["unchanged_count"],
        "score_delta": diff["score_delta"],
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sev_color": _sev_color,
    }

    html = template.render(**ctx)
    (report_dir / "diff.html").write_text(html)
