"""JSON report generator."""

import json
from pathlib import Path
from datetime import datetime


def _finding_to_dict(f, module_name=""):
    if isinstance(f, dict):
        return f
    return {
        "title": f.title,
        "description": f.description,
        "severity": str(f.severity.value) if hasattr(f.severity, "value") else str(f.severity),
        "passed": f.passed,
        "recommendation": f.recommendation,
        "raw_output": f.raw_output[:500] if f.raw_output else "",
        "references": f.references,
        "tags": f.tags,
        "module_name": module_name,
    }


def write_json_report(scan_obj: dict, findings, module_results, report_dir: Path, from_db=False):
    modules_out = []

    if from_db:
        # findings and module_results are dicts from DB
        by_module = {}
        for f in findings:
            mn = f.get("module_name", "unknown")
            by_module.setdefault(mn, []).append(f)
        for mr in module_results:
            mn = mr.get("module_name", "unknown")
            modules_out.append({
                "module_name": mn,
                "display_name": mr.get("display_name", mn),
                "duration_seconds": mr.get("duration_seconds", 0),
                "findings": by_module.get(mn, []),
            })
    else:
        # module_results are ModuleResult objects
        for mr in module_results:
            modules_out.append({
                "module_name": mr.module_name,
                "display_name": mr.module_display_name,
                "duration_seconds": mr.duration_seconds,
                "findings": [_finding_to_dict(f, mr.module_name) for f in mr.findings],
            })

    data = {
        "scan_id": scan_obj.get("id") or scan_obj.get("scan_id"),
        "scan_uuid": scan_obj.get("scan_uuid"),
        "hostname": scan_obj.get("hostname"),
        "started_at": scan_obj.get("started_at"),
        "finished_at": scan_obj.get("finished_at"),
        "duration_seconds": scan_obj.get("duration_seconds"),
        "overall_score": scan_obj.get("overall_score"),
        "grade": scan_obj.get("grade"),
        "grade_label": scan_obj.get("grade_label", ""),
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_critical": scan_obj.get("total_critical", 0),
            "total_high": scan_obj.get("total_high", 0),
            "total_medium": scan_obj.get("total_medium", 0),
            "total_low": scan_obj.get("total_low", 0),
            "total_info": scan_obj.get("total_info", 0),
            "total_pass": scan_obj.get("total_pass", 0),
        },
        "modules": modules_out,
    }

    out = report_dir / "report.json"
    out.write_text(json.dumps(data, indent=2, default=str))
