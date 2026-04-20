"""All database read/write functions."""

import json
from janscan.storage.db import get_connection


def save_scan(scan_data: dict) -> int:
    conn = get_connection()
    try:
        cur = conn.execute(
            """INSERT INTO scans
               (scan_uuid, hostname, started_at, finished_at, duration_seconds,
                overall_score, grade, total_critical, total_high, total_medium,
                total_low, total_info, total_pass)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                scan_data["scan_uuid"], scan_data.get("hostname"),
                scan_data["started_at"], scan_data.get("finished_at"),
                scan_data.get("duration_seconds"), scan_data.get("overall_score"),
                scan_data.get("grade"), scan_data.get("total_critical", 0),
                scan_data.get("total_high", 0), scan_data.get("total_medium", 0),
                scan_data.get("total_low", 0), scan_data.get("total_info", 0),
                scan_data.get("total_pass", 0),
            )
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def save_findings(scan_id: int, all_findings, module_results=None) -> None:
    """Save findings. Accepts Finding objects or dicts. Optionally map to module_name."""
    conn = get_connection()
    try:
        # Build module_name lookup if we have module_results
        finding_module_map = {}
        if module_results:
            for mr in module_results:
                for f in mr.findings:
                    finding_module_map[id(f)] = mr.module_name

        for f in all_findings:
            if hasattr(f, "title"):
                # It's a Finding object
                module_name = finding_module_map.get(id(f), "unknown")
                conn.execute(
                    """INSERT INTO findings
                       (scan_id, module_name, title, description, severity, passed,
                        recommendation, raw_output, ref_links, tags)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        scan_id, module_name, f.title, f.description,
                        str(f.severity.value) if hasattr(f.severity, "value") else str(f.severity),
                        1 if f.passed else 0, f.recommendation, f.raw_output,
                        json.dumps(getattr(f, 'references', [])), json.dumps(f.tags),
                    )
                )
            else:
                # Dict
                conn.execute(
                    """INSERT INTO findings
                       (scan_id, module_name, title, description, severity, passed,
                        recommendation, raw_output, ref_links, tags)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        scan_id, f.get("module_name", "unknown"), f.get("title", ""),
                        f.get("description", ""), f.get("severity", "INFO"),
                        f.get("passed", 0), f.get("recommendation", ""),
                        f.get("raw_output", ""), f.get("ref_links", "[]"), f.get("tags", "[]"),
                    )
                )
        conn.commit()
    finally:
        conn.close()


def save_module_results(scan_id: int, results: list) -> None:
    conn = get_connection()
    try:
        for r in results:
            conn.execute(
                """INSERT INTO module_results
                   (scan_id, module_name, display_name, duration_seconds, finding_count, error)
                   VALUES (?,?,?,?,?,?)""",
                (
                    scan_id, r.module_name, r.module_display_name,
                    r.duration_seconds, len(r.findings), r.error,
                )
            )
        conn.commit()
    finally:
        conn.close()


def get_scan_by_id(scan_id: int) -> dict | None:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_scan_by_uuid(uuid: str) -> dict | None:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM scans WHERE scan_uuid = ?", (uuid,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_latest_scan() -> dict | None:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_scans(limit: int = 20) -> list:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_findings_for_scan(scan_id: int, severity: str | None = None) -> list:
    conn = get_connection()
    try:
        if severity:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? AND severity = ?",
                (scan_id, severity)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_module_results_for_scan(scan_id: int) -> list:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM module_results WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def delete_scan(scan_id: int) -> None:
    conn = get_connection()
    try:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
    finally:
        conn.close()


def diff_scans(scan_id_a: int, scan_id_b: int) -> dict:
    scan_a = get_scan_by_id(scan_id_a)
    scan_b = get_scan_by_id(scan_id_b)
    if not scan_a:
        return {"error": f"Scan ID {scan_id_a} not found."}
    if not scan_b:
        return {"error": f"Scan ID {scan_id_b} not found."}

    findings_a = get_findings_for_scan(scan_id_a)
    findings_b = get_findings_for_scan(scan_id_b)

    keys_a = {(f["module_name"], f["title"]) for f in findings_a if not f["passed"]}
    keys_b = {(f["module_name"], f["title"]) for f in findings_b if not f["passed"]}

    new_keys = keys_b - keys_a
    resolved_keys = keys_a - keys_b
    unchanged = keys_a & keys_b

    return {
        "scan_a": scan_a,
        "scan_b": scan_b,
        "new": [f for f in findings_b if (f["module_name"], f["title"]) in new_keys],
        "resolved": [f for f in findings_a if (f["module_name"], f["title"]) in resolved_keys],
        "unchanged_count": len(unchanged),
        "score_delta": (scan_b.get("overall_score") or 0) - (scan_a.get("overall_score") or 0),
    }
