"""Severity scoring and grade calculation."""

from dataclasses import dataclass
from janscan.modules.base import Finding, Severity

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: -20,
    Severity.HIGH:     -10,
    Severity.MEDIUM:   -5,
    Severity.LOW:      -2,
    Severity.INFO:      0,
    Severity.PASS:      0,
}

GRADE_MAP = [
    (90, "A", "Excellent"),
    (75, "B", "Good"),
    (60, "C", "Fair"),
    (40, "D", "Poor"),
    (0,  "F", "Critical Risk"),
]


@dataclass
class ScanScore:
    overall: int
    grade: str
    grade_label: str
    total_critical: int
    total_high: int
    total_medium: int
    total_low: int
    total_info: int
    total_pass: int


def calculate_score(all_findings: list) -> ScanScore:
    base = 100
    counts = {s: 0 for s in Severity}

    for f in all_findings:
        sev = f.severity if isinstance(f.severity, Severity) else Severity(f.severity)
        if not f.passed:
            base += SEVERITY_WEIGHTS.get(sev, 0)
        counts[sev] += 1

    score = max(0, min(100, base))

    grade, label = "F", "Critical Risk"
    for threshold, g, l in GRADE_MAP:
        if score >= threshold:
            grade, label = g, l
            break

    return ScanScore(
        overall=score,
        grade=grade,
        grade_label=label,
        total_critical=counts[Severity.CRITICAL],
        total_high=counts[Severity.HIGH],
        total_medium=counts[Severity.MEDIUM],
        total_low=counts[Severity.LOW],
        total_info=counts[Severity.INFO],
        total_pass=counts[Severity.PASS],
    )


def _findings_from_db(findings_db: list) -> list:
    """Convert DB finding dicts to Finding objects for scoring."""
    result = []
    for f in findings_db:
        try:
            result.append(Finding(
                title=f.get("title", ""),
                description=f.get("description", ""),
                severity=Severity(f.get("severity", "INFO")),
                passed=bool(f.get("passed", 0)),
                recommendation=f.get("recommendation", ""),
                raw_output=f.get("raw_output", ""),
            ))
        except Exception:
            pass
    return result
