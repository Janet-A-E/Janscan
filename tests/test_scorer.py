"""Scorer tests."""

from janscan.modules.base import Finding, Severity
from janscan.engine.scorer import calculate_score


def make_finding(sev, passed=False):
    return Finding(title="t", description="d", severity=sev, passed=passed)


def test_perfect_score():
    findings = [make_finding(Severity.PASS, True) for _ in range(10)]
    score = calculate_score(findings)
    assert score.overall == 100
    assert score.grade == "A"


def test_critical_deduction():
    findings = [make_finding(Severity.CRITICAL, False)]
    score = calculate_score(findings)
    assert score.overall == 80


def test_score_floor():
    findings = [make_finding(Severity.CRITICAL, False) for _ in range(20)]
    score = calculate_score(findings)
    assert score.overall == 0


def test_grade_f():
    findings = [make_finding(Severity.CRITICAL, False) for _ in range(5)]
    score = calculate_score(findings)
    assert score.grade == "F"
