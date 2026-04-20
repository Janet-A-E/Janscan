"""Audit Summary module — always runs last."""

import time
from janscan.modules.base import BaseModule, ModuleResult, Finding, Severity


class AuditSummaryModule(BaseModule):
    name = "audit_summary"
    display_name = "Audit Summary"
    description = "Summarises all findings from the audit run. Always runs last."
    requires_root = False

    # These are injected by runner after all other modules complete
    _all_results = []

    def run(self) -> ModuleResult:
        t0 = time.time()
        findings = []

        all_results = getattr(self, "_all_results", [])
        all_findings = [f for r in all_results for f in r.findings]

        counts = {s: 0 for s in Severity}
        for f in all_findings:
            sev = f.severity if isinstance(f.severity, Severity) else Severity(f.severity)
            counts[sev] += 1

        total = len(all_findings)
        findings.append(Finding(
            title="Total Findings",
            description=(
                f"CRITICAL: {counts[Severity.CRITICAL]}  "
                f"HIGH: {counts[Severity.HIGH]}  "
                f"MEDIUM: {counts[Severity.MEDIUM]}  "
                f"LOW: {counts[Severity.LOW]}  "
                f"PASS: {counts[Severity.PASS]}  "
                f"INFO: {counts[Severity.INFO]}  "
                f"Total: {total}"
            ),
            severity=Severity.INFO, passed=True,
        ))

        # Top 5 critical/high
        critical_high = [f for f in all_findings if f.severity in (Severity.CRITICAL, Severity.HIGH) and not f.passed]
        if critical_high:
            top5 = critical_high[:5]
            findings.append(Finding(
                title=f"Top Critical/High Issues ({len(critical_high)} total)",
                description="\n".join(f"[{f.severity}] {f.title}" for f in top5),
                severity=Severity.INFO, passed=True,
            ))

        # Modules with most issues
        module_counts = {}
        for r in all_results:
            issues = sum(1 for f in r.findings if not f.passed and f.severity not in (Severity.INFO, Severity.PASS))
            module_counts[r.module_display_name] = issues
        worst = sorted(module_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        if worst:
            findings.append(Finding(
                title="Modules with Most Issues",
                description="\n".join(f"{m}: {c} issue(s)" for m, c in worst if c > 0),
                severity=Severity.INFO, passed=True,
            ))

        # Quick wins (LOW severity fixes)
        quick = [f for f in all_findings if f.severity == Severity.LOW and not f.passed and f.recommendation][:3]
        if quick:
            findings.append(Finding(
                title="Quick Win Recommendations",
                description="\n".join(f"- {f.title}: {f.recommendation}" for f in quick),
                severity=Severity.INFO, passed=True,
            ))

        return ModuleResult(self.name, self.display_name, findings, time.time() - t0)
