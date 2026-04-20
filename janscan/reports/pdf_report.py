"""PDF report generator using ReportLab."""

from pathlib import Path
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)
from reportlab.platypus.flowables import KeepTogether
from reportlab.graphics.shapes import Drawing, Circle, String
from reportlab.graphics import renderPDF

SEV_COLORS = {
    "CRITICAL": colors.HexColor("#cc0000"),
    "HIGH":     colors.HexColor("#e05000"),
    "MEDIUM":   colors.HexColor("#cc8800"),
    "LOW":      colors.HexColor("#0066bb"),
    "INFO":     colors.HexColor("#666666"),
    "PASS":     colors.HexColor("#007744"),
}

PAGE_W, PAGE_H = A4


def _header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#555555"))
    canvas.drawString(2 * cm, 1 * cm, "JanScan Security Audit Report — CONFIDENTIAL")
    canvas.drawRightString(PAGE_W - 2 * cm, 1 * cm, f"Page {doc.page}")
    canvas.drawString(2 * cm, PAGE_H - 1.2 * cm, "JanScan v1.0.0")
    canvas.drawRightString(PAGE_W - 2 * cm, PAGE_H - 1.2 * cm, datetime.now().strftime("%Y-%m-%d"))
    canvas.restoreState()


def _score_circle(score: int, grade: str, grade_color_hex: str) -> Drawing:
    d = Drawing(160, 160)
    # Outer circle
    c_outer = Circle(80, 80, 70)
    c_outer.fillColor = colors.HexColor("#1a1a2e")
    c_outer.strokeColor = colors.HexColor(grade_color_hex)
    c_outer.strokeWidth = 4
    d.add(c_outer)
    # Score text
    score_str = String(80, 85, str(score), textAnchor="middle")
    score_str.fontName = "Helvetica-Bold"
    score_str.fontSize = 36
    score_str.fillColor = colors.HexColor(grade_color_hex)
    d.add(score_str)
    # Grade label
    grade_str = String(80, 60, f"Grade {grade}", textAnchor="middle")
    grade_str.fontName = "Helvetica"
    grade_str.fontSize = 14
    grade_str.fillColor = colors.HexColor(grade_color_hex)
    d.add(grade_str)
    return d


def _sev_row_color(sev: str):
    return {
        "CRITICAL": colors.HexColor("#ffeeee"),
        "HIGH":     colors.HexColor("#fff3ee"),
        "MEDIUM":   colors.HexColor("#fffbee"),
        "LOW":      colors.HexColor("#eef6ff"),
        "INFO":     colors.white,
        "PASS":     colors.HexColor("#eeffee"),
    }.get(str(sev).upper(), colors.white)


def _finding_sev(f):
    if isinstance(f, dict):
        return str(f.get("severity", "INFO")).upper()
    return str(f.severity.value).upper() if hasattr(f.severity, "value") else str(f.severity).upper()


def _finding_attr(f, key, default=""):
    if isinstance(f, dict):
        return f.get(key, default)
    return getattr(f, key, default)


def write_pdf_report(scan_obj, findings, module_results, score, report_dir: Path, from_db=False):
    out_path = str(report_dir / "report.pdf")
    styles = getSampleStyleSheet()

    heading1 = ParagraphStyle("H1", parent=styles["Heading1"], textColor=colors.HexColor("#cc0000"), fontSize=16, spaceAfter=8)
    heading2 = ParagraphStyle("H2", parent=styles["Heading2"], textColor=colors.HexColor("#333333"), fontSize=13, spaceAfter=6)
    body = ParagraphStyle("Body", parent=styles["Normal"], fontSize=9, leading=13)
    mono = ParagraphStyle("Mono", parent=styles["Code"], fontSize=7, leading=10, fontName="Courier")
    small = ParagraphStyle("Small", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor("#555555"))

    grade_hex = {"A": "#00aa55", "B": "#0088aa", "C": "#aa7700", "D": "#aa3300", "F": "#cc0000"}
    grade = scan_obj.get("grade", "F")
    g_hex = grade_hex.get(grade, "#cc0000")

    doc = SimpleDocTemplate(
        out_path, pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm,
        leftMargin=2 * cm, rightMargin=2 * cm,
    )

    story = []

    # ── COVER PAGE ──
    story.append(Spacer(1, 2 * cm))
    story.append(Paragraph("JanScan Security Audit Report", heading1))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#cc0000")))
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph(f"<b>Host:</b> {scan_obj.get('hostname', 'Unknown')}", body))
    story.append(Paragraph(f"<b>Scan Date:</b> {str(scan_obj.get('started_at', ''))[:19]}", body))
    story.append(Paragraph(f"<b>Duration:</b> {scan_obj.get('duration_seconds', 0):.1f}s", body))
    story.append(Spacer(1, 1 * cm))

    circ = _score_circle(score.overall if hasattr(score, "overall") else score, grade, g_hex)
    story.append(circ)
    story.append(Spacer(1, 0.5 * cm))
    grade_label = getattr(score, "grade_label", "")
    story.append(Paragraph(f"<b>Security Grade: {grade} — {grade_label}</b>", heading2))
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph(
        "<i>CONFIDENTIAL — This report contains sensitive security information. "
        "Handle according to your organization's security policies.</i>", small
    ))
    story.append(PageBreak())

    # ── EXECUTIVE SUMMARY ──
    story.append(Paragraph("Executive Summary", heading1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.3 * cm))

    sc = score
    summary_data = [
        ["Severity", "Count", "Impact"],
        ["CRITICAL", str(getattr(sc, "total_critical", 0)), "Immediate action required"],
        ["HIGH", str(getattr(sc, "total_high", 0)), "Address within 24 hours"],
        ["MEDIUM", str(getattr(sc, "total_medium", 0)), "Address within 1 week"],
        ["LOW", str(getattr(sc, "total_low", 0)), "Address within 1 month"],
        ["PASS", str(getattr(sc, "total_pass", 0)), "No action needed"],
        ["INFO", str(getattr(sc, "total_info", 0)), "Informational only"],
    ]
    t = Table(summary_data, colWidths=[5 * cm, 3 * cm, 9 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#cc0000")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f8f8")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.5 * cm))

    # Top 3 critical
    all_f = findings if from_db else [f for mr in module_results for f in mr.findings]
    top_critical = [f for f in all_f
                    if _finding_sev(f) in ("CRITICAL", "HIGH")
                    and not _finding_attr(f, "passed")][:3]
    if top_critical:
        story.append(Paragraph("Top Critical Issues", heading2))
        for f in top_critical:
            sev = _finding_sev(f)
            title = _finding_attr(f, "title")
            desc = _finding_attr(f, "description")
            rec = _finding_attr(f, "recommendation")
            story.append(Paragraph(f"<b>[{sev}] {title}</b>", body))
            story.append(Paragraph(desc[:300], small))
            if rec:
                story.append(Paragraph(f"<i>Fix: {rec[:200]}</i>", small))
            story.append(Spacer(1, 0.2 * cm))

    story.append(PageBreak())

    # ── MODULE REPORTS ──
    if from_db:
        by_module = {}
        for f in findings:
            mn = f.get("module_name", "unknown")
            by_module.setdefault(mn, {"display_name": mn, "findings": []})
            by_module[mn]["findings"].append(f)
        for mr in module_results:
            mn = mr.get("module_name", "unknown")
            if mn in by_module:
                by_module[mn]["display_name"] = mr.get("display_name", mn)
        modules_iter = list(by_module.values())
    else:
        modules_iter = [{"display_name": mr.module_display_name, "findings": mr.findings} for mr in module_results]

    for mod in modules_iter:
        dn = mod["display_name"]
        mf = mod["findings"]
        story.append(Paragraph(dn, heading2))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#dddddd")))
        story.append(Spacer(1, 0.2 * cm))

        if not mf:
            story.append(Paragraph("No findings.", small))
            story.append(Spacer(1, 0.3 * cm))
            continue

        rows = [["Severity", "Title", "Description / Recommendation"]]
        row_sevs = []
        for f in mf:
            sev = _finding_sev(f)
            title = _finding_attr(f, "title")
            desc = _finding_attr(f, "description", "")[:120]
            rec = _finding_attr(f, "recommendation", "")[:120]
            combined = desc
            if rec:
                combined += f"\n→ {rec}"
            rows.append([sev, title[:60], combined])
            row_sevs.append(sev)

        col_widths = [2.5 * cm, 5.5 * cm, 9 * cm]
        ft = Table(rows, colWidths=col_widths, repeatRows=1)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("WORDWRAP", (0, 0), (-1, -1), True),
        ]
        for i, sev in enumerate(row_sevs, 1):
            rc = _sev_row_color(sev)
            style.append(("BACKGROUND", (0, i), (0, i), SEV_COLORS.get(sev, colors.gray)))
            style.append(("TEXTCOLOR", (0, i), (0, i), colors.white))
            style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
            style.append(("ROWBACKGROUNDS", (1, i), (-1, i), [rc]))

        ft.setStyle(TableStyle(style))
        story.append(ft)
        story.append(Spacer(1, 0.5 * cm))

    story.append(PageBreak())

    # ── RECOMMENDATIONS ──
    story.append(Paragraph("All Recommendations", heading1))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#cc0000")))
    story.append(Spacer(1, 0.3 * cm))

    all_issues = [f for f in all_f if not _finding_attr(f, "passed") and _finding_sev(f) not in ("INFO", "PASS")]
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    all_issues.sort(key=lambda f: sev_order.index(_finding_sev(f)) if _finding_sev(f) in sev_order else 99)

    for f in all_issues:
        sev = _finding_sev(f)
        title = _finding_attr(f, "title")
        desc = _finding_attr(f, "description", "")[:300]
        rec = _finding_attr(f, "recommendation", "")

        block = [
            Paragraph(f"<b>[{sev}] {title}</b>", body),
            Paragraph(desc, small),
        ]
        if rec:
            block.append(Paragraph(f"<b>Fix:</b> <i>{rec[:250]}</i>", small))
        block.append(Spacer(1, 0.15 * cm))
        story.append(KeepTogether(block))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
