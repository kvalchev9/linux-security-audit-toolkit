from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
)


def format_pdf_report(report: dict, output_path: str | Path) -> None:
    """Generate a professional PDF audit report."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="Linux SSH Security Audit Report",
        author=report.get("tool", "Linux Security Audit Toolkit"),
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=21,
        leading=26,
        alignment=TA_LEFT,
        textColor=colors.HexColor("#17324D"),
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#17324D"),
        spaceBefore=12,
        spaceAfter=7,
    ))
    styles.add(ParagraphStyle(
        name="SmallText",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#526273"),
    ))
    styles.add(ParagraphStyle(
        name="FindingTitle",
        parent=styles["Heading3"],
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#17324D"),
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="FindingBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=12,
        spaceAfter=4,
        wordWrap="CJK",
    ))

    system = report["system"]
    summary = report["summary"]
    findings = report["findings"]

    story = [
        Paragraph("Linux Security Audit Toolkit", styles["ReportTitle"]),
        Paragraph("SSH CONFIGURATION SECURITY AUDIT", styles["SmallText"]),
        Spacer(1, 5 * mm),
        Paragraph(
            f"Generated: {report['generated_at']}",
            styles["SmallText"],
        ),
        Spacer(1, 5 * mm),
        Paragraph("Executive Summary", styles["SectionHeading"]),
    ]

    summary_data = [
        ["TOTAL FINDINGS", "PASS", "REVIEW", "HIGH"],
        [
            str(summary["total_findings"]),
            str(summary["pass"]),
            str(summary["review"]),
            str(summary["high"]),
        ],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[42 * mm, 34 * mm, 34 * mm, 34 * mm],
        hAlign="LEFT",
    )
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17324D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 7),
        ("FONTSIZE", (0, 1), (-1, 1), 17),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 1), (-1, 1), colors.HexColor("#17324D")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#F0F4F8")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D5DEE8")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D5DEE8")),
    ]))
    story.extend([summary_table, Spacer(1, 4 * mm)])

    story.append(Paragraph("System Information", styles["SectionHeading"]))
    system_data = [
        ["Hostname", str(system.get("hostname", "N/A"))],
        ["Operating system", str(system.get("operating_system", "N/A"))],
        ["OS release", str(system.get("os_release", "N/A"))],
        ["Architecture", str(system.get("architecture", "N/A"))],
        ["Python version", str(system.get("python_version", "N/A"))],
    ]
    system_table = Table(
        system_data,
        colWidths=[45 * mm, 125 * mm],
        hAlign="LEFT",
    )
    system_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F0F4F8")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#17324D")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D5DEE8")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([system_table, Spacer(1, 3 * mm)])

    story.append(Paragraph("Detailed Findings", styles["SectionHeading"]))

    if not findings:
        story.append(Paragraph(
            "No findings were generated.",
            styles["FindingBody"],
        ))
    else:
        for index, finding in enumerate(findings, start=1):
            status = str(finding.get("status", "UNKNOWN"))
            severity = str(finding.get("severity", "UNKNOWN"))

            heading = Paragraph(
                f"{index}. {finding.get('check', 'Unnamed check')}",
                styles["FindingTitle"],
            )
            details = [
                Paragraph(
                    f"<b>Status:</b> {status} &nbsp;&nbsp; "
                    f"<b>Severity:</b> {severity}",
                    styles["FindingBody"],
                ),
                Paragraph(
                    f"<b>Evidence:</b> {finding.get('evidence', 'N/A')}",
                    styles["FindingBody"],
                ),
                Paragraph(
                    f"<b>Recommendation:</b> "
                    f"{finding.get('recommendation', 'N/A')}",
                    styles["FindingBody"],
                ),
            ]

            status_color = (
                colors.HexColor("#E8F5E9")
                if status == "PASS"
                else colors.HexColor("#FFF3E0")
            )
            finding_table = Table(
                [[ [heading] + details ]],
                colWidths=[170 * mm],
            )
            finding_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), status_color),
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#D5DEE8")),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.extend([KeepTogether([finding_table]), Spacer(1, 3 * mm)])

    story.extend([
        Spacer(1, 5 * mm),
        Paragraph("Scope and Limitations", styles["SectionHeading"]),
        Paragraph(
            "This report evaluates the SSH configuration settings checked by "
            "the toolkit. A file-based review may not represent all effective "
            "settings, including values affected by Include directives, Match "
            "blocks, or runtime configuration. Review findings and validate "
            "the effective SSH daemon configuration before making changes.",
            styles["SmallText"],
        ),
    ])

    def add_page_number(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#D5DEE8"))
        canvas.line(18 * mm, 14 * mm, A4[0] - 18 * mm, 14 * mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#526273"))
        canvas.drawString(18 * mm, 9 * mm, "Linux Security Audit Toolkit")
        canvas.drawRightString(
            A4[0] - 18 * mm,
            9 * mm,
            f"Page {document.page}",
        )
        canvas.restoreState()

    doc.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number,
    )