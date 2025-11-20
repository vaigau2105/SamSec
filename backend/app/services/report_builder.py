from pathlib import Path
import json
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)

def generate_html_report(job_id, results):
    html_path = RESULTS_DIR / f"{job_id}.html"

    severity_colors = {
        "high": "#ff4b4b",
        "medium": "#ffb84b",
        "low": "#4bff6c"
    }

    findings = results.get("findings", [])

    findings_html = ""
    for f in findings:
        color = severity_colors.get(f["severity"].lower(), "#ffffff")
        findings_html += f"""
        <div class="finding" style="border-left: 6px solid {color}">
            <h3>{f['severity'].upper()}</h3>
            <p><b>Description:</b> {f['description']}</p>
            <p><b>Target:</b> {f['target']}</p>
        </div>
        """

    html_template = f"""
    <html>
    <head>
        <title>SamSec Report - {job_id}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #0d1117;
                color: #e6edf3;
                padding: 20px;
            }}
            h1 {{
                text-align: center;
                color: #58a6ff;
            }}
            .section {{
                background: #161b22;
                padding: 20px;
                border-radius: 10px;
                margin-bottom: 20px;
            }}
            .finding {{
                background: #1c2128;
                padding: 15px;
                margin-top: 10px;
                border-radius: 8px;
            }}
            hr {{
                border: 1px solid #30363d;
            }}
        </style>
    </head>
    <body>
        <h1>SamSec Scan Report</h1>
        
        <div class="section">
            <h2>Scan Summary</h2>
            <p><b>Job ID:</b> {job_id}</p>
            <p><b>Targets:</b> {results['targets']}</p>
            <p><b>Status:</b> {results['status']}</p>
            <p><b>Timestamp:</b> {results['timestamp']}</p>
        </div>

        <div class="section">
            <h2>Findings ({len(findings)})</h2>
            {findings_html}
        </div>
    </body>
    </html>
    """

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_template)

    return html_path


def generate_pdf_report(job_id, results):
    pdf_path = RESULTS_DIR / f"{job_id}.pdf"
    styles = getSampleStyleSheet()
    pdf = SimpleDocTemplate(str(pdf_path), pagesize=A4)

    content = []
    title = Paragraph("<b>SamSec Scan Report</b>", styles["Title"])
    content.append(title)
    content.append(Spacer(1, 12))

    summary = f"""
    <b>Job ID:</b> {job_id}<br/>
    <b>Targets:</b> {results['targets']}<br/>
    <b>Status:</b> {results['status']}<br/>
    <b>Timestamp:</b> {results['timestamp']}<br/>
    """
    content.append(Paragraph(summary, styles["BodyText"]))
    content.append(Spacer(1, 16))

    content.append(Paragraph("<b>Findings</b>", styles["Heading2"]))
    content.append(Spacer(1, 12))

    for f in results["findings"]:
        finding_block = f"""
        <b>Severity:</b> {f['severity']}<br/>
        <b>Description:</b> {f['description']}<br/>
        <b>Target:</b> {f['target']}<br/><br/>
        """
        content.append(Paragraph(finding_block, styles["BodyText"]))
        content.append(Spacer(1, 12))

    pdf.build(content)
    return pdf_path
