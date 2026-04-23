from fpdf import FPDF
from vuln_database import get_details

def clean_text(text):
    return text.encode("latin-1", "replace").decode("latin-1")

def generate_report(vulns):

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200,10, clean_text("AI Vulnerability Report"), ln=True)
    pdf.cell(200,10, clean_text(f"Total Findings: {len(vulns)}"), ln=True)
    pdf.cell(200,10, clean_text("----------------------------"), ln=True)

    if len(vulns) == 0:
        pdf.cell(200,10, clean_text("No vulnerabilities found"), ln=True)

    for v in vulns:

        impact, rec = get_details(v["vulnerability"])

        pdf.multi_cell(0,10, clean_text("Vulnerability: " + v["vulnerability"]))
        pdf.cell(200,10, clean_text("Severity: " + v["severity"]), ln=True)
        pdf.cell(200,10, clean_text("CVSS: " + str(v["cvss"])), ln=True)

        pdf.multi_cell(0,10, clean_text("Impact: " + impact))
        pdf.multi_cell(0,10, clean_text("Recommendation: " + rec))

        pdf.cell(200,10, clean_text("----------------------"), ln=True)

    path = "report.pdf"
    pdf.output(path)

    return path
