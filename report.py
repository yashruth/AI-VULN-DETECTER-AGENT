from fpdf import FPDF
from vuln_database import get_details
import os

def clean(text):
    return str(text).encode("latin-1", "replace").decode("latin-1")

class PDF(FPDF):

    def header(self):
        self.set_fill_color(20, 20, 20)
        self.set_text_color(255, 255, 255)
        self.set_font("Arial", "B", 16)
        self.cell(0, 12, "AI Vulnerability Assessment Report", 0, 1, "C", True)
        self.ln(4)

    def section(self, title):
        self.set_fill_color(230, 230, 230)
        self.set_text_color(0, 0, 0)
        self.set_font("Arial", "B", 12)
        self.cell(0, 8, title, 0, 1, "L", True)
        self.ln(2)

def severity_badge(pdf, severity):

    if severity == "Critical":
        pdf.set_fill_color(220, 53, 69)
    elif severity == "High":
        pdf.set_fill_color(255, 140, 0)
    elif severity == "Medium":
        pdf.set_fill_color(255, 193, 7)
    else:
        pdf.set_fill_color(40, 167, 69)

    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Arial", "B", 10)
    pdf.cell(30, 6, severity, 0, 0, "C", True)
    pdf.ln(8)

def generate_report(vulns, target="Unknown Target"):

    pdf = PDF()
    pdf.add_page()
    pdf.set_font("Arial", size=11)

    # -------- Target Info --------
    pdf.section("Target Information")
    pdf.cell(0, 6, clean(f"Target: {target}"), ln=True)
    pdf.cell(0, 6, f"Total Findings: {len(vulns)}", ln=True)

    pdf.ln(4)

    # -------- Summary --------
    pdf.section("Executive Summary")
    pdf.multi_cell(0, 6, clean(
        f"The scan identified {len(vulns)} vulnerabilities across different severity levels."
    ))

    pdf.ln(4)

    # 🔥 Insert Graph Image
    if os.path.exists("chart.png"):
        pdf.section("Severity Graph")
        pdf.image("chart.png", x=10, w=180)
        pdf.ln(5)

    # -------- Detailed Findings --------
    pdf.section("Detailed Findings")

    for i, v in enumerate(vulns, 1):

        desc, impact, likelihood, rec = get_details(v["vulnerability"])

        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, clean(f"{i}. {v['vulnerability']}"), ln=True)

        severity_badge(pdf, v["severity"])

        pdf.set_font("Arial", size=11)

        pdf.cell(0, 6, clean(f"Likelihood: {likelihood}"), ln=True)
        pdf.cell(0, 6, clean(f"CVSS: {v.get('cvss','N/A')}"), ln=True)

        pdf.multi_cell(0, 6, clean("Description: " + desc))
        pdf.multi_cell(0, 6, clean("Impact: " + impact))
        pdf.multi_cell(0, 6, clean("Recommendation: " + rec))

        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)

    path = "report.pdf"
    pdf.output(path)

    return path
