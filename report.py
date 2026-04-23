from fpdf import FPDF
from vuln_database import get_details

def clean(text):
    return str(text).encode("latin-1", "replace").decode("latin-1")

class PDF(FPDF):

    def header(self):
        self.set_fill_color(20, 20, 20)
        self.set_text_color(255, 255, 255)
        self.set_font("Arial", "B", 14)
        self.cell(0, 12, "Web Application Penetration Testing Report", 0, 1, "C", True)
        self.ln(4)

    def section(self, title):
        self.set_fill_color(230, 230, 230)
        self.set_text_color(0, 0, 0)
        self.set_font("Arial", "B", 12)
        self.cell(0, 8, title, 0, 1, "L", True)
        self.ln(2)

def generate_report(vulns, target="Unknown Target"):

    pdf = PDF()
    pdf.add_page()
    pdf.set_font("Arial", size=11)

    # Executive Summary
    pdf.section("1. Executive Summary")
    pdf.multi_cell(0, 6, clean(
        f"A security assessment was conducted on {target}. "
        f"{len(vulns)} vulnerabilities were identified."
    ))

    # Scope
    pdf.section("1.1 Scope")
    pdf.cell(60, 8, "Application", 1)
    pdf.cell(130, 8, clean(target), 1, 1)

    pdf.cell(60, 8, "Testing Type", 1)
    pdf.cell(130, 8, "Automated Scan", 1, 1)

    pdf.ln(3)

    # Summary
    counts = {"Critical":0,"High":0,"Medium":0,"Low":0}
    for v in vulns:
        counts[v["severity"]] += 1

    pdf.section("1.2 Summary")
    for k,v in counts.items():
        pdf.cell(0, 8, f"{k}: {v}", ln=True)

    pdf.cell(0, 8, f"Total: {len(vulns)}", ln=True)

    # Detailed
    pdf.section("2. Detailed Vulnerabilities")

    for i, v in enumerate(vulns, 1):

        desc, impact, likelihood, rec = get_details(v["vulnerability"])

        pdf.set_font("Arial","B",11)
        pdf.cell(0, 8, clean(f"{i}. {v['vulnerability']}"), ln=True)

        pdf.set_font("Arial", size=11)
        pdf.cell(0, 6, f"Severity: {v['severity']}", ln=True)
        pdf.cell(0, 6, f"CVSS: {v.get('cvss','N/A')}", ln=True)
        pdf.cell(0, 6, f"Likelihood: {likelihood}", ln=True)

        pdf.multi_cell(0, 6, clean("Impact: " + impact))
        pdf.multi_cell(0, 6, clean("Observation: " + desc))
        pdf.multi_cell(0, 6, clean("Recommendation: " + rec))

        pdf.ln(3)

    path = "report.pdf"
    pdf.output(path)

    return path
