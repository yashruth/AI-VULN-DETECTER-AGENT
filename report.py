from fpdf import FPDF
from vuln_database import get_details

# Fix Unicode issues
def clean(text):
    return str(text).encode("latin-1", "replace").decode("latin-1")

def generate_report(vulns, target="Unknown Target"):

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=11)

    # ---------------- TITLE ----------------
    pdf.set_font("Arial", "B", 14)
    pdf.cell(200, 10, clean("WEB APPLICATION PENETRATION TEST REPORT"), ln=True)

    pdf.set_font("Arial", size=11)
    pdf.cell(200, 8, clean(f"Target: {target}"), ln=True)
    pdf.cell(200, 8, clean("Assessment Type: Automated Security Scan"), ln=True)

    pdf.ln(5)

    # ---------------- SUMMARY ----------------
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for v in vulns:
        if v["severity"] in counts:
            counts[v["severity"]] += 1

    total = len(vulns)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 8, "1. Executive Summary", ln=True)

    pdf.set_font("Arial", size=11)
    pdf.multi_cell(0, 8, clean(
        f"This report presents the findings of an automated security assessment "
        f"conducted on {target}. A total of {total} issues were identified across "
        f"multiple severity levels."
    ))

    pdf.ln(3)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 8, "2. Vulnerability Summary", ln=True)

    pdf.set_font("Arial", size=11)
    pdf.cell(200, 8, clean(f"Total Findings: {total}"), ln=True)
    pdf.cell(200, 8, clean(
        f"Critical: {counts['Critical']} | High: {counts['High']} | "
        f"Medium: {counts['Medium']} | Low: {counts['Low']}"
    ), ln=True)

    pdf.ln(5)

    # ---------------- TOP FINDINGS ----------------
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 8, "3. Key Vulnerabilities", ln=True)

    pdf.set_font("Arial", size=11)

    for i, v in enumerate(vulns[:10], 1):
        pdf.cell(200, 8, clean(f"{i}. {v['vulnerability']} ({v['severity']})"), ln=True)

    pdf.ln(5)

    # ---------------- DETAILED FINDINGS ----------------
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 8, "4. Detailed Findings", ln=True)

    for i, v in enumerate(vulns, 1):

        # Get vulnerability details
        desc, impact, likelihood, rec = get_details(v["vulnerability"])

        pdf.set_font("Arial", "B", 11)
        pdf.cell(200, 8, clean(f"{i}. {v['vulnerability']}"), ln=True)

        pdf.set_font("Arial", size=11)
        pdf.cell(200, 8, clean(f"Severity: {v['severity']}"), ln=True)
        pdf.cell(200, 8, clean(f"Likelihood: {likelihood}"), ln=True)
        pdf.cell(200, 8, clean(f"CVSS Score: {v.get('cvss', 'N/A')}"), ln=True)

        pdf.multi_cell(0, 8, clean("Description: " + desc))
        pdf.multi_cell(0, 8, clean("Impact: " + impact))
        pdf.multi_cell(0, 8, clean("Recommendation: " + rec))

        pdf.cell(200, 8, clean("-" * 50), ln=True)

    # ---------------- SAVE ----------------
    path = "report.pdf"
    pdf.output(path)

    return path
