from fpdf import FPDF
from vuln_database import get_details

def clean(t):
    return t.encode("latin-1", "replace").decode("latin-1")

def generate_report(vulns, target):

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=11)

    # ---------------- TITLE ----------------
    pdf.set_font("Arial", "B", 14)
    pdf.cell(200,10, clean("WEB APPLICATION PENETRATION TEST REPORT"), ln=True)

    pdf.set_font("Arial", size=11)
    pdf.cell(200,8, clean(f"Target: {target}"), ln=True)
    pdf.cell(200,8, clean("Assessment Type: Automated Security Scan"), ln=True)
    pdf.cell(200,8, clean("Tester: AI Vulnerability Scanner"), ln=True)

    pdf.ln(5)

    # ---------------- EXECUTIVE SUMMARY ----------------
    pdf.set_font("Arial","B",12)
    pdf.cell(200,8,"1. Executive Summary", ln=True)

    pdf.set_font("Arial", size=11)
    pdf.multi_cell(0,8, clean(
        f"This report presents the results of a web application security assessment conducted "
        f"on {target}. The objective was to identify vulnerabilities that could be exploited "
        f"by attackers. The findings include multiple security issues categorized based on severity."
    ))

    pdf.ln(3)

    # ---------------- SCOPE ----------------
    pdf.set_font("Arial","B",12)
    pdf.cell(200,8,"2. Scope", ln=True)

    pdf.set_font("Arial", size=11)
    pdf.cell(200,8, clean(f"In-Scope Target: {target}"), ln=True)
    pdf.cell(200,8, clean("Methodology: Automated vulnerability scanning"), ln=True)

    pdf.ln(5)

    # ---------------- SUMMARY TABLE ----------------
    counts = {"Critical":0,"High":0,"Medium":0,"Low":0}

    for v in vulns:
        counts[v["severity"]] += 1

    total = len(vulns)

    pdf.set_font("Arial","B",12)
    pdf.cell(200,8,"3. Vulnerability Summary", ln=True)

    pdf.set_font("Arial", size=11)
    pdf.cell(200,8, clean(f"Total Findings: {total}"), ln=True)
    pdf.cell(200,8, clean(
        f"Critical: {counts['Critical']} | High: {counts['High']} | "
        f"Medium: {counts['Medium']} | Low: {counts['Low']}"
    ), ln=True)

    pdf.ln(5)

    # ---------------- KEY FINDINGS ----------------
    pdf.set_font("Arial","B",12)
    pdf.cell(200,8,"4. Key Vulnerabilities", ln=True)

    pdf.set_font("Arial", size=11)

    for i, v in enumerate(vulns[:10], 1):
        pdf.cell(200,8, clean(f"{i}. {v['vulnerability']} ({v['severity']})"), ln=True)

    pdf.ln(5)

    # ---------------- DETAILED FINDINGS ----------------
    pdf.set_font("Arial","B",12)
    pdf.cell(200,8,"5. Detailed Findings", ln=True)

    for i, v in enumerate(vulns, 1):

        desc, impact, likelihood, rec = get_details(v["vulnerability"])

        pdf.set_font("Arial","B",11)
        pdf.cell(200,8, clean(f"5.{i} {v['vulnerability']}"), ln=True)

        pdf.set_font("Arial", size=11)
        pdf.cell(200,8, clean(f"Severity: {v['severity']}"), ln=True)
        pdf.cell(200,8, clean(f"Likelihood: {likelihood}"), ln=True)
        pdf.cell(200,8, clean(f"CVSS Score: {v['cvss']}"), ln=True)

        pdf.multi_cell(0,8, clean("Description: " + desc))
        pdf.multi_cell(0,8, clean("Impact: " + impact))
        pdf.multi_cell(0,8, clean("Recommendation: " + rec))

        pdf.cell(200,8, clean("--------------------------------------------------"), ln=True)

    path = "report.pdf"
    pdf.output(path)

    return path
