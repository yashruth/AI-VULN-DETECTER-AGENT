from fpdf import FPDF
from vuln_database import get_details

def generate_report(vulns):

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200,10,"AI Vulnerability Assessment Report", ln=True)
    pdf.cell(200,10,f"Total Findings: {len(vulns)}", ln=True)
    pdf.cell(200,10,"--------------------------------------", ln=True)

    if len(vulns) == 0:
        pdf.cell(200,10,"No vulnerabilities found", ln=True)

    for v in vulns:

        impact, rec = get_details(v["vulnerability"])

        pdf.set_font("Arial","B",12)
        pdf.cell(200,10,"Vulnerability:", ln=True)

        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0,10,v["vulnerability"])

        pdf.cell(200,10,"Severity: " + v["severity"], ln=True)
        pdf.cell(200,10,"CVSS: " + str(v["cvss"]), ln=True)

        pdf.set_font("Arial","B",12)
        pdf.cell(200,10,"Impact:", ln=True)

        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0,10,impact)

        pdf.set_font("Arial","B",12)
        pdf.cell(200,10,"Recommendation:", ln=True)

        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0,10,rec)

        pdf.cell(200,10,"--------------------------------------", ln=True)

    path = "report.pdf"
    pdf.output(path)

    return path
