from fpdf import FPDF
from vuln_database import get_details

def generate_report(vulns):

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200,10,"AI Vulnerability Report", ln=True)
    pdf.cell(200,10,f"Total Findings: {len(vulns)}", ln=True)
    pdf.cell(200,10,"----------------------------", ln=True)

    if len(vulns) == 0:
        pdf.cell(200,10,"No vulnerabilities found", ln=True)

    for v in vulns:

        impact, rec = get_details(v["vulnerability"])

        pdf.cell(200,10,"Vuln: "+v["vulnerability"], ln=True)
        pdf.cell(200,10,"Severity: "+v["severity"], ln=True)
        pdf.cell(200,10,"CVSS: "+str(v["cvss"]), ln=True)
        pdf.cell(200,10,"Impact: "+impact, ln=True)
        pdf.cell(200,10,"Recommendation: "+rec, ln=True)
        pdf.cell(200,10,"----------------------", ln=True)

    path = "report.pdf"
    pdf.output(path)

    return path
