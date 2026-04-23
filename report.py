from fpdf import FPDF
from vuln_database import get_details

def generate_report(vulns):

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200,10,"Vulnerability Report", ln=True)

    if len(vulns)==0:
        pdf.cell(200,10,"No vulnerabilities found", ln=True)

    for v in vulns:

        impact, rec = get_details(v["vulnerability"])

        pdf.cell(200,10,v["vulnerability"], ln=True)
        pdf.cell(200,10,v["severity"], ln=True)
        pdf.cell(200,10,str(v["cvss"]), ln=True)
        pdf.cell(200,10,impact, ln=True)
        pdf.cell(200,10,rec, ln=True)

        pdf.cell(200,10,"----------------", ln=True)

    path = "report.pdf"
    pdf.output(path)

    return path
