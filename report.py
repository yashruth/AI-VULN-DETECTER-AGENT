from fpdf import FPDF
from vuln_database import get_details

def generate_report(vulns):

    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Arial", size=12)

    pdf.cell(200,10,"AI Vulnerability Scan Report", ln=True)

    for v in vulns:

        details = get_details(v["vulnerability"])

        pdf.cell(200,10,f"Vulnerability: {v['vulnerability']}", ln=True)
        pdf.cell(200,10,f"Risk: {v['risk']}", ln=True)
        pdf.cell(200,10,f"Impact: {details['impact']}", ln=True)
        pdf.cell(200,10,f"Recommendation: {details['recommendation']}", ln=True)

        pdf.cell(200,10,"---------------------------------", ln=True)

    pdf.output("security_report.pdf")
