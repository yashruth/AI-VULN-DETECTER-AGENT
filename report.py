from fpdf import FPDF

def generate_report(vulns):

    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Arial", size=12)

    pdf.cell(200,10,"AI Bug Bounty Report", ln=True)

    for v in vulns:

        line = f"{v['vulnerability']} | Risk: {v['risk']} | CVSS: {v['cvss']}"

        pdf.cell(200,10,line, ln=True)

    pdf.output("report.pdf")