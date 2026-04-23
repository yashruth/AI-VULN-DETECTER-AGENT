from weasyprint import HTML
from vuln_database import get_details
import base64
import os

# -------- OPTIONAL: map vuln → CWE + CVSS vector --------
def get_cwe_cvss(v):
    v = v.lower()

    if "sql injection" in v:
        return ("CWE-89", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    if "xss" in v:
        return ("CWE-79", "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    if "sensitive file" in v or ".env" in v or ".git" in v:
        return ("CWE-522", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    if "directory" in v:
        return ("CWE-284", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
    if "header" in v:
        return ("CWE-693", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")

    return ("CWE-200", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")

# -------- embed image as base64 --------
def img_to_base64(path):
    if not path or not os.path.exists(path):
        return ""
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode()

def generate_report(vulns, target="Unknown Target"):

    # -------- counts --------
    counts = {"Critical":0,"High":0,"Medium":0,"Low":0}
    for v in vulns:
        counts[v["severity"]] += 1

    # -------- key table rows --------
    key_rows = ""
    for i, v in enumerate(vulns[:10], 1):
        key_rows += f"""
        <tr>
            <td>{i}</td>
            <td>{v['vulnerability']}</td>
            <td>{v['severity']}</td>
            <td>Open</td>
        </tr>
        """

    # -------- detailed --------
    details = ""
    for i, v in enumerate(vulns, 1):

        desc, impact, likelihood, rec = get_details(v["vulnerability"])
        cwe, cvss_vector = get_cwe_cvss(v["vulnerability"])

        # optional screenshot path from v (if you attach it)
        screenshot_html = ""
        img_path = v.get("screenshot")
        if img_path and os.path.exists(img_path):
            b64 = img_to_base64(img_path)
            screenshot_html = f"""
            <tr>
                <td>Proof of Concept</td>
                <td><img src="data:image/png;base64,{b64}" style="max-width:500px;"></td>
            </tr>
            """

        details += f"""
        <h3>{i}. {v['vulnerability']}</h3>
        <table>
            <tr><td>Status</td><td>Open</td></tr>
            <tr><td>Severity</td><td class="{v['severity'].lower()}">{v['severity']}</td></tr>
            <tr><td>Likelihood</td><td>{likelihood}</td></tr>
            <tr><td>CVSS Score</td><td>{v.get('cvss','N/A')}</td></tr>
            <tr><td>CVSS Vector</td><td>{cvss_vector}</td></tr>
            <tr><td>CWE</td><td>{cwe}</td></tr>
            <tr><td>Technical Impact</td><td>{impact}</td></tr>
            <tr><td>Observation</td><td>{desc}</td></tr>
            <tr><td>Testing Steps</td><td>Automated scanning + crafted requests</td></tr>
            {screenshot_html}
            <tr><td>Recommendation</td><td>{rec}</td></tr>
            <tr><td>References</td><td>OWASP Top 10, CWE Database</td></tr>
        </table>
        """

    # -------- embed logo (optional) --------
    logo_b64 = ""
    if os.path.exists("static/logo.png"):
        logo_b64 = img_to_base64("static/logo.png")

    # -------- HTML TEMPLATE --------
    html = f"""
    <html>
    <head>
    <style>
        @page {{
            size: A4;
            margin: 30px;
        }}

        body {{
            font-family: Arial;
        }}

        .cover {{
            text-align:center;
            margin-top:150px;
            page-break-after: always;
        }}

        h1 {{
            background:#222;
            color:white;
            padding:10px;
            text-align:center;
        }}

        h2 {{
            border-bottom:2px solid #333;
        }}

        table {{
            width:100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}

        th, td {{
            border:1px solid black;
            padding:8px;
        }}

        th {{
            background:#ddd;
        }}

        .critical {{ color:red; font-weight:bold; }}
        .high {{ color:orange; font-weight:bold; }}
        .medium {{ color:goldenrod; font-weight:bold; }}
        .low {{ color:green; font-weight:bold; }}

        .toc a {{
            text-decoration:none;
            color:black;
        }}
    </style>
    </head>

    <body>

    <!-- COVER PAGE -->
    <div class="cover">
        {f'<img src="data:image/png;base64,{logo_b64}" width="120"><br><br>' if logo_b64 else ''}
        <h1>Web Application Penetration Testing Report</h1>
        <h3>{target}</h3>
        <p>Prepared by: AI Vulnerability Scanner</p>
        <p>Confidential</p>
    </div>

    <!-- TABLE OF CONTENTS -->
    <h2>Table of Contents</h2>
    <div class="toc">
        <p>1. Executive Summary</p>
        <p>1.1 Scope</p>
        <p>1.2 Summary of Vulnerabilities</p>
        <p>1.3 Key Vulnerabilities</p>
        <p>2. Conclusion</p>
        <p>3. Detailed Vulnerabilities</p>
        <p>4. Appendix</p>
    </div>

    <!-- EXEC SUMMARY -->
    <h2>1. Executive Summary</h2>
    <p>
    A penetration test was conducted on {target}. A total of {len(vulns)} vulnerabilities
    were identified across multiple severity levels.
    </p>

    <!-- SCOPE -->
    <h2>1.1 Scope</h2>
    <table>
        <tr><td>Application</td><td>{target}</td></tr>
        <tr><td>Testing Type</td><td>Automated Scan</td></tr>
    </table>

    <!-- SUMMARY -->
    <h2>1.2 Summary of Vulnerabilities</h2>
    <table>
        <tr>
            <th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th>
        </tr>
        <tr>
            <td class="critical">{counts['Critical']}</td>
            <td class="high">{counts['High']}</td>
            <td class="medium">{counts['Medium']}</td>
            <td class="low">{counts['Low']}</td>
            <td>{len(vulns)}</td>
        </tr>
    </table>

    <!-- KEY -->
    <h2>1.3 Key Vulnerabilities</h2>
    <table>
        <tr>
            <th>#</th><th>Vulnerability</th><th>Severity</th><th>Status</th>
        </tr>
        {key_rows}
    </table>

    <!-- CONCLUSION -->
    <h2>2. Conclusion</h2>
    <p>Critical and high severity issues must be fixed immediately.</p>

    <!-- DETAILS -->
    <h2>3. Detailed Vulnerabilities</h2>
    {details}

    <!-- APPENDIX -->
    <h2>4. Appendix</h2>
    <h3>Methodology</h3>
    <p>OWASP Testing Methodology followed.</p>

    <h3>Tools Used</h3>
    <ul>
        <li>Automated Scanner</li>
        <li>HTTP Requests</li>
    </ul>

    </body>
    </html>
    """

    HTML(string=html).write_pdf("report.pdf")
    return "report.pdf"
