import streamlit as st
import pandas as pd

from scanner import scan
from crawler import crawl
from subdomain import find_subdomains
from port_scan import scan_ports
from analyzer import analyze
from cvss import calculate_cvss
from report import generate_report

st.title("🔥 AI Vulnerability Scanner")

url = st.text_input("Enter Target URL")

if st.button("Start Scan"):

    if url:

        st.write("Scanning...")

        # Crawl URLs
        urls = crawl(url)

        if url not in urls:
            urls.append(url)

        # Subdomains
        domain = url.replace("https://","").replace("http://","").split("/")[0]
        subs = find_subdomains(domain)

        all_urls = urls + subs

        all_vulns = []

        for u in all_urls:
            all_vulns.extend(scan(u))

        analyzed = analyze(all_vulns)

        results = []

        for a in analyzed:
            a["cvss"] = calculate_cvss(a["severity"])
            results.append(a)

        # Display
        if len(results) == 0:
            st.success("No vulnerabilities found")

        else:
            for r in results:
                st.warning(f"{r['vulnerability']} | {r['severity']} | CVSS: {r['cvss']}")

        # Port Scan
        ports = scan_ports(domain)
        st.write("Open Ports:", ports)

        # Graph
        severity_count = {"Critical":0,"High":0,"Medium":0,"Low":0}

        for r in results:
            severity_count[r["severity"]] += 1

        df = pd.DataFrame(severity_count.items(), columns=["Severity","Count"])
        st.bar_chart(df.set_index("Severity"))

        # Report
        report_path = generate_report(results)

        with open(report_path, "rb") as f:
            st.download_button("Download Report", f, "report.pdf")

    else:
        st.error("Enter URL")
