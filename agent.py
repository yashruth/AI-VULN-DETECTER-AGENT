import streamlit as st
import pandas as pd

from scanner import scan
from analyzer import analyze
from cvss import calculate_cvss
from report import generate_report

st.set_page_config(page_title="AI Vulnerability Scanner")

st.title("AI Vulnerability Scanner")

url = st.text_input("Enter Target URL")

if st.button("Start Scan"):

    if url:

        st.write("Scanning...")

        # Scan
        vulns = scan(url)
        analyzed = analyze(vulns)

        results = []

        # Process
        for a in analyzed:
            a["cvss"] = calculate_cvss(a["severity"])
            results.append(a)

        # Sort
        order = {"Critical":0,"High":1,"Medium":2,"Low":3}
        results = sorted(results, key=lambda x: order.get(x["severity"], 4))

        # Display
        if not results:
            st.success("No vulnerabilities found")
        else:
            st.subheader("Findings")
            for r in results:
                st.warning(f"{r['vulnerability']} | {r['severity']} | CVSS: {r['cvss']}")

        # Graph
        severity_count = {"Critical":0,"High":0,"Medium":0,"Low":0}
        for r in results:
            severity_count[r["severity"]] += 1

        df = pd.DataFrame(list(severity_count.items()), columns=["Severity","Count"])
        st.subheader("Severity Distribution")
        st.bar_chart(df.set_index("Severity"))

        # Generate report
        report_path = generate_report(results, url)

        with open(report_path, "rb") as f:
            st.download_button("Download Report", f, "report.pdf")

        st.success("Scan completed!")

    else:
        st.error("Enter URL")
