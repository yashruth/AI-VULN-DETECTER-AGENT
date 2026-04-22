import streamlit as st
from crawler import crawl
from scanner import scan
from analyzer import analyze
from cvss import calculate_cvss
from report import generate_report

st.title("AI Bug Bounty Scanner")

url = st.text_input("Enter Target URL")

if st.button("Start Scan"):

    if url:

        st.write("Scanning target...")

        urls = crawl(url)

        if url not in urls:
            urls.append(url)

        results = []

        for u in urls:

            vulns = scan(u)

            analyzed = analyze(vulns)

            for a in analyzed:

                a["cvss"] = calculate_cvss(a["risk"])

                results.append(a)

        for r in results:
            st.warning(
                f"{r['vulnerability']} | Risk: {r['risk']} | CVSS: {r['cvss']}"
            )

        generate_report(results)

        st.success("Scan complete. Report generated.")

    else:
        st.error("Enter a URL")
