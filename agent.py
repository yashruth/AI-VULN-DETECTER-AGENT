from crawler import crawl
from scanner import scan
from analyzer import analyze
from cvss import calculate_cvss
from report import generate_report

target = input("Enter target URL: ")

urls = crawl(target)

if target not in urls:
    urls.append(target)

all_results = []

for url in urls:

    vulns = scan(url)

    analyzed = analyze(vulns)

    for a in analyzed:

        a["cvss"] = calculate_cvss(a["risk"])

        all_results.append(a)

generate_report(all_results)

print("Scan finished.")
print("Report saved as report.pdf")