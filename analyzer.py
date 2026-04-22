def analyze(vulns):

    results = []

    for v in vulns:

        if "SQL" in v or "Sensitive File" in v or "Command" in v:
            severity = "Critical"

        elif "XSS" in v or "Redirect" in v:
            severity = "High"

        elif "Directory" in v:
            severity = "Medium"

        else:
            severity = "Low"

        results.append({
            "vulnerability": v,
            "severity": severity
        })

    return results
