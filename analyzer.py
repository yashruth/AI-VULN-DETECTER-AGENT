def analyze(vulns):

    results = []

    for v in vulns:

        if "Critical" in v:
            risk = "Critical"

        elif "SQL" in v or "XSS" in v:
            risk = "High"

        elif "Directory" in v:
            risk = "Medium"

        else:
            risk = "Low"

        results.append({
            "vulnerability": v,
            "risk": risk
        })

    return results
