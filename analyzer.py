def analyze(vulns):

    results = []

    for v in vulns:

        if "SQL" in v or "XSS" in v:
            risk = "High"

        elif "Sensitive" in v or "Directory" in v:
            risk = "Medium"

        else:
            risk = "Low"

        results.append({
            "vulnerability": v,
            "risk": risk
        })

    return results