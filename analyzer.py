def analyze(vulns):

    results = []

    for v in vulns:

        # Normalize for safer matching
        v_lower = v.lower()

        # ---------------- CRITICAL ----------------
        if (
            "sql injection" in v_lower or
            "sensitive file" in v_lower or
            "data leakage" in v_lower
        ):
            severity = "Critical"

        # ---------------- HIGH ----------------
        elif (
            "xss" in v_lower or
            "cross-site scripting" in v_lower or
            "open redirect" in v_lower or
            "ai prompt injection" in v_lower or
            "ai jailbreak" in v_lower or
            "ai tool abuse" in v_lower or
            "ai role manipulation" in v_lower
        ):
            severity = "High"

        # ---------------- MEDIUM ----------------
        elif (
            "directory" in v_lower or
            "exposed" in v_lower
        ):
            severity = "Medium"

        # ---------------- LOW ----------------
        elif (
            "header" in v_lower or
            "server" in v_lower
        ):
            severity = "Low"

        else:
            severity = "Low"

        results.append({
            "vulnerability": v,
            "severity": severity
        })

    return results
