def get_details(v):

    # ---------------- CRITICAL ----------------
    if "SQL" in v:
        return (
            "SQL Injection vulnerability.",
            "Database compromise possible.",
            "High",
            "Use parameterized queries."
        )

    if "Sensitive File" in v:
        return (
            "Sensitive file exposed.",
            "Confidential data leakage.",
            "High",
            "Restrict file access."
        )

    if "AI Sensitive Data Leakage" in v:
        return (
            "AI exposes sensitive data.",
            "Confidential information may leak.",
            "High",
            "Restrict AI data access."
        )

    # ---------------- HIGH ----------------
    if "XSS" in v:
        return (
            "Cross-site scripting vulnerability.",
            "Client-side attack possible.",
            "High",
            "Sanitize user input."
        )

    if "AI Prompt Injection" in v:
        return (
            "User can manipulate AI behavior.",
            "AI responses can be controlled by attacker.",
            "High",
            "Validate and isolate prompts."
        )

    if "AI Jailbreak" in v:
        return (
            "AI safety bypass possible.",
            "Unsafe outputs may be generated.",
            "Medium",
            "Add stronger guardrails."
        )

    if "AI Tool Abuse" in v:
        return (
            "AI may execute unintended commands.",
            "System misuse possible.",
            "High",
            "Restrict tool execution."
        )

    if "AI Role Manipulation" in v:
        return (
            "User can escalate AI privileges.",
            "Unauthorized access possible.",
            "High",
            "Validate role context."
        )

    # ---------------- MEDIUM ----------------
    if "Directory" in v:
        return (
            "Directory exposed.",
            "Unauthorized access possible.",
            "Medium",
            "Restrict directory access."
        )

    # ---------------- LOW ----------------
    if "Header" in v:
        return (
            "Missing security header.",
            "Weak protection.",
            "Low",
            "Add security headers."
        )

    # ---------------- DEFAULT ----------------
    return (
        f"Issue detected: {v}",
        "Potential risk.",
        "Low",
        "Review and fix."
    )
