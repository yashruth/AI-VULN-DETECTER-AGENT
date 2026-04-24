def get_details(v):

    v = v.lower()

    # ---------------- CRITICAL ----------------
    if "sql injection" in v:
        return (
            "SQL Injection vulnerability.",
            "Attackers can read, modify, or delete database data.",
            "High",
            "Use parameterized queries and input validation."
        )

    if "remote code execution" in v or "rce" in v:
        return (
            "Remote code execution vulnerability.",
            "Full system compromise is possible.",
            "High",
            "Avoid executing user input and secure command execution."
        )

    if "sensitive file" in v or ".env" in v or ".git" in v:
        return (
            "Sensitive files are publicly accessible.",
            "Credentials, API keys, or configurations may be exposed.",
            "High",
            "Restrict access and move sensitive files outside web root."
        )

    # ---------------- HIGH ----------------
    if "xss" in v:
        return (
            "Cross-site scripting vulnerability.",
            "Attackers can execute scripts in user browsers.",
            "High",
            "Sanitize inputs and implement CSP."
        )

    if "open redirect" in v:
        return (
            "Open redirect vulnerability.",
            "Users can be redirected to malicious websites.",
            "High",
            "Validate redirect URLs."
        )

    if "cors" in v:
        return (
            "CORS misconfiguration.",
            "Unauthorized domains may access sensitive data.",
            "High",
            "Restrict allowed origins."
        )

    if "command injection" in v:
        return (
            "Command injection vulnerability.",
            "Attackers can execute system commands.",
            "High",
            "Avoid passing user input into system calls."
        )

    # ---------------- MEDIUM ----------------
    if "directory listing" in v:
        return (
            "Directory listing enabled.",
            "Attackers can view internal file structure.",
            "Medium",
            "Disable directory listing."
        )

    if "directory" in v or "admin" in v or "login" in v:
        return (
            "Sensitive directory exposed.",
            "Unauthorized access to restricted endpoints.",
            "Medium",
            "Restrict access using authentication."
        )

    if "debug" in v or "traceback" in v:
        return (
            "Debug information exposed.",
            "Internal system details may leak.",
            "Medium",
            "Disable debug mode in production."
        )

    # ---------------- LOW ----------------
    if "missing header" in v:
        return (
            "Security header missing.",
            "Reduced browser protection against attacks.",
            "Low",
            "Add recommended HTTP security headers."
        )

    if "csp" in v:
        return (
            "Content Security Policy not implemented.",
            "Increases risk of XSS attacks.",
            "Low",
            "Implement CSP headers."
        )

    if "x-frame" in v:
        return (
            "Missing X-Frame-Options header.",
            "Application may be vulnerable to clickjacking.",
            "Low",
            "Set X-Frame-Options to DENY or SAMEORIGIN."
        )

    if "hsts" in v:
        return (
            "HSTS not enabled.",
            "HTTPS is not enforced.",
            "Low",
            "Enable Strict-Transport-Security."
        )

    if "server disclosure" in v:
        return (
            "Server information disclosed.",
            "Helps attackers identify vulnerabilities.",
            "Low",
            "Remove or hide server headers."
        )

    if "technology disclosure" in v:
        return (
            "Technology stack exposed.",
            "Increases attack surface.",
            "Low",
            "Remove X-Powered-By headers."
        )

    if "cookie" in v:
        return (
            "Insecure cookie configuration.",
            "Cookies may be accessed by attackers.",
            "Low",
            "Use Secure, HttpOnly, and SameSite flags."
        )

    if "https" in v:
        return (
            "Application not using HTTPS.",
            "Data can be intercepted.",
            "Low",
            "Enable HTTPS and redirect all traffic."
        )

    # ---------------- DEFAULT ----------------
    return (
        f"Issue detected: {v}",
        "This issue may expose the application to security risks.",
        "Low",
        "Investigate and apply appropriate security controls."
    )
    if "AI Prompt Injection" in v:
    return (
        "User input can override AI system instructions.",
        "Attackers may control AI responses.",
        "High",
        "Sanitize inputs and isolate system prompts."
    )

if "AI Sensitive Data Leakage" in v:
    return (
        "AI exposes sensitive information.",
        "Confidential data leakage risk.",
        "High",
        "Restrict access to sensitive data."
    )

if "AI Jailbreak" in v:
    return (
        "AI safety controls can be bypassed.",
        "Unsafe responses may be generated.",
        "Medium",
        "Implement stronger guardrails."
    )

if "AI Role Manipulation" in v:
    return (
        "User can escalate privileges in AI context.",
        "Unauthorized data exposure possible.",
        "High",
        "Validate role context strictly."
    )

if "AI Tool Abuse" in v:
    return (
        "AI may execute unintended commands.",
        "System compromise risk.",
        "High",
        "Restrict tool execution."
    )
