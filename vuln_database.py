def get_details(v):

    # ---------------- CRITICAL ----------------
    if "SQL Injection" in v:
        return (
            "Attackers can access, modify, or delete sensitive database data.",
            "Use parameterized queries (prepared statements) and strict input validation."
        )

    if "Remote Code Execution" in v:
        return (
            "Attackers can execute arbitrary commands and take full control of the server.",
            "Avoid executing user input in system commands and use secure APIs."
        )

    if "Sensitive File Exposure" in v:
        return (
            "Sensitive data such as credentials, API keys, or configurations may be exposed.",
            "Restrict access to sensitive files using proper permissions and server rules."
        )

    if ".env" in v or ".git" in v:
        return (
            "Critical secrets like database credentials or API keys may be leaked.",
            "Remove these files from public access and store secrets securely."
        )

    # ---------------- HIGH ----------------
    if "XSS" in v:
        return (
            "Attackers can inject malicious scripts that execute in users’ browsers.",
            "Sanitize and encode all user inputs and implement Content Security Policy (CSP)."
        )

    if "Open Redirect" in v:
        return (
            "Users can be redirected to malicious or phishing websites.",
            "Validate and restrict redirect URLs to trusted domains only."
        )

    if "CORS" in v:
        return (
            "Unauthorized domains may access sensitive data from your application.",
            "Restrict Access-Control-Allow-Origin to trusted domains only."
        )

    if "Command Injection" in v:
        return (
            "Attackers may execute arbitrary system commands.",
            "Avoid passing user input directly into system commands."
        )

    # ---------------- MEDIUM ----------------
    if "Directory Listing" in v:
        return (
            "Server directory structure is exposed to attackers.",
            "Disable directory listing in the web server configuration."
        )

    if "Directory" in v:
        return (
            "Unauthorized users may access restricted endpoints or admin panels.",
            "Restrict access to sensitive directories using authentication and access controls."
        )

    if "Debug" in v or "Traceback" in v:
        return (
            "Internal application details and errors are exposed.",
            "Disable debug mode and remove detailed error messages in production."
        )

    if "API" in v:
        return (
            "API endpoints may expose sensitive data or functionality.",
            "Implement authentication, authorization, and rate limiting."
        )

    # ---------------- LOW ----------------
    if "Missing Header" in v:
        return (
            "Security protections like clickjacking or XSS defense are weakened.",
            "Add recommended HTTP security headers such as CSP, HSTS, and X-Frame-Options."
        )

    if "CSP" in v:
        return (
            "Browser protection against script injection is missing.",
            "Implement a strong Content Security Policy."
        )

    if "X-Frame" in v:
        return (
            "Application may be vulnerable to clickjacking attacks.",
            "Set X-Frame-Options to DENY or SAMEORIGIN."
        )

    if "HSTS" in v:
        return (
            "Secure HTTPS connections are not enforced.",
            "Enable Strict-Transport-Security with an appropriate max-age."
        )

    if "Server Disclosure" in v:
        return (
            "Server version details help attackers identify vulnerabilities.",
            "Remove or obfuscate server header information."
        )

    if "Technology Disclosure" in v:
        return (
            "Technology stack information increases attack surface.",
            "Remove X-Powered-By and similar headers."
        )

    if "Cookie" in v:
        return (
            "Cookies may be exposed or accessible to attackers.",
            "Set Secure, HttpOnly, and SameSite attributes for cookies."
        )

    if "HTTPS" in v:
        return (
            "Data transmitted between user and server can be intercepted.",
            "Enable HTTPS and redirect all HTTP traffic to HTTPS."
        )

    # ---------------- FALLBACK (SPECIFIC, NOT GENERIC) ----------------
    return (
        f"The issue '{v}' may expose the application to security risks.",
        f"Investigate '{v}' and apply appropriate security hardening measures."
    )
