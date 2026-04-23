def get_details(v):

    # ---------------- CRITICAL ----------------
    if "SQL Injection" in v:
        return (
            "Attackers can read, modify, or delete database data.",
            "Use parameterized queries and ORM frameworks."
        )

    if "Remote Code Execution" in v:
        return (
            "Attackers can execute system commands and fully compromise the server.",
            "Validate inputs and disable dangerous functions."
        )

    if "Sensitive File Exposure" in v:
        return (
            "Credentials or configuration data may be exposed.",
            "Restrict access to sensitive files and use proper permissions."
        )

    if ".env" in v or ".git" in v:
        return (
            "Critical secrets like API keys or credentials may be leaked.",
            "Remove sensitive files from public access and secure them."
        )

    # ---------------- HIGH ----------------
    if "XSS" in v:
        return (
            "Attackers can inject malicious scripts into users’ browsers.",
            "Sanitize user inputs and implement CSP headers."
        )

    if "Open Redirect" in v:
        return (
            "Users can be redirected to malicious phishing sites.",
            "Validate and restrict redirect URLs."
        )

    if "CORS" in v:
        return (
            "Unauthorized domains may access sensitive data.",
            "Restrict Access-Control-Allow-Origin to trusted domains."
        )

    if "Command Injection" in v:
        return (
            "Attackers can run arbitrary system commands.",
            "Avoid system calls with user input."
        )

    # ---------------- MEDIUM ----------------
    if "Directory" in v:
        return (
            "Sensitive endpoints may be accessible to unauthorized users.",
            "Restrict access and disable directory listing."
        )

    if "Directory Listing" in v:
        return (
            "Server file structure is exposed.",
            "Disable directory listing on the server."
        )

    if "Debug" in v or "Traceback" in v:
        return (
            "Internal system details are exposed.",
            "Disable debug mode in production."
        )

    if "API" in v:
        return (
            "API endpoints may expose sensitive functionality.",
            "Implement authentication and rate limiting."
        )

    # ---------------- LOW ----------------
    if "Missing Header" in v:
        return (
            "Security protections are reduced.",
            "Add recommended HTTP security headers."
        )

    if "CSP" in v:
        return (
            "Browser protection against XSS is missing.",
            "Implement Content Security Policy."
        )

    if "X-Frame" in v:
        return (
            "Application is vulnerable to clickjacking.",
            "Set X-Frame-Options to DENY or SAMEORIGIN."
        )

    if "HSTS" in v:
        return (
            "HTTPS is not enforced.",
            "Enable Strict-Transport-Security header."
        )

    if "Server Disclosure" in v:
        return (
            "Server version information helps attackers.",
            "Hide server headers."
        )

    if "Technology Disclosure" in v:
        return (
            "Technology stack is exposed.",
            "Remove X-Powered-By headers."
        )

    if "Cookie" in v:
        return (
            "Cookies may be accessible or insecure.",
            "Use Secure, HttpOnly, and SameSite flags."
        )

    if "HTTPS" in v:
        return (
            "Data can be intercepted in transit.",
            "Enable HTTPS and redirect all traffic."
        )

    # ---------------- DEFAULT ----------------
    return (
        "Potential security misconfiguration detected.",
        "Review and harden application security."
    )
