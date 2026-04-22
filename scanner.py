import requests

def scan(url):

    vulns = []

    try:

        r = requests.get(url, timeout=5)
        headers = r.headers
        body = r.text.lower()

        # ------------------------------------------------
        # CRITICAL VULNERABILITIES
        # ------------------------------------------------

        # SQL Injection indicator
        sql_payload = "' OR 1=1--"

        try:
            sqli = requests.get(url + "?id=" + sql_payload)

            sql_errors = [
                "sql syntax",
                "mysql",
                "database error",
                "warning: mysql",
                "postgresql error"
            ]

            for e in sql_errors:
                if e in sqli.text.lower():
                    vulns.append("Possible SQL Injection")

        except:
            pass


        # Command Injection / RCE indicator
        try:
            cmd = requests.get(url + "?cmd=id")

            if "uid=" in cmd.text:
                vulns.append("Possible Remote Command Execution")

        except:
            pass


        # Sensitive file exposure
        sensitive_files = [
        "/.env",
        "/.git/config",
        "/backup.zip",
        "/database.sql",
        "/config.php",
        "/wp-config.php",
        "/phpinfo.php",
        "/debug.log",
        "/.htaccess",
        "/.svn/entries"
        ]

        for f in sensitive_files:

            try:

                res = requests.get(url + f)

                if res.status_code == 200:
                    vulns.append("Sensitive File Exposure " + f)

            except:
                pass


        # ------------------------------------------------
        # HIGH VULNERABILITIES
        # ------------------------------------------------

        # Reflected XSS
        payload = "<script>alert(1)</script>"

        try:

            xss = requests.get(url + "?q=" + payload)

            if payload in xss.text:
                vulns.append("Reflected XSS")

        except:
            pass


        # Open redirect
        try:

            redirect = requests.get(
                url + "?redirect=https://evil.com",
                allow_redirects=False
            )

            if "evil.com" in str(redirect.headers):
                vulns.append("Open Redirect")

        except:
            pass


        # CORS misconfiguration
        try:

            cors = requests.get(url, headers={"Origin":"evil.com"})

            if "Access-Control-Allow-Origin" in cors.headers:
                vulns.append("Possible CORS Misconfiguration")

        except:
            pass


        # Directory listing
        if "index of /" in body:
            vulns.append("Directory Listing Enabled")


        # ------------------------------------------------
        # MEDIUM VULNERABILITIES
        # ------------------------------------------------

        # Admin / directory exposure
        directories = [
        "/admin",
        "/administrator",
        "/login",
        "/dashboard",
        "/uploads",
        "/backup",
        "/config",
        "/private",
        "/test",
        "/api"
        ]

        for d in directories:

            try:

                res = requests.get(url + d)

                if res.status_code == 200:
                    vulns.append("Exposed Directory " + d)

            except:
                pass


        # Debug information
        debug_words = [
        "debug",
        "stack trace",
        "exception",
        "traceback"
        ]

        for word in debug_words:

            if word in body:
                vulns.append("Debug Information Disclosure")


        # ------------------------------------------------
        # LOW VULNERABILITIES
        # ------------------------------------------------

        # Security headers
        security_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Resource-Policy",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Opener-Policy",
        "Expect-CT"
        ]

        for h in security_headers:

            if h not in headers:
                vulns.append("Missing Security Header " + h)


        # HTTPS check
        if url.startswith("http://"):
            vulns.append("Website not using HTTPS")


        # Server disclosure
        if "Server" in headers:
            vulns.append("Server Information Disclosure")


        if "X-Powered-By" in headers:
            vulns.append("Technology Disclosure")


        # Cookie issues
        for cookie in r.cookies:

            if not cookie.secure:
                vulns.append("Cookie without Secure flag")

            if not cookie.has_nonstandard_attr("HttpOnly"):
                vulns.append("Cookie without HttpOnly")


    except:

        vulns.append("Target not reachable")


    return list(set(vulns))
