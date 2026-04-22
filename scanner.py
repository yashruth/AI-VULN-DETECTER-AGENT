import requests

# payloads
xss_payload = "<script>alert(1)</script>"
sql_payload = "' OR 1=1--"

# directories to scan
directories = [
"/admin","/administrator","/login","/dashboard","/backup",
"/uploads","/private","/test","/config","/api"
]

# sensitive files
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
"/robots.txt"
]

# security headers
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


def scan(url):

    vulns = []

    try:

        r = requests.get(url, timeout=5)
        headers = r.headers

        # --------------------------------
        # SECURITY HEADER CHECKS
        # --------------------------------

        for header in security_headers:

            if header not in headers:
                vulns.append(f"Missing Security Header: {header}")

        # --------------------------------
        # HTTPS CHECK
        # --------------------------------

        if url.startswith("http://"):
            vulns.append("Website not using HTTPS")

        # --------------------------------
        # SERVER DISCLOSURE
        # --------------------------------

        if "Server" in headers:
            vulns.append("Server Information Disclosure")

        if "X-Powered-By" in headers:
            vulns.append("Technology Disclosure")

        # --------------------------------
        # COOKIE SECURITY
        # --------------------------------

        for cookie in r.cookies:

            if not cookie.secure:
                vulns.append("Cookie without Secure flag")

            if not cookie.has_nonstandard_attr("HttpOnly"):
                vulns.append("Cookie without HttpOnly")

        # --------------------------------
        # DIRECTORY DISCOVERY
        # --------------------------------

        for d in directories:

            try:

                res = requests.get(url + d, timeout=3)

                if res.status_code == 200:
                    vulns.append("Exposed Directory: " + d)

            except:
                pass

        # --------------------------------
        # SENSITIVE FILE DISCOVERY
        # --------------------------------

        for f in sensitive_files:

            try:

                res = requests.get(url + f, timeout=3)

                if res.status_code == 200:
                    vulns.append("Sensitive File Exposed: " + f)

            except:
                pass

        # --------------------------------
        # SQL INJECTION INDICATOR
        # --------------------------------

        try:

            test = requests.get(url + "?id=" + sql_payload)

            sql_errors = [
            "sql syntax",
            "mysql",
            "database error",
            "warning: mysql"
            ]

            for error in sql_errors:

                if error in test.text.lower():
                    vulns.append("Possible SQL Injection")
                    break

        except:
            pass

        # --------------------------------
        # XSS TEST
        # --------------------------------

        try:

            xss_test = requests.get(url + "?q=" + xss_payload)

            if xss_payload in xss_test.text:
                vulns.append("Possible Reflected XSS")

        except:
            pass

        # --------------------------------
        # CORS MISCONFIGURATION
        # --------------------------------

        try:

            cors_headers = {"Origin": "evil.com"}

            cors_test = requests.get(url, headers=cors_headers)

            if "Access-Control-Allow-Origin" in cors_test.headers:
                vulns.append("Possible CORS Misconfiguration")

        except:
            pass

        # --------------------------------
        # OPEN REDIRECT
        # --------------------------------

        try:

            redirect = requests.get(
                url + "?redirect=https://evil.com",
                allow_redirects=False
            )

            if "evil.com" in str(redirect.headers):
                vulns.append("Open Redirect Vulnerability")

        except:
            pass

        # --------------------------------
        # DEBUG MODE / ERROR DISCLOSURE
        # --------------------------------

        debug_words = [
        "stack trace",
        "debug mode",
        "exception occurred",
        "traceback"
        ]

        for word in debug_words:

            if word in r.text.lower():
                vulns.append("Debug Information Disclosure")

        # --------------------------------
        # DIRECTORY LISTING
        # --------------------------------

        if "index of /" in r.text.lower():
            vulns.append("Directory Listing Enabled")
            # CRITICAL FILE EXPOSURE

critical_files = [
"/.env",
"/.git/config",
"/config.php",
"/backup.zip",
"/database.sql"
]

for file in critical_files:

    try:

        r = requests.get(url + file, timeout=3)

        if r.status_code == 200:
            vulns.append("Critical: Sensitive File Exposure " + file)

    except:
        pass

    except:

        vulns.append("Target not reachable")

    return list(set(vulns))
