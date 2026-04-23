import requests

def normalize(url):
    if not url.startswith("http"):
        url = "https://" + url
    return url

def scan(url):

    url = normalize(url)
    vulns = []

    try:
        r = requests.get(url, timeout=10)
        headers = r.headers
        body = r.text.lower()

        # 🔴 CRITICAL VULNS

        # SQL Injection
        try:
            sqli = requests.get(url + "?id=' OR 1=1--")
            errors = ["sql", "mysql", "syntax", "database"]
            if any(e in sqli.text.lower() for e in errors):
                vulns.append("Critical: SQL Injection")
        except:
            pass

        # Command Injection / RCE indicator
        try:
            cmd = requests.get(url + "?cmd=id")
            if "uid=" in cmd.text:
                vulns.append("Critical: Remote Code Execution")
        except:
            pass

        # Sensitive files
        critical_files = [
            "/.env","/.git/config","/database.sql","/backup.zip"
        ]

        for f in critical_files:
            try:
                if requests.get(url + f).status_code == 200:
                    vulns.append("Critical: Sensitive File Exposure " + f)
            except:
                pass


        # 🟠 HIGH

        try:
            xss = requests.get(url + "?q=<script>alert(1)</script>")
            if "<script>" in xss.text:
                vulns.append("High: XSS")
        except:
            pass

        try:
            redirect = requests.get(url + "?redirect=https://evil.com", allow_redirects=False)
            if "evil.com" in str(redirect.headers):
                vulns.append("High: Open Redirect")
        except:
            pass


        # 🟡 MEDIUM

        dirs = ["/admin","/login","/dashboard","/backup","/uploads"]

        for d in dirs:
            try:
                if requests.get(url + d).status_code == 200:
                    vulns.append("Medium: Exposed Directory " + d)
            except:
                pass


        # 🟢 LOW (HEADERS + INFO)

        headers_list = [
            "Content-Security-Policy","X-Frame-Options",
            "Strict-Transport-Security","X-Content-Type-Options",
            "Referrer-Policy"
        ]

        for h in headers_list:
            if h not in headers:
                vulns.append("Low: Missing Header " + h)

        if "server" in headers:
            vulns.append("Low: Server Disclosure")

        if "x-powered-by" in headers:
            vulns.append("Low: Technology Disclosure")

        if url.startswith("http://"):
            vulns.append("Low: No HTTPS")

        if "index of /" in body:
            vulns.append("Medium: Directory Listing Enabled")

    except:
        return []

    return list(set(vulns))
