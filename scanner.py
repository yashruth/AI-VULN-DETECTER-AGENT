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

        # CRITICAL
        try:
            sqli = requests.get(url + "?id=' OR 1=1--")
            if "sql" in sqli.text.lower():
                vulns.append("SQL Injection")
        except:
            pass

        for f in ["/.env","/.git/config","/database.sql"]:
            try:
                if requests.get(url + f).status_code == 200:
                    vulns.append("Sensitive File Exposure")
            except:
                pass

        # HIGH
        try:
            xss = requests.get(url + "?q=<script>alert(1)</script>")
            if "<script>" in xss.text:
                vulns.append("XSS")
        except:
            pass

        # MEDIUM
        for d in ["/admin","/login","/dashboard"]:
            try:
                if requests.get(url + d).status_code == 200:
                    vulns.append("Exposed Directory")
            except:
                pass

        # LOW
        if "Content-Security-Policy" not in headers:
            vulns.append("Missing CSP")

        if "X-Frame-Options" not in headers:
            vulns.append("Missing X-Frame")

    except:
        return []

    return list(set(vulns))
