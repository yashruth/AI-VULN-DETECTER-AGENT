import requests

def find_subdomains(domain):

    subs = ["admin","api","dev","test"]

    found = []

    for s in subs:
        url = f"https://{s}.{domain}"

        try:
            if requests.get(url, timeout=3).status_code < 400:
                found.append(url)
        except:
            pass

    return found
