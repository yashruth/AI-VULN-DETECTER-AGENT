import requests
from bs4 import BeautifulSoup

def crawl(url):

    urls = []

    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")

        for link in soup.find_all("a"):
            href = link.get("href")

            if href and href.startswith("/"):
                urls.append(url + href)

    except:
        pass

    return list(set(urls))