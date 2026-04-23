import requests
from bs4 import BeautifulSoup

def crawl(url):

    urls = set()

    try:
        r = requests.get(url)
        soup = BeautifulSoup(r.text, "html.parser")

        for link in soup.find_all("a"):
            href = link.get("href")

            if href and href.startswith("/"):
                urls.add(url.rstrip("/") + href)

    except:
        pass

    return list(urls)
