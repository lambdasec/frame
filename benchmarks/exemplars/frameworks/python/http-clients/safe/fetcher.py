import httpx
import requests
import urllib3

ALLOWED_URLS = {
    "https://images.partner.example/logo.png",
    "https://api.partner.example/v1/status",
}


class Fetcher:
    def __init__(self):
        self.http = requests.Session()
        self.pool = urllib3.PoolManager()

    def preview(self, url):
        if url not in ALLOWED_URLS:
            raise ValueError("url not allowed")
        resp = self.http.get(url, timeout=5)
        return {"status": resp.status_code, "length": len(resp.text)}

    def download(self, src):
        if src not in ALLOWED_URLS:
            raise ValueError("url not allowed")
        with httpx.Client(timeout=5) as client:
            return client.get(src).content

    def head(self, target):
        if target not in ALLOWED_URLS:
            raise ValueError("url not allowed")
        return self.pool.request("HEAD", target).status
