import httpx
import requests
import urllib3


class Fetcher:
    def __init__(self):
        self.http = requests.Session()
        self.pool = urllib3.PoolManager()

    def preview(self, url):
        resp = self.http.get(url, timeout=5)  # frame-expect: CWE-918
        return {"status": resp.status_code, "length": len(resp.text)}

    def download(self, src):
        with httpx.Client(timeout=5) as client:
            return client.get(src).content  # frame-expect: CWE-918

    def head(self, target):
        return self.pool.request("HEAD", target).status  # frame-expect: CWE-918
