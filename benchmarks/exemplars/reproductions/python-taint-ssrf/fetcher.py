import urllib.request
def fetch(url):
    # CWE-918: attacker-controlled URL to the HTTP client
    return urllib.request.urlopen(url)
