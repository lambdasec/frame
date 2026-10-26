import httpx

_client = httpx.AsyncClient()


async def notify_async(url, payload):
    await _client.post(url, json=payload)  # frame-expect: CWE-918


def notify(url, payload):
    with httpx.Client() as client:
        client.post(url, json=payload)  # frame-expect: CWE-918
