import httpx

REGISTERED_HOOKS = {"https://hooks.partner.example/created"}

_client = httpx.AsyncClient()


async def notify_async(url, payload):
    if url not in REGISTERED_HOOKS:
        raise ValueError("callback not registered")
    await _client.post(url, json=payload)


def notify(url, payload):
    if url not in REGISTERED_HOOKS:
        raise ValueError("callback not registered")
    with httpx.Client() as client:
        client.post(url, json=payload)
