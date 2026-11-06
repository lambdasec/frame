from store import load_session
def restore(cookie):           # entry point: cookie is client-controlled
    return load_session(cookie)
