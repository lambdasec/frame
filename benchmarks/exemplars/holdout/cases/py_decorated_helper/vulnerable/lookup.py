import functools
import os


@functools.lru_cache(maxsize=32)
def resolve(host):
    return os.popen('nslookup ' + host).read()
