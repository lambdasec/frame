import os


def ping(host):
    return os.system('ping -c1 ' + host)
