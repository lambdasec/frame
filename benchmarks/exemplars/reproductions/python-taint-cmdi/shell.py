import os
def run_ping(host):
    os.system("ping -c1 " + host)   # vulnerable: command injection
