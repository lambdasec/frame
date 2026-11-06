import subprocess
def tail_log(name):
    # CWE-78: shell=True with attacker data (real stdlib subprocess)
    return subprocess.call("tail /var/log/" + name, shell=True)
