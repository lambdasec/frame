import shlex

import paramiko
from fabric import Connection


def disk_usage(host, path):
    client = paramiko.SSHClient()
    client.connect(host, username="ops")
    stdin, stdout, stderr = client.exec_command("du -sh " + shlex.quote(path))
    return stdout.read().decode()


def deploy(branch):
    conn = Connection("deploy.internal")
    result = conn.run("git checkout " + shlex.quote(branch) + " && ./release.sh")
    return result.stdout
