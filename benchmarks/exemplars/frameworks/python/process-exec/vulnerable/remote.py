import paramiko
from fabric import Connection


def disk_usage(host, path):
    client = paramiko.SSHClient()
    client.connect(host, username="ops")
    stdin, stdout, stderr = client.exec_command("du -sh " + path)  # frame-expect: CWE-78
    return stdout.read().decode()


def deploy(branch):
    conn = Connection("deploy.internal")
    result = conn.run("git checkout " + branch + " && ./release.sh")  # frame-expect: CWE-78
    return result.stdout
