import paramiko


def run(host, command):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.connect(host)
    return client.exec_command(command)
