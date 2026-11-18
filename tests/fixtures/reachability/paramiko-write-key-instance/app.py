import paramiko


def new_key(path):
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    return key
