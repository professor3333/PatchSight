from paramiko import RSAKey


def save(key, path):
    RSAKey.write_private_key_file(key, path)
