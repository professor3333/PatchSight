from urllib3.util import Retry


def policy():
    return Retry(total=3, redirect=2)
