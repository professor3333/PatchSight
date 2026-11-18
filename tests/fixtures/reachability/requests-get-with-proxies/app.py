import requests


def fetch(url, proxy):
    return requests.get(url, proxies={"https": proxy}, timeout=10)
