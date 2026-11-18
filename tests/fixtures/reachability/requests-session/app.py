import requests


def statuses(urls):
    with requests.Session() as session:
        return [session.get(url, timeout=10).status_code for url in urls]
