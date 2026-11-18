import urllib3


def fetch(url, cookie):
    http = urllib3.PoolManager()
    return http.request("GET", url, headers={"Cookie": cookie})
