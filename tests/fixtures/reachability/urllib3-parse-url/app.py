from urllib3.util import parse_url


def host_of(url):
    return parse_url(url).host
