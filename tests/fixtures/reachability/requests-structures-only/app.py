from requests.structures import CaseInsensitiveDict


def headers(pairs):
    return CaseInsensitiveDict(pairs)
