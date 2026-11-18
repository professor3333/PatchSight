import yaml


def read_config(text, trusted):
    loader = "full_load" if trusted else "safe_load"
    return getattr(yaml, loader)(text)
