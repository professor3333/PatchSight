"""Reads configuration. Never use yaml.full_load here: see the security notes."""

import yaml


# yaml.full_load would construct arbitrary Python objects.
def read_config(text):
    return yaml.safe_load(text)
