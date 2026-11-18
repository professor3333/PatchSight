from setuptools import find_packages


def packages():
    return find_packages(exclude=["tests"])
