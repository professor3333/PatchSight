from setuptools.package_index import PackageIndex


def fetch(url, folder):
    return PackageIndex().download(url, folder)
