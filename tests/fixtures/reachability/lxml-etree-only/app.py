from lxml import etree


def parse(xml):
    return etree.fromstring(xml)
