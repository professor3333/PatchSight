from lxml.html import clean


def sanitise(html):
    return clean.clean_html(html)
