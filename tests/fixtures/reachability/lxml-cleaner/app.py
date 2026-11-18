from lxml.html.clean import Cleaner


def sanitise(html):
    return Cleaner(javascript=True, style=True).clean_html(html)
