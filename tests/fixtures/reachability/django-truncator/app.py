from django.utils.text import Truncator


def summary(text):
    return Truncator(text).words(30, html=True)
