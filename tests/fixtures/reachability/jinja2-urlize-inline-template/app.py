from jinja2 import Environment

ENV = Environment(autoescape=True)


def linkify(text):
    return ENV.from_string("{{ text|urlize }}").render(text=text)
