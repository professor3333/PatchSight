"""``patchsight report``: a pre-filled GitHub issue saying an advisory's symbol data is wrong.

Nothing is sent. The command builds the URL of a draft issue on the "wrong symbol data"
form, filled with the advisory ID and the local ``patchsight explain`` output, and opens it
in the browser for the user to review, complete and submit. The URL holds database
content only: never the user's code, paths or dependencies (design rule 2).
"""

from urllib.parse import urlencode

ISSUES = "https://github.com/professor3333/PatchSight/issues/new"
TEMPLATE = "wrong_symbols.yml"
# Browsers and GitHub accept long URLs, but not unbounded ones; keep well below 8 KB.
MAX_URL = 7_000
TRUNCATED = "\n[... truncated: run `patchsight explain {identifier}` for the rest]"


def issue_url(identifier: str, explanation: str) -> str:
    """The draft issue's URL, with the explanation shortened to fit if it must be."""

    def build(text: str) -> str:
        fields = {
            "template": TEMPLATE,
            "title": f"Wrong symbol data: {identifier}",
            "advisory": identifier,
            "explain": text,
        }
        return f"{ISSUES}?{urlencode(fields)}"

    url = build(explanation)
    if len(url) <= MAX_URL:
        return url
    note = TRUNCATED.format(identifier=identifier)
    low, high = 0, len(explanation)
    while low < high:  # the longest prefix that fits
        middle = (low + high + 1) // 2
        if len(build(explanation[:middle] + note)) <= MAX_URL:
            low = middle
        else:
            high = middle - 1
    return build(explanation[:low] + note)
