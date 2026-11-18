import sqlparse as sp


def pretty(sql):
    return sp.format(sql, reindent=True, keyword_case="upper")
