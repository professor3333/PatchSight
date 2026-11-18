from sqlparse import tokens


def is_keyword(ttype):
    return ttype in tokens.Keyword
