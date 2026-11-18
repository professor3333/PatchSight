import sqlparse


def statements(sql):
    return sqlparse.parse(sql)
