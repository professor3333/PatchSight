from langgraph.checkpoint.sqlite import SqliteSaver


def checkpointer(conn):
    return SqliteSaver(conn)
