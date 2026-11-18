from langgraph.store.sqlite import SqliteStore


def find(conn, kind):
    store = SqliteStore(conn)
    return store.search(("docs",), filter={"kind": kind})
