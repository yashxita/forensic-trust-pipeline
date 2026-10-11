"""Parser A: the reference parser, built on Python's sqlite3 module (C library)."""
import sqlite3


def parse(db_path, table="messages"):
    if not table.isidentifier():
        raise ValueError("invalid table name")
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        cur = con.execute(f"SELECT * FROM {table} ORDER BY rowid")
        cols = [d[0] for d in cur.description]
        rows = [tuple(r) for r in cur.fetchall()]
    finally:
        con.close()
    return cols, rows
