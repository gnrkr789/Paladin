"""Isolated customer search task."""

TABLE = "customer"


def search(conn, term):
    return conn.execute(
        f"SELECT id, name FROM {TABLE} WHERE name LIKE ?",
        (f"%{term}%",),
    ).fetchall()
