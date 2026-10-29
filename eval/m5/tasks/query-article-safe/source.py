"""Isolated article search task."""

TABLE = "article"


def search(conn, term):
    return conn.execute(
        f"SELECT id, name FROM {TABLE} WHERE name LIKE ?",
        (f"%{term}%",),
    ).fetchall()
