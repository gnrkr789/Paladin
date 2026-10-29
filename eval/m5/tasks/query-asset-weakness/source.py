"""Isolated asset search task."""

TABLE = "asset"


def search(conn, term):
    return conn.execute(
        f"SELECT id, name FROM {TABLE} WHERE name LIKE '%{term}%'"
    ).fetchall()
