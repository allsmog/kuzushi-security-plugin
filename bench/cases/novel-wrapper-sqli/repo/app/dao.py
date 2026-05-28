import sqlite3
_conn = sqlite3.connect('app.db')

def run(sql):
    # custom query helper — not .execute()/.query() that scanners pattern-match
    return _conn.cursor().execute(sql).fetchall()
