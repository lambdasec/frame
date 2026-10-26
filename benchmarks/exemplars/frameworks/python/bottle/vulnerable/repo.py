import sqlite3


def find_user(uid):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = " + uid)  # frame-expect: CWE-89
    return cur.fetchone()
