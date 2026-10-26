import sqlite3

conn = sqlite3.connect("app.db", check_same_thread=False)


def get_user(uid):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = " + uid)  # frame-expect: CWE-89
    return cur.fetchone()


def search(q):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name LIKE ?", ("%" + q + "%",))
    return cur.fetchall()
