import sqlite3

DB = sqlite3.connect("users.db")


def lookup(username):
    cur = DB.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % username)  # frame-expect: CWE-89
    return cur.fetchone()


def update_bio(username, bio):
    DB.execute("UPDATE users SET bio = ? WHERE name = ?", (bio, username))
    return {"ok": True}
