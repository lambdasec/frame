import sqlite3

DB = sqlite3.connect("users.db")


def lookup(username):
    cur = DB.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cur.fetchone()


def update_bio(username, bio):
    DB.execute("UPDATE users SET bio = ? WHERE name = ?", (bio, username))
    return {"ok": True}
