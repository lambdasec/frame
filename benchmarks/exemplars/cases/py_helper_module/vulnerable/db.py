import sqlite3


def find_user(name):
    conn = sqlite3.connect('app.db')
    return conn.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall()
