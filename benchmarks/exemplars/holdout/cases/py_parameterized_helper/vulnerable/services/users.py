import sqlite3


def search(term):
    conn = sqlite3.connect('app.db')
    return conn.execute("SELECT * FROM u WHERE name = '%s'" % term).fetchall()
