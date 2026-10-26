import sqlite3


class UserRepo:
    def __init__(self):
        self.conn = sqlite3.connect('app.db')

    def find(self, name):
        return self.conn.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall()
