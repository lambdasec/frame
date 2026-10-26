import sqlite3


class UserRepo:
    def find(self, name):
        return sqlite3.connect('app.db').execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall()
