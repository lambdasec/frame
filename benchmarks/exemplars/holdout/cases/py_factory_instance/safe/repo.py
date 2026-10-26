import sqlite3


class Repo:
    def find(self, name):
        return sqlite3.connect('a.db').execute("SELECT * FROM u WHERE n = '%s'" % name).fetchall()


def make_repo():
    return Repo()
