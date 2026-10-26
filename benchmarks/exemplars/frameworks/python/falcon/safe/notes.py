import sqlite3


class NoteStore:
    def __init__(self, path):
        self.db = sqlite3.connect(path)

    def search(self, term):
        cur = self.db.cursor()
        cur.execute("SELECT * FROM notes WHERE title LIKE ?", ("%" + term + "%",))
        return cur.fetchall()

    def by_id(self, note_id):
        cur = self.db.cursor()
        cur.execute("SELECT * FROM notes WHERE id = ?", (note_id,))
        return cur.fetchone()

    def add(self, title, text):
        self.db.execute("INSERT INTO notes (title, text) VALUES (?, ?)", (title, text))
