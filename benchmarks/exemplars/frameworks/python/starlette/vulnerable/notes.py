from databases import Database

database = Database("sqlite:///notes.db")


async def get_note(note_id):
    return await database.fetch_one(f"SELECT * FROM notes WHERE id = {note_id}")  # frame-expect: CWE-89


async def search(term):
    return await database.fetch_all("SELECT * FROM notes WHERE body LIKE '%" + term + "%'")  # frame-expect: CWE-89
