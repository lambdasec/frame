from databases import Database

database = Database("sqlite:///notes.db")


async def get_note(note_id):
    return await database.fetch_one("SELECT * FROM notes WHERE id = :id", {"id": note_id})


async def search(term):
    return await database.fetch_all("SELECT * FROM notes WHERE body LIKE :t", {"t": "%" + term + "%"})
