from sqlalchemy import text


def find_user(session, name):
    row = session.execute(text("SELECT * FROM users WHERE name = :n"), {"n": name}).first()
    return dict(row) if row else {}


def search_users(session, term):
    q = text("SELECT * FROM users WHERE bio LIKE :term")
    return [dict(r) for r in session.execute(q, {"term": "%" + term + "%"})]
