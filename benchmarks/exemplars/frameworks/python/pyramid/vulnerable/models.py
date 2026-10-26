from sqlalchemy import text


def find_user(session, name):
    row = session.execute(text("SELECT * FROM users WHERE name = '" + name + "'")).first()  # frame-expect: CWE-89
    return dict(row) if row else {}


def search_users(session, term):
    q = text("SELECT * FROM users WHERE bio LIKE :term")
    return [dict(r) for r in session.execute(q, {"term": "%" + term + "%"})]
