import psycopg2
import pymysql
from sqlalchemy.orm import Session

from analytics import engine


def monthly(month):
    conn = psycopg2.connect("dbname=shop")
    with conn.cursor() as cur:
        cur.execute("SELECT sum(total) FROM orders WHERE month = %s", (month,))
        return cur.fetchall()


def audit_rows(actor):
    conn = pymysql.connect(host="db", user="app", database="audit")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit WHERE actor = %s", (actor,))
    return cursor.fetchall()


ALLOWED_SCRIPTS = {"VACUUM;", "ANALYZE;"}


def apply_script(script):
    if script not in ALLOWED_SCRIPTS:
        raise ValueError("unknown maintenance script")
    with Session(engine) as session:
        session.connection().connection.executescript(script)
