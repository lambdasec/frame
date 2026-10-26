import psycopg2
import pymysql
from sqlalchemy.orm import Session

from analytics import engine


def monthly(month):
    conn = psycopg2.connect("dbname=shop")
    with conn.cursor() as cur:
        cur.execute("SELECT sum(total) FROM orders WHERE month = '%s'" % month)  # frame-expect: CWE-89
        return cur.fetchall()


def audit_rows(actor):
    conn = pymysql.connect(host="db", user="app", database="audit")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM audit WHERE actor = '{actor}'")  # frame-expect: CWE-89
    return cursor.fetchall()


def apply_script(script):
    with Session(engine) as session:
        session.connection().connection.executescript(script)  # frame-expect: CWE-89
