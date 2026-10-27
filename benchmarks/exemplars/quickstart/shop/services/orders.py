import os
import sqlite3


def for_customer(name):
    db = sqlite3.connect("shop.db")
    cur = db.cursor()
    cur.execute("SELECT * FROM orders WHERE customer = '" + name.strip() + "'")
    return cur.fetchall()


def export(fmt):
    os.system("export-orders --format " + fmt)
    return "queued"
