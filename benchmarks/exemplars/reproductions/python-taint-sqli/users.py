from db import Cursor
def find_user(name):                # entry point
    c = Cursor()
    return c.execute("SELECT * FROM users WHERE name = '" + name + "'")
