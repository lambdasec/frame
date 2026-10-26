import peewee
from pony import orm

db = peewee.SqliteDatabase("people.db")
pony_db = orm.Database()


class Person(peewee.Model):
    name = peewee.CharField()
    city = peewee.CharField()

    class Meta:
        database = db


def search_people(name):
    cursor = db.execute_sql("SELECT name, city FROM person WHERE name = ?", (name,))
    return cursor.fetchall()


@orm.db_session
def by_city(city):
    return pony_db.select("SELECT * FROM person WHERE city = $city")
