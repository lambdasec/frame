from django.db import connection


def search_articles(term):
    with connection.cursor() as cursor:
        cursor.execute("SELECT id, title FROM articles WHERE title LIKE %s", ["%" + term + "%"])
        return cursor.fetchall()
