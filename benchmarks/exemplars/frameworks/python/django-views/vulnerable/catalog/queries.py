from django.db import connection

from catalog.models import Product


def in_category(category):
    return list(Product.objects.raw("SELECT * FROM catalog_product WHERE category = '" + category + "'"))  # frame-expect: CWE-89


def count_all():
    with connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM catalog_product")
        return cursor.fetchone()[0]
