from sqlalchemy import text


class ProductRepository:
    def __init__(self, session):
        self.session = session

    def search(self, term):
        sql = text("SELECT * FROM products WHERE name LIKE :t")
        return self.session.execute(sql, {"t": "%" + term + "%"}).fetchall()

    def by_category(self, category):
        stmt = text("SELECT * FROM products WHERE category = :c")
        return self.session.execute(stmt, {"c": category}).fetchall()

    def by_sku(self, sku):
        return self.session.execute(text("SELECT * FROM products WHERE sku = :sku"), {"sku": sku}).fetchone()
