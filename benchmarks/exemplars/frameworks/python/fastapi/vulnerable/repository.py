from sqlalchemy import text


class ProductRepository:
    def __init__(self, session):
        self.session = session

    def search(self, term):
        sql = text("SELECT * FROM products WHERE name LIKE '%" + term + "%'")  # frame-expect: CWE-89
        return self.session.execute(sql).fetchall()

    def by_category(self, category):
        stmt = text(f"SELECT * FROM products WHERE category = '{category}'")  # frame-expect: CWE-89
        return self.session.execute(stmt).fetchall()

    def by_sku(self, sku):
        return self.session.execute(text("SELECT * FROM products WHERE sku = :sku"), {"sku": sku}).fetchone()
