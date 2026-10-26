import aiosqlite


async def get_item(item_id):
    async with aiosqlite.connect("shop.db") as db:
        cur = await db.execute("SELECT * FROM items WHERE id = " + item_id)  # frame-expect: CWE-89
        return await cur.fetchone()


async def search(term):
    async with aiosqlite.connect("shop.db") as db:
        cur = await db.execute("SELECT * FROM items WHERE name LIKE ?", ("%" + term + "%",))
        return await cur.fetchall()
