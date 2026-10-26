import asyncpg

async def fetch(pool: asyncpg.Pool, order_id):
    async with pool.acquire() as conn:
        return await conn.fetchrow("SELECT * FROM orders WHERE id = " + order_id)  # frame-expect: CWE-89


async def by_status(pool: asyncpg.Pool, status):
    async with pool.acquire() as conn:
        return await conn.fetch(f"SELECT * FROM orders WHERE status = '{status}'")  # frame-expect: CWE-89
