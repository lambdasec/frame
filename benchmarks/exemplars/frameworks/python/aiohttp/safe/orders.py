import asyncpg

async def fetch(pool: asyncpg.Pool, order_id):
    async with pool.acquire() as conn:
        return await conn.fetchrow("SELECT * FROM orders WHERE id = $1", int(order_id))


async def by_status(pool: asyncpg.Pool, status):
    async with pool.acquire() as conn:
        return await conn.fetch("SELECT * FROM orders WHERE status = $1", status)
