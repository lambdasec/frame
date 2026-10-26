const express = require('express');
const prisma = require('./lib/prisma');
const { Prisma } = require('@prisma/client');
const knex = require('knex')({ client: 'pg', connection: process.env.DATABASE_URL });

const router = express.Router();

router.get('/users', async (req, res) => {
  const name = req.query.name;
  const users = await prisma.$queryRaw`SELECT * FROM "User" WHERE name = ${name}`;
  res.json(users);
});

router.delete('/users/:id', async (req, res) => {
  await prisma.$executeRawUnsafe('DELETE FROM "User" WHERE id = $1', Number(req.params.id));
  res.sendStatus(204);
});

router.get('/orders', async (req, res) => {
  const rows = await knex('orders').whereRaw('status = ?', [req.query.status]);
  res.json(rows);
});

router.get('/report', async (req, res) => {
  const column = ['created_at', 'total'].includes(req.query.sort) ? req.query.sort : 'created_at';
  const rows = await knex.raw('SELECT * FROM reports ORDER BY ??', [column]);
  res.json(rows.rows);
});

module.exports = router;
