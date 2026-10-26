const express = require('express');
const prisma = require('./lib/prisma');
const { Prisma } = require('@prisma/client');
const knex = require('knex')({ client: 'pg', connection: process.env.DATABASE_URL });

const router = express.Router();

router.get('/users', async (req, res) => {
  const users = await prisma.$queryRawUnsafe('SELECT * FROM "User" WHERE name = \'' + req.query.name + '\'');  // frame-expect: CWE-89
  res.json(users);
});

router.delete('/users/:id', async (req, res) => {
  await prisma.$executeRawUnsafe(`DELETE FROM "User" WHERE id = ${req.params.id}`);  // frame-expect: CWE-89
  res.sendStatus(204);
});

router.get('/orders', async (req, res) => {
  const rows = await knex('orders').whereRaw("status = '" + req.query.status + "'");  // frame-expect: CWE-89
  res.json(rows);
});

router.get('/report', async (req, res) => {
  const rows = await knex.raw('SELECT * FROM reports ORDER BY ' + req.query.sort);  // frame-expect: CWE-89
  res.json(rows.rows);
});

module.exports = router;
