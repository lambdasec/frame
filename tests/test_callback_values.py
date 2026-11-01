"""A database library hands its callbacks a value of its own: knex's transaction handler gets a
transaction (used as a knex instance), pg-promise's task / tx callbacks a task with every query
method, a mysql or pg pool's checkout callback a connection, TypeORM's transaction an
EntityManager. The packs say so with `[[callback_param]]`; the parameter's name decides nothing."""

import pytest

from frame.sil.scanner import FrameScanner

APP = """const express = require('express');
const app = express();
{SETUP}
app.get('/u', (req, res) => {
  {BODY}
});
"""


def _sql(setup, body):
    code = APP.replace("{SETUP}", setup).replace("{BODY}", body)
    return [v.line for v in FrameScanner(language="javascript", verify=False).scan(code, "app.js").vulnerabilities
            if v.cwe_id == "CWE-89"]


KNEX = "const knex = require('knex')({ client: 'pg' });"
KNEX_MODULE = "const Knex = require('knex');\nconst knex = Knex({ client: 'pg' });"
PGP = "const pgp = require('pg-promise')();\nconst db = pgp('postgres://db');"
MYSQL = "const mysql = require('mysql');\nconst pool = mysql.createPool({ host: 'db' });"
MYSQL2 = "const mysql = require('mysql2');\nconst pool = mysql.createPool({ host: 'db' });"
PG = "const { Pool } = require('pg');\nconst pool = new Pool();"
TYPEORM = "const { DataSource } = require('typeorm');\nconst ds = new DataSource({ type: 'postgres' });"
Q = "\"SELECT * FROM u WHERE n = '\" + req.query.n + \"'\""


@pytest.mark.parametrize("setup, body", [
    (KNEX, "knex.transaction(async (trx) => { await trx.raw(Q); });"),
    (KNEX, "knex.transaction(async (t) => { await t('users').whereRaw(Q); });"),
    (KNEX_MODULE, "knex.transaction(async (trx) => { await trx.raw(Q); });"),
    (PGP, "db.task(async (t) => t.any(Q));"),
    (PGP, "db.tx('named', async (t) => t.none(Q));"),
    (PGP, "db.tx(async (t) => t.task(async (t2) => t2.one(Q)));"),       # nested: a task of a task
    (MYSQL, "pool.getConnection((err, conn) => { conn.query(Q); conn.release(); });"),
    (MYSQL2, "pool.getConnection((err, c) => { c.query(Q); });"),
    (PG, "pool.connect((err, client, release) => { client.query(Q); release(); });"),
    (TYPEORM, "ds.transaction(async (manager) => manager.query(Q));"),
    (TYPEORM, "ds.transaction('SERIALIZABLE', async (em) => em.query(Q));"),
])
def test_the_callback_gets_the_librarys_value(setup, body):
    assert _sql(setup, body.replace("Q", Q)) == [4 + setup.count("\n") + 1]


@pytest.mark.parametrize("setup, body", [
    (KNEX, "knex.transaction(async (trx) => { await trx.raw('SELECT * FROM u WHERE n = ?', [req.query.n]); });"),
    (PGP, "db.task(async (t) => t.any('SELECT * FROM u WHERE n = $1', [req.query.n]));"),
    (PG, "pool.connect((err, client, release) => { client.query('SELECT * FROM u WHERE n = $1', [req.query.n]); });"),
])
def test_parameterised_queries_in_the_callback_are_clean(setup, body):
    assert _sql(setup, body) == []


def test_a_callback_of_something_else_gets_nothing():
    setup = "const jobs = require('./jobs');"
    body = "jobs.task(async (t) => t.any(" + Q + "));"
    assert _sql(setup, body) == []
