const express = require('express');
const escapeHtml = require('escape-html');
const db = require('../db');

const router = express.Router();

router.get('/search', (req, res) => {
  const term = req.query.q;
  db.query("SELECT id, name FROM users WHERE name LIKE ?", ['%' + term + '%'], (err, rows) => {
    res.json(rows);
  });
});

router.get('/echo', (req, res) => {
  res.status(200).json({ q: req.query.q });
});

router.get('/plain', (req, res) => {
  res.type('text').send('You searched for ' + req.query.q);
});

router.get('/greet', (req, res) => {
  res.send('<h1>Hello ' + escapeHtml(req.query.name) + '</h1>');
});

router.get('/go', (req, res) => {
  const next = req.query.next;
  if (typeof next === 'string' && next.startsWith('/') && !next.startsWith('//')) {
    return res.redirect(next);
  }
  res.redirect('/');
});

module.exports = router;
