const express = require('express');
const db = require('../db');

const router = express.Router();

router.get('/search', (req, res) => {
  const term = req.query.q;
  db.query("SELECT id, name FROM users WHERE name LIKE '%" + term + "%'", (err, rows) => {  // frame-expect: CWE-89
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
  res.send('<h1>Hello ' + req.query.name + '</h1>');  // frame-expect: CWE-79
});

router.get('/go', (req, res) => {
  res.redirect(req.query.next);  // frame-expect: CWE-601
});

module.exports = router;
