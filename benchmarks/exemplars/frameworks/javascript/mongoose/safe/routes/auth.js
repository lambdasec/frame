const express = require('express');
const User = require('../models/user');

const router = express.Router();

router.post('/login', async (req, res) => {
  const username = String(req.body.username);
  const password = String(req.body.password);
  const user = await User.findOne({ username, password });
  if (!user) return res.status(401).end();
  res.json({ ok: true });
});

router.get('/lookup', async (req, res) => {
  const name = String(req.query.name);
  const users = await User.find({ username: name });
  res.json(users);
});

router.get('/search', async (req, res) => {
  const users = await User.find({ role: String(req.query.role) });
  res.json(users);
});

module.exports = router;
