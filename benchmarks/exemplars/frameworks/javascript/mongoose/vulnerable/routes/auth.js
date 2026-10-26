const express = require('express');
const User = require('../models/user');

const router = express.Router();

router.post('/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username, password: req.body.password });  // frame-expect: CWE-943
  if (!user) return res.status(401).end();
  res.json({ ok: true });
});

router.get('/lookup', async (req, res) => {
  const users = await User.find({ $where: "this.username == '" + req.query.name + "'" });  // frame-expect: CWE-943
  res.json(users);
});

router.get('/search', async (req, res) => {
  const users = await User.find(req.query);  // frame-expect: CWE-943
  res.json(users);
});

module.exports = router;
