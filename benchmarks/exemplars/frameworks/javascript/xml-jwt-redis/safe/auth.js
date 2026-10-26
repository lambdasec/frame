const express = require('express');
const jwt = require('jsonwebtoken');
const libxmljs = require('libxmljs');
const Redis = require('ioredis');

const router = express.Router();
const redis = new Redis();

router.post('/import', (req, res) => {
  const doc = libxmljs.parseXml(req.body.xml, { noent: false, nonet: true });
  res.json({ root: doc.root().name() });
});

router.get('/me', (req, res) => {
  const token = req.headers.authorization.split(' ')[1];
  const claims = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
  res.json({ user: claims.sub });
});

router.post('/rate', async (req, res) => {
  const count = await redis.eval("return redis.call('incr', KEYS[1])", 1, req.body.key);
  res.json({ count });
});

module.exports = router;
