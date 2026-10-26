const express = require('express');
const jwt = require('jsonwebtoken');
const libxmljs = require('libxmljs');
const Redis = require('ioredis');

const router = express.Router();
const redis = new Redis();

router.post('/import', (req, res) => {
  const doc = libxmljs.parseXml(req.body.xml, { noent: true });  // frame-expect: CWE-611
  res.json({ root: doc.root().name() });
});

router.get('/me', (req, res) => {
  const token = req.headers.authorization.split(' ')[1];
  const claims = jwt.decode(token);  // frame-expect: CWE-863
  res.json({ user: claims.sub });
});

router.post('/rate', async (req, res) => {
  const count = await redis.eval("return redis.call('incr', '" + req.body.key + "')", 0);  // frame-expect: CWE-94
  res.json({ count });
});

module.exports = router;
