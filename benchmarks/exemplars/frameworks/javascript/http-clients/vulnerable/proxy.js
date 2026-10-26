const express = require('express');
const axios = require('axios');
const got = require('got');
const fetch = require('node-fetch');
const superagent = require('superagent');
const needle = require('needle');

const router = express.Router();

router.get('/preview', async (req, res) => {
  const page = await axios.get(req.query.url);  // frame-expect: CWE-918
  res.type('text').send(String(page.data).slice(0, 200));
});

router.get('/avatar', async (req, res) => {
  const body = await got(req.query.src).buffer();  // frame-expect: CWE-918
  res.send(body);
});

router.post('/webhook-test', async (req, res) => {
  const r = await fetch(req.body.callback, { method: 'POST' });  // frame-expect: CWE-918
  res.json({ status: r.status });
});

router.get('/feed', async (req, res) => {
  const r = await superagent.get(req.query.feed);  // frame-expect: CWE-918
  res.json(r.body);
});

router.get('/headers', (req, res) => {
  needle.get(req.query.host, (err, resp) => {  // frame-expect: CWE-918
    res.json(resp.headers);
  });
});

router.get('/config', async (req, res) => {
  const r = await axios({ url: req.query.endpoint, method: 'get' });  // frame-expect: CWE-918
  res.json(r.data);
});

module.exports = router;
