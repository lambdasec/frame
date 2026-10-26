const express = require('express');
const axios = require('axios');
const got = require('got');
const fetch = require('node-fetch');
const superagent = require('superagent');
const needle = require('needle');

const router = express.Router();

const ALLOWED = ['https://status.example.com/page', 'https://cdn.example.com/avatar.png', 'https://hooks.example.com/test'];

router.get('/preview', async (req, res) => {
  const url = req.query.url;
  if (!ALLOWED.includes(url)) return res.sendStatus(400);
  const page = await axios.get(url);
  res.type('text').send(String(page.data).slice(0, 200));
});

router.get('/avatar', async (req, res) => {
  const src = req.query.src;
  if (!ALLOWED.includes(src)) return res.sendStatus(400);
  const body = await got(src).buffer();
  res.send(body);
});

router.post('/webhook-test', async (req, res) => {
  const callback = req.body.callback;
  if (!ALLOWED.includes(callback)) return res.sendStatus(400);
  const r = await fetch(callback, { method: 'POST' });
  res.json({ status: r.status });
});

router.get('/feed', async (req, res) => {
  const feed = req.query.feed;
  if (!ALLOWED.includes(feed)) return res.sendStatus(400);
  const r = await superagent.get(feed);
  res.json(r.body);
});

router.get('/headers', (req, res) => {
  const host = req.query.host;
  if (!ALLOWED.includes(host)) return res.sendStatus(400);
  needle.get(host, (err, resp) => {
    res.json(resp.headers);
  });
});

router.get('/config', async (req, res) => {
  const endpoint = req.query.endpoint;
  if (!ALLOWED.includes(endpoint)) return res.sendStatus(400);
  const r = await axios({ url: endpoint, method: 'get' });
  res.json(r.data);
});

module.exports = router;
