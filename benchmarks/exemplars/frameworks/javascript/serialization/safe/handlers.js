const express = require('express');
const yaml = require('js-yaml');
const vm = require('vm');
const { evaluate } = require('mathjs');

const router = express.Router();

router.post('/session/restore', (req, res) => {
  const session = JSON.parse(req.cookies.session);
  res.json(session);
});

router.post('/config/import', (req, res) => {
  const cfg = yaml.load(req.body.yaml, { schema: yaml.JSON_SCHEMA });
  res.json(cfg);
});

const FORMULAS = { area: 'w * h', perimeter: '2 * (w + h)' };

router.post('/formula', (req, res) => {
  const name = req.body.name;
  if (!(name in FORMULAS)) return res.sendStatus(400);
  res.json({ result: vm.runInNewContext(FORMULAS[name], { w: 2, h: 3 }) });
});

router.post('/script', (req, res) => {
  res.json({ result: evaluate(String(req.body.code)) });
});

router.post('/calc', (req, res) => {
  const factor = Number(req.body.factor);
  const fn = new Function('a', 'b', 'return a * b * ' + factor);
  res.json({ v: fn(1, 2) });
});

module.exports = router;
