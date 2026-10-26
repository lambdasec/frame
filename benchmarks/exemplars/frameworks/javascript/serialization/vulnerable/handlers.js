const express = require('express');
const serialize = require('node-serialize');
const yaml = require('js-yaml');
const vm = require('vm');
const { Script } = require('vm');

const router = express.Router();

router.post('/session/restore', (req, res) => {
  const session = serialize.unserialize(req.cookies.session);  // frame-expect: CWE-502
  res.json(session);
});

router.post('/config/import', (req, res) => {
  const cfg = yaml.load(req.body.yaml, { schema: yaml.DEFAULT_FULL_SCHEMA });  // frame-expect: CWE-502
  res.json(cfg);
});

router.post('/formula', (req, res) => {
  const result = vm.runInNewContext(req.body.expression, { Math });  // frame-expect: CWE-94
  res.json({ result });
});

router.post('/script', (req, res) => {
  const script = new Script(req.body.code);  // frame-expect: CWE-94
  res.json(script.runInNewContext({}));
});

router.post('/calc', (req, res) => {
  const fn = new Function('a', 'b', 'return ' + req.body.formula);  // frame-expect: CWE-94
  res.json({ v: fn(1, 2) });
});

module.exports = router;
