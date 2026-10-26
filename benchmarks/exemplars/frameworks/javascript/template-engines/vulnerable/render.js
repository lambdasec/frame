const express = require('express');
const ejs = require('ejs');
const pug = require('pug');
const Handlebars = require('handlebars');
const nunjucks = require('nunjucks');
const _ = require('lodash');

const router = express.Router();

router.post('/preview/ejs', (req, res) => {
  const template = req.body.template;
  res.type('text').send(ejs.render(template, { user: req.user }));  // frame-expect: CWE-1336
});

router.post('/preview/pug', (req, res) => {
  const fn = pug.compile(req.body.template);  // frame-expect: CWE-1336
  res.type('text').send(fn({ user: req.user }));
});

router.post('/preview/hbs', (req, res) => {
  const tpl = Handlebars.compile(req.body.template);  // frame-expect: CWE-1336
  res.type('text').send(tpl({ user: req.user }));
});

router.post('/preview/njk', (req, res) => {
  const template = req.body.template;
  res.type('text').send(nunjucks.renderString(template, { user: req.user }));  // frame-expect: CWE-1336
});

router.post('/preview/lodash', (req, res) => {
  const compiled = _.template(req.body.template);  // frame-expect: CWE-1336
  res.type('text').send(compiled({ user: req.user }));
});

module.exports = router;
