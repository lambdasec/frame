const express = require('express');
const ejs = require('ejs');
const pug = require('pug');
const Handlebars = require('handlebars');
const nunjucks = require('nunjucks');
const _ = require('lodash');

const router = express.Router();

const TEMPLATES = {
  welcome: 'Hello <%= user.name %>',
  invoice: 'Invoice for <%= user.name %>',
};

router.post('/preview/ejs', (req, res) => {
  res.type('text').send(ejs.render(TEMPLATES.welcome, { user: req.user, note: req.body.template }));
});

router.post('/preview/pug', (req, res) => {
  const fn = pug.compile('p Hello #{user.name}');
  res.type('text').send(fn({ user: req.user, note: req.body.template }));
});

router.post('/preview/hbs', (req, res) => {
  const tpl = Handlebars.compile('Hello {{user.name}} {{note}}');
  res.type('text').send(tpl({ user: req.user, note: req.body.template }));
});

router.post('/preview/njk', (req, res) => {
  res.type('text').send(nunjucks.renderString('Hello {{ user.name }} {{ note }}', { user: req.user, note: req.body.template }));
});

router.post('/preview/lodash', (req, res) => {
  const compiled = _.template('Hello <%- user.name %> <%- note %>');
  res.type('text').send(compiled({ user: req.user, note: req.body.template }));
});

module.exports = router;
