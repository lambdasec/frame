const express = require('express');
const { exec } = require('child_process');
const { clean } = require('./escape');
const app = express();

app.get('/g', (req, res) => {
  exec('grep ' + clean(req.query.pattern) + ' log.txt');
  res.send('ok');
});
