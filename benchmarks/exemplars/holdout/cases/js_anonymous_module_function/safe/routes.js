const express = require('express');
const convert = require('./render');
const app = express();

app.get('/c', (req, res) => {
  res.send(convert('a.png'));
});
