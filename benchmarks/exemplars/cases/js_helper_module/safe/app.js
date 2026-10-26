const express = require('express');
const { listDir } = require('./shell');
const app = express();

app.get('/ls', (req, res) => {
  listDir('/tmp', (err, out) => res.send(out));
});
