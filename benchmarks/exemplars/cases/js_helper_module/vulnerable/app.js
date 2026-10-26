const express = require('express');
const { listDir } = require('./shell');
const app = express();

app.get('/ls', (req, res) => {
  listDir(req.query.dir, (err, out) => res.send(out));
});
