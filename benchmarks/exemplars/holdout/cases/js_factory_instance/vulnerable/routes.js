const express = require('express');
const { createRepo } = require('./repo');
const app = express();
const repo = createRepo();

app.get('/f', (req, res) => {
  repo.find(req.query.name, (e, rows) => res.json(rows));
});
