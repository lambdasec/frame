const express = require('express');
const { createRepo } = require('./repo');
const app = express();
const repo = createRepo();

app.get('/f', (req, res) => {
  repo.find('admin', (e, rows) => res.json(rows));
});
