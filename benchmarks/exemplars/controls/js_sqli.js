const express = require('express');
const app = express();
app.get('/u', (req, res) => { db.query("SELECT * FROM u WHERE id = " + req.query.id, (e, r) => res.json(r)); });
