const express = require('express');
const { exec } = require('child_process');
const app = express();
app.get('/ls', (req, res) => { exec('ls ' + req.query.dir, (e, o) => res.send(o)); });
