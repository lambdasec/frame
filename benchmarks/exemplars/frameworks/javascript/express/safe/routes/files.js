const path = require('path');
const express = require('express');
const { execFile } = require('child_process');

const router = express.Router();
const ROOT = path.join(__dirname, '..', 'public');

router.get('/download', (req, res) => {
  res.sendFile(path.join(ROOT, path.basename(req.query.name)));
});

router.get('/get/:file', (req, res) => {
  res.download(path.join(ROOT, path.basename(req.params.file)));
});

router.post('/thumb', (req, res) => {
  execFile('convert', [req.body.file, '-resize', '64x64', 'out.png'], (err) => {
    res.sendStatus(err ? 500 : 200);
  });
});

module.exports = router;
