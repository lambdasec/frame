const path = require('path');
const express = require('express');
const { exec } = require('child_process');

const router = express.Router();
const ROOT = path.join(__dirname, '..', 'public');

router.get('/download', (req, res) => {
  res.sendFile(path.join(ROOT, req.query.name));  // frame-expect: CWE-22
});

router.get('/get/:file', (req, res) => {
  res.download(ROOT + '/' + req.params.file);  // frame-expect: CWE-22
});

router.post('/thumb', (req, res) => {
  exec('convert ' + req.body.file + ' -resize 64x64 out.png', (err) => {  // frame-expect: CWE-78
    res.sendStatus(err ? 500 : 200);
  });
});

module.exports = router;
