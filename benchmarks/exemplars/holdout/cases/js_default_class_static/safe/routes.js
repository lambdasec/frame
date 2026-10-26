import express from 'express';
import Archiver from './repo';
const app = express();

app.get('/pack', (req, res) => {
  Archiver.pack('/tmp');
  res.send('ok');
});
