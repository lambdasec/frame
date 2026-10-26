import express from 'express';
import { listDir } from '@/services/shell';
const app = express();

app.get('/ls', (req, res) => {
  listDir('/tmp');
  res.send('ok');
});
