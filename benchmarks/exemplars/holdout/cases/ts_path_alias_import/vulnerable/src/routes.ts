import express from 'express';
import { listDir } from '@/services/shell';
const app = express();

app.get('/ls', (req, res) => {
  listDir(req.query.dir as string);
  res.send('ok');
});
