import express from 'express';
import { Controller } from './controller';
import { Shell } from './shell';

const app = express();
const controller = new Controller(new Shell());
app.get('/list', (req, res) => controller.list(req, res));
app.listen(3000);
