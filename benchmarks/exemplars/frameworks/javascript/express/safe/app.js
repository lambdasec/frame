const express = require('express');
const usersRouter = require('./routes/users');
const filesRouter = require('./routes/files');

const app = express();
app.use(express.json());
app.use('/users', usersRouter);
app.use('/files', filesRouter);

app.listen(3000);
