const express = require('express');
const mongoose = require('mongoose');
const auth = require('./routes/auth');

mongoose.connect('mongodb://localhost/app');

const app = express();
app.use(express.json());
app.use('/api', auth);
app.listen(3006);
