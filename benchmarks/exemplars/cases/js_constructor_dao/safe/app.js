const express = require('express');
const mysql = require('mysql');
const Handler = require('./handler');

const app = express();
const handler = new Handler(mysql.createPool({ host: 'db', database: 'shop' }));
app.get('/users', handler.show);
app.listen(3000);
