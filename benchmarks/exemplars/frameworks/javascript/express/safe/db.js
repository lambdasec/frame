const mysql = require('mysql2');

const pool = mysql.createPool({ host: 'localhost', user: 'app', database: 'shop' });

module.exports = pool;
