const mysql = require('mysql');

module.exports = mysql.createPool({ host: 'db', database: 'app' });
