const mysql = require('mysql2/promise');

// A second pool for the read replica, exported as a field.
exports.reporting = mysql.createPool({ host: 'replica', user: 'books' });
