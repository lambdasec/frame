const db = require('../db');

function find(name, cb) {
  db.query("SELECT * FROM users WHERE name = '" + name + "'", cb);
}

module.exports = { find };
