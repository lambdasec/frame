const mysql = require('mysql');

class Repo {
  constructor() {
    this.db = mysql.createPool({ host: 'db', database: 'app' });
  }

  find(name, cb) {
    this.db.query("SELECT * FROM t WHERE n = '" + name + "'", cb);
  }
}

function createRepo() {
  return new Repo();
}

module.exports = { createRepo };
