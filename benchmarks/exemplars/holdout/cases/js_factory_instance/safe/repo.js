class Repo {
  find(name, cb) {
    this.db.query("SELECT * FROM t WHERE n = '" + name + "'", cb);
  }
}

function createRepo() {
  return new Repo();
}

module.exports = { createRepo };
