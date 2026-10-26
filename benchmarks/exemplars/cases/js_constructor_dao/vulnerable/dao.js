function UserDAO(db) {
  this.byId = (id, cb) => {
    db.query("SELECT * FROM users WHERE id = " + id, cb);
  };
}

module.exports = UserDAO;
