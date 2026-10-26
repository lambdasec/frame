const UserDAO = require('./dao');

function Handler(db) {
  const dao = new UserDAO(db);
  this.show = (req, res) => {
    dao.byId('42', (e, rows) => res.json(rows));
  };
}

module.exports = Handler;
