const fs = require('fs');

module.exports = {
  search: async function (req, res) {
    const term = req.param('term');
    const rows = await sails.sendNativeQuery("SELECT * FROM product WHERE name LIKE '%" + term + "%'");  // frame-expect: CWE-89
    return res.json(rows.rows);
  },

  preview: function (req, res) {
    return res.send('<h1>' + req.allParams().title + '</h1>');  // frame-expect: CWE-79
  },

  download: async function (req, res) {
    const stream = fs.createReadStream('./.tmp/uploads/' + req.param('file'));  // frame-expect: CWE-22
    return stream.pipe(res);
  },

  bounce: function (req, res) {
    return res.redirect(req.query.to);  // frame-expect: CWE-601
  },
};
