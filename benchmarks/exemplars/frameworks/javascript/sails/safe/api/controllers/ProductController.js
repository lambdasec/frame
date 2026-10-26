const fs = require('fs');
const path = require('path');
const escapeHtml = require('escape-html');

module.exports = {
  search: async function (req, res) {
    const term = req.param('term');
    const rows = await sails.sendNativeQuery('SELECT * FROM product WHERE name LIKE $1', ['%' + term + '%']);
    return res.json(rows.rows);
  },

  preview: function (req, res) {
    return res.send('<h1>' + escapeHtml(req.allParams().title) + '</h1>');
  },

  download: async function (req, res) {
    const stream = fs.createReadStream(path.join('./.tmp/uploads', path.basename(req.param('file'))));
    return stream.pipe(res);
  },

  bounce: function (req, res) {
    const to = req.query.to;
    if (to.startsWith('/') && !to.startsWith('//')) {
      return res.redirect(to);
    }
    return res.redirect('/');
  },
};
