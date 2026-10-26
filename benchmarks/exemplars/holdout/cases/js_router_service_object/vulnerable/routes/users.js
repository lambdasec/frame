const express = require('express');
const svc = require('../services/userService');
const router = express.Router();

router.get('/', (req, res) => {
  svc.find(req.query.name, (err, rows) => res.json(rows));
});

module.exports = router;
