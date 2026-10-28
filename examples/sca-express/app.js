const _ = require("lodash");
const express = require("express");

const app = express();

// A greeting page whose template the caller chooses: lodash compiles it as code.
app.get("/greet", (req, res) => {
  const render = _.template(req.query.tpl);
  res.send(render({ name: "world" }));
});

// The same page with a fixed, escaping template: not a finding.
app.get("/hello", (req, res) => {
  res.send(_.template("<b>Hello <%- name %></b>")({ name: req.query.name }));
});

app.listen(3000);
