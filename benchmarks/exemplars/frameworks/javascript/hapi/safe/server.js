'use strict';
const Hapi = require('@hapi/hapi');
const fs = require('fs');
const path = require('path');
const escapeHtml = require('escape-html');
const knex = require('knex')({ client: 'sqlite3', connection: { filename: './app.db' } });

const init = async () => {
  const server = Hapi.server({ port: 3003 });

  server.route({
    method: 'GET',
    path: '/products',
    handler: async (request, h) => {
      const { category } = request.query;
      return knex.raw('SELECT * FROM products WHERE category = ?', [category]);
    },
  });

  server.route({
    method: 'POST',
    path: '/comment',
    handler: (request, h) => {
      return h.response('<div>' + escapeHtml(request.payload.text) + '</div>').type('text/html');
    },
  });

  server.route({
    method: 'GET',
    path: '/r/{target}',
    handler: (request, h) => {
      const target = request.params.target;
      if (target.startsWith('/') && !target.startsWith('//')) {
        return h.redirect(target);
      }
      return h.redirect('/');
    },
  });

  server.route({
    method: 'GET',
    path: '/doc/{name}',
    handler: (request, h) => fs.readFileSync(path.join('./docs', path.basename(request.params.name)), 'utf8'),
  });

  await server.start();
};

init();
