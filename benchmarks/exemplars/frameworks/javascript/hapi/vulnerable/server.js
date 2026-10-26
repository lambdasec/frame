'use strict';
const Hapi = require('@hapi/hapi');
const fs = require('fs');
const knex = require('knex')({ client: 'sqlite3', connection: { filename: './app.db' } });

const init = async () => {
  const server = Hapi.server({ port: 3003 });

  server.route({
    method: 'GET',
    path: '/products',
    handler: async (request, h) => {
      const { category } = request.query;
      return knex.raw("SELECT * FROM products WHERE category = '" + category + "'");  // frame-expect: CWE-89
    },
  });

  server.route({
    method: 'POST',
    path: '/comment',
    handler: (request, h) => {
      return h.response('<div>' + request.payload.text + '</div>').type('text/html');  // frame-expect: CWE-79
    },
  });

  server.route({
    method: 'GET',
    path: '/r/{target}',
    handler: (request, h) => h.redirect(request.params.target),  // frame-expect: CWE-601
  });

  server.route({
    method: 'GET',
    path: '/doc/{name}',
    handler: (request, h) => fs.readFileSync('./docs/' + request.params.name, 'utf8'),  // frame-expect: CWE-22
  });

  await server.start();
};

init();
