import Fastify, { FastifyRequest, FastifyReply } from 'fastify';
import { findNotes } from './repo';

const app = Fastify();

app.get('/notes', async (request: FastifyRequest<{ Querystring: { owner: string } }>, reply: FastifyReply) => {
  findNotes(request.query.owner, (rows) => reply.send(rows));
});

app.get('/echo', async (request, reply) => {
  const { owner } = request.query as { owner: string };
  reply.code(200).send({ owner });
});

app.get('/preview', async (request, reply) => {
  const { title } = request.query as { title: string };
  reply.type('text/html').send(`<h1>${title}</h1>`);  // frame-expect: CWE-79
});

app.get('/jump', async (request, reply) => {
  const { to } = request.query as { to: string };
  reply.redirect(to);  // frame-expect: CWE-601
});

app.post('/ping', async (request, reply) => {
  const { host } = request.body as { host: string };
  require('child_process').execSync('ping -c1 ' + host);  // frame-expect: CWE-78
  reply.send({ ok: true });
});

app.listen({ port: 3002 });
