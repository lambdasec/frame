import Fastify, { FastifyRequest, FastifyReply } from 'fastify';
import { execFileSync } from 'child_process';
import escapeHtml from 'escape-html';
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
  reply.type('text/html').send(`<h1>${escapeHtml(title)}</h1>`);
});

app.get('/jump', async (request, reply) => {
  const { to } = request.query as { to: string };
  if (to.startsWith('/') && !to.startsWith('//')) {
    reply.redirect(to);
  } else {
    reply.redirect('/');
  }
});

app.post('/ping', async (request, reply) => {
  const { host } = request.body as { host: string };
  execFileSync('ping', ['-c1', host]);
  reply.send({ ok: true });
});

app.listen({ port: 3002 });
