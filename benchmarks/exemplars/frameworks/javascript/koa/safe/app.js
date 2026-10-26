const Koa = require('koa');
const Router = require('@koa/router');
const bodyParser = require('koa-bodyparser');
const { execFile } = require('child_process');
const escapeHtml = require('escape-html');
const db = require('./db');

const app = new Koa();
const router = new Router();

router.get('/orders', async (ctx) => {
  const status = ctx.query.status;
  const result = await db.query('SELECT * FROM orders WHERE status = $1', [status]);
  ctx.body = result.rows;
});

router.get('/echo', async (ctx) => {
  ctx.body = { status: ctx.query.status, requestedBy: ctx.headers['x-user'] };
});

router.get('/hello/:name', async (ctx) => {
  ctx.body = '<p>Hello ' + escapeHtml(ctx.params.name) + '</p>';
});

router.get('/out', async (ctx) => {
  const url = ctx.query.url;
  if (url.startsWith('/') && !url.startsWith('//')) {
    ctx.redirect(url);
  } else {
    ctx.redirect('/');
  }
});

router.post('/convert', async (ctx) => {
  const { file } = ctx.request.body;
  execFile('pandoc', [file, '-o', 'out.pdf']);
  ctx.status = 202;
});

app.use(bodyParser());
app.use(router.routes());
app.listen(3001);
