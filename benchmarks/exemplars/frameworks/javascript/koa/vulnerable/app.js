const Koa = require('koa');
const Router = require('@koa/router');
const bodyParser = require('koa-bodyparser');
const { exec } = require('child_process');
const db = require('./db');

const app = new Koa();
const router = new Router();

router.get('/orders', async (ctx) => {
  const status = ctx.query.status;
  const result = await db.query("SELECT * FROM orders WHERE status = '" + status + "'");  // frame-expect: CWE-89
  ctx.body = result.rows;
});

router.get('/echo', async (ctx) => {
  ctx.body = { status: ctx.query.status, requestedBy: ctx.headers['x-user'] };
});

router.get('/hello/:name', async (ctx) => {
  ctx.body = '<p>Hello ' + ctx.params.name + '</p>';  // frame-expect: CWE-79
});

router.get('/out', async (ctx) => {
  ctx.redirect(ctx.query.url);  // frame-expect: CWE-601
});

router.post('/convert', async (ctx) => {
  const { file } = ctx.request.body;
  exec('pandoc ' + file + ' -o out.pdf');  // frame-expect: CWE-78
  ctx.status = 202;
});

app.use(bodyParser());
app.use(router.routes());
app.listen(3001);
