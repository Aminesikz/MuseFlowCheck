const Koa = require('koa');
const knex = require('knex')({ client: 'pg', connection: process.env.PG_URL });

const app = new Koa();

app.use(async (ctx) => {
  const fields = (ctx.query.fields || 'id,name').split(',');
  const sortDir = ctx.query.dir || 'asc';
  const result = await knex.raw(
    'SELECT ' + fields.join(', ') + ' FROM products ORDER BY price ' + sortDir
  );
  ctx.body = result.rows;
});

module.exports = app;
