import assert from 'node:assert/strict';
import test from 'node:test';

import { Hono } from 'hono';
import { cors } from 'hono/cors';

test('default CORS middleware handles a whitespace-heavy preflight header', async () => {
  const app = new Hono();
  app.use('/*', cors());
  app.get('/resolve/:offer', (c) => c.text('ok'));

  const response = await app.request('https://example.test/resolve/lno1offer', {
    method: 'OPTIONS',
    headers: {
      Origin: 'https://example.test',
      'Access-Control-Request-Method': 'GET',
      'Access-Control-Request-Headers': ' \t'.repeat(8192),
    },
  });

  assert.equal(response.status, 204);
});

test('query parsing ignores parameters after a URL fragment', async () => {
  const app = new Hono();
  app.get('/resolve/:offer', (c) => c.json({ amount: c.req.query('amount') ?? null }));

  const fragmentRequest = new Request('https://example.test/resolve/lno1offer#hidden?amount=999');
  assert.match(fragmentRequest.url, /#hidden\?amount=999$/);
  const fragmentResponse = await app.request(fragmentRequest);
  assert.deepEqual(await fragmentResponse.json(), { amount: null });

  const queryResponse = await app.request(
    'https://example.test/resolve/lno1offer?amount=123#hidden?amount=999'
  );
  assert.deepEqual(await queryResponse.json(), { amount: '123' });
});
