import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createBotHandlers } from '../src/bot.js';
import { addClient, createTestIdp, login, loginAndExchange, pkce, postForm, refreshGrant, startLogin, tgUser } from './helpers.js';

test('first-party clients skip the prompt after the first consent; third-party never do', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx, { clientId: 'first', firstParty: true });
  await addClient(idp.ctx, { clientId: 'third' });

  assert.equal((await login(idp, { clientId: 'first' })).outcome.kind, 'consent');
  assert.equal((await login(idp, { clientId: 'first' })).outcome.kind, 'approved');
  // Asking for more than was consented to prompts again.
  assert.equal((await login(idp, { clientId: 'first', scope: 'openid offline_access' })).outcome.kind, 'consent');

  assert.equal((await login(idp, { clientId: 'third' })).outcome.kind, 'consent');
  assert.equal((await login(idp, { clientId: 'third' })).outcome.kind, 'consent');
});

test('revoking a grant kills refresh tokens and outstanding access tokens', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const tokens = await loginAndExchange(idp);

  assert.deepEqual(idp.ctx.oauth.listGrants(1001).map((g) => g.client_id), ['test-client']);
  assert.equal(idp.ctx.oauth.revokeGrant(1001, 'test-client'), true);
  assert.deepEqual(idp.ctx.oauth.listGrants(1001), []);

  assert.equal((await refreshGrant(idp.app, tokens.refresh_token)).statusCode, 400);
  const info = await idp.app.inject({ url: '/userinfo', headers: { authorization: `Bearer ${tokens.access_token}` } });
  assert.equal(info.statusCode, 401);
  const intro = await postForm(idp.app, '/introspect', { token: tokens.access_token, client_id: 'test-client' });
  assert.equal(intro.json().active, false);

  // Consenting again does not resurrect tokens issued before the revocation.
  idp.clock.advance(1);
  const fresh = await loginAndExchange(idp);
  assert.equal((await idp.app.inject({ url: '/userinfo', headers: { authorization: `Bearer ${tokens.access_token}` } })).statusCode, 401);
  assert.equal((await idp.app.inject({ url: '/userinfo', headers: { authorization: `Bearer ${fresh.access_token}` } })).statusCode, 200);
});

test('consenting to a new scope does not invalidate tokens that do not use it', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx, { firstParty: true });
  const narrow = await loginAndExchange(idp, { scope: 'openid' });
  idp.clock.advance(5);
  await loginAndExchange(idp, { scope: 'openid telegram' }); // grants telegram later
  const info = await idp.app.inject({ url: '/userinfo', headers: { authorization: `Bearer ${narrow.access_token}` } });
  assert.equal(info.statusCode, 200);
});

test('bot /apps lists grants and the revoke button withdraws consent', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx, { firstParty: true });
  await login(idp);
  const bot = createBotHandlers(idp.ctx);

  const replies = [];
  await bot.apps({ from: tgUser(), reply: async (text, extra) => replies.push({ text, extra }) });
  assert.match(replies[0].text, /Test Client/);
  const data = replies[0].extra.reply_markup.inline_keyboard[0][0].callback_data;
  assert.equal(data, 'revoke:test-client');

  let answered;
  await bot.callback({
    from: tgUser(), callbackQuery: { data },
    answerCallbackQuery: async (a) => { answered = a; }, editMessageText: async () => {},
  });
  assert.equal(answered.text, 'Access revoked.');

  // The first-party shortcut is gone: the next login prompts again.
  const { token } = await startLogin(idp.app, { code_challenge: pkce().challenge });
  assert.equal((await idp.ctx.oauth.beginTelegramLogin(token, tgUser())).kind, 'consent');
});

test('bot /revoke command', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  await login(idp);
  const bot = createBotHandlers(idp.ctx);
  const replies = [];
  const ctx = (match) => ({ from: tgUser(), match, reply: async (t) => replies.push(t) });
  await bot.revoke(ctx('test-client'));
  await bot.revoke(ctx('test-client'));
  assert.match(replies[0], /revoked/);
  assert.match(replies[1], /No access/);
});
