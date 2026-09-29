import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluatePolicy, validatePolicy } from '../src/policy.js';
import { createBotHandlers } from '../src/bot.js';
import { addClient, createTestIdp, fakeTelegram, pollStatus, startLogin, pkce, tgUser } from './helpers.js';

const premium = { type: 'is_premium', value: true };
const notPremium = { type: 'is_premium', value: false };

test('is_premium reads the live Telegram user object', async () => {
  assert.equal((await evaluatePolicy(premium, { id: 1, is_premium: true }, null)).pass, true);
  assert.equal((await evaluatePolicy(premium, { id: 1 }, null)).pass, false);
  assert.equal((await evaluatePolicy(notPremium, { id: 1 }, null)).pass, true);
  assert.equal((await evaluatePolicy(notPremium, { id: 1, is_premium: true }, null)).pass, false);
});

test('language_code_in matches full tag or primary subtag, case-insensitively', async () => {
  const policy = { type: 'language_code_in', codes: ['en', 'pt-BR'] };
  assert.equal((await evaluatePolicy(policy, { id: 1, language_code: 'en' }, null)).pass, true);
  assert.equal((await evaluatePolicy(policy, { id: 1, language_code: 'en-gb' }, null)).pass, true);
  assert.equal((await evaluatePolicy(policy, { id: 1, language_code: 'pt-br' }, null)).pass, true);
  assert.equal((await evaluatePolicy(policy, { id: 1, language_code: 'de' }, null)).pass, false);
  assert.equal((await evaluatePolicy(policy, { id: 1 }, null)).pass, false);
});

test('group membership uses the injected Telegram API and fails closed', async () => {
  const telegram = fakeTelegram({ '-1:7': 'member', '-2:7': 'administrator' });
  const member = { type: 'group_membership', chat_id: -1 };
  assert.equal((await evaluatePolicy(member, { id: 7 }, telegram)).pass, true);
  assert.equal((await evaluatePolicy(member, { id: 8 }, telegram)).pass, false);
  assert.equal((await evaluatePolicy(member, { id: 7 }, null)).pass, false);
  const admin = { type: 'group_membership', chat_id: -1, role: 'administrator' };
  assert.equal((await evaluatePolicy(admin, { id: 7 }, telegram)).pass, false);
  assert.equal((await evaluatePolicy({ type: 'all_group_membership', chat_ids: [-1, -2] }, { id: 7 }, telegram)).pass, true);
  assert.equal((await evaluatePolicy({ type: 'any_group_membership', chat_ids: [-3, -2] }, { id: 7 }, telegram)).pass, true);
  telegram.members['-1:7'] = 'kicked';
  assert.equal((await evaluatePolicy(member, { id: 7 }, telegram)).pass, false);
});

test('operators, and fail-closed behaviour on bad input', async () => {
  const user = { id: 5, username: 'bob' };
  assert.equal((await evaluatePolicy({ operator: 'or', conditions: [premium, { type: 'user_id_in_list', user_ids: [5] }] }, user, null)).pass, true);
  assert.equal((await evaluatePolicy({ operator: 'and', conditions: [premium, { type: 'user_id_in_list', user_ids: [5] }] }, user, null)).pass, false);
  assert.equal((await evaluatePolicy({ operator: 'not', condition: premium }, user, null)).pass, true);
  assert.equal((await evaluatePolicy({ type: 'username_matches', pattern: '^b' }, user, null)).pass, true);
  assert.equal((await evaluatePolicy({ type: 'username_matches', pattern: '^b' }, { id: 5 }, null)).pass, false);
  assert.equal((await evaluatePolicy({ operator: 'xor', conditions: [] }, user, null)).pass, false);
  assert.equal((await evaluatePolicy({ type: 'nope' }, user, null)).pass, false);
  assert.equal((await evaluatePolicy({ type: 'username_matches', pattern: '(' }, user, null)).pass, false);
});

test('validatePolicy rejects malformed policies', () => {
  validatePolicy(null);
  validatePolicy({ operator: 'and', conditions: [premium, { type: 'group_membership', chat_id: -100 }] });
  assert.throws(() => validatePolicy({ type: 'is_premium' }), /value/);
  assert.throws(() => validatePolicy({ type: 'bogus' }), /not a known condition/);
  assert.throws(() => validatePolicy({ operator: 'and', conditions: [] }), /non-empty/);
  assert.throws(() => validatePolicy({ type: 'username_matches', pattern: '(' }));
  assert.throws(() => validatePolicy([premium]), /object/);
});

/** Minimal stand-in for a grammY context. */
function fakeCtx(from, match) {
  const replies = [];
  return {
    from, match, replies,
    reply: async (text, extra) => { replies.push({ text, extra }); },
  };
}

test('bot flow: premium-only client admits a premium user and persists premium/language', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx, { policy: premium });
  const bot = createBotHandlers(idp.ctx);
  const { token } = await startLogin(idp.app, { code_challenge: pkce().challenge });

  const user = tgUser({ is_premium: true, language_code: 'pt-br' });
  const ctx = fakeCtx(user, `auth_${token}`);
  await bot.start(ctx);
  assert.match(ctx.replies[0].text, /wants to sign you in/);
  const approve = ctx.replies[0].extra.reply_markup.inline_keyboard[0][0].callback_data;

  const cb = { from: user, callbackQuery: { data: approve }, answerCallbackQuery: async () => {}, editMessageText: async () => {} };
  await bot.callback(cb);
  const row = idp.ctx.store.getUserByTelegramId(user.id);
  assert.equal(row.is_premium, 1);
  assert.equal(row.language_code, 'pt-br');
});

test('bot flow: a non-premium user is denied and the browser gets access_denied', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx, { policy: premium });
  const bot = createBotHandlers(idp.ctx);
  const { token, statusUrl, cookie } = await startLogin(idp.app, { code_challenge: pkce().challenge, state: 's' });
  const ctx = fakeCtx(tgUser(), `auth_${token}`);
  await bot.start(ctx);
  assert.match(ctx.replies[0].text, /do not meet the requirements/);
  assert.match(ctx.replies[0].text, /Premium is required/);
  const { body } = await pollStatus(idp.app, statusUrl, cookie);
  const url = new URL(body.redirect_to);
  assert.equal(url.searchParams.get('error'), 'access_denied');
  // The policy reason is not leaked to the client.
  assert.doesNotMatch(url.searchParams.get('error_description'), /Premium/);
});

test('bot flow: language policy', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx, { policy: { type: 'language_code_in', codes: ['de'] } });
  const bot = createBotHandlers(idp.ctx);
  const a = await startLogin(idp.app, { code_challenge: pkce().challenge });
  const german = fakeCtx(tgUser({ language_code: 'de-AT' }), `auth_${a.token}`);
  await bot.start(german);
  assert.match(german.replies[0].text, /wants to sign you in/);
  const b = await startLogin(idp.app, { code_challenge: pkce().challenge });
  const english = fakeCtx(tgUser({ id: 2002 }), `auth_${b.token}`);
  await bot.start(english);
  assert.match(english.replies[0].text, /do not meet the requirements/);
});

test('bot escapes client names in HTML messages', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx, { name: '<b>Evil</b> & co' });
  const bot = createBotHandlers(idp.ctx);
  const { token } = await startLogin(idp.app, { code_challenge: pkce().challenge });
  const ctx = fakeCtx(tgUser(), `auth_${token}`);
  await bot.start(ctx);
  assert.match(ctx.replies[0].text, /&lt;b&gt;Evil&lt;\/b&gt; &amp; co/);
});
