import { Bot, InlineKeyboard } from 'grammy';
import { escapeHtml as e } from './util.js';

/** @typedef {import('./types.js').IdpContext} IdpContext */

const SCOPE_LABELS = {
  openid: 'your Telegram-linked account id',
  profile: 'your name, username and language',
  telegram: 'your Telegram user id and Premium status',
  offline_access: 'staying signed in',
};

/**
 * grammY-free handlers over the OAuth service, so they can be unit tested
 * with a fake `ctx` (anything with `from`, `match`, `reply`, …).
 * @param {IdpContext} idp
 */
export function createBotHandlers(idp) {
  const { oauth } = idp;

  async function start(ctx) {
    const payload = typeof ctx.match === 'string' ? ctx.match : '';
    if (!payload.startsWith('auth_')) {
      return ctx.reply('Welcome! Scan a sign-in QR code to log in to an app. Use /apps to see and revoke apps you have signed in to.');
    }
    const outcome = await oauth.beginTelegramLogin(payload.slice(5), ctx.from);
    switch (outcome.kind) {
      case 'invalid':
        return ctx.reply('❌ This sign-in request is invalid, expired, or was opened by another account.');
      case 'denied':
        return ctx.reply(
          `❌ You do not meet the requirements to sign in to <b>${e(outcome.client.name)}</b>: ${e(outcome.reason)}`,
          { parse_mode: 'HTML' });
      case 'approved':
        return ctx.reply(
          `✅ Signed in to <b>${e(outcome.client.name)}</b> (you approved it before). You can return to your browser.`,
          { parse_mode: 'HTML' });
      case 'consent': {
        const keyboard = new InlineKeyboard()
          .text('✅ Approve', `approve:${outcome.authRequestId}`)
          .text('❌ Deny', `deny:${outcome.authRequestId}`);
        const who = ctx.from.username ? `@${ctx.from.username}` : ctx.from.first_name;
        const scopes = outcome.scopes.map((s) => `• ${e(SCOPE_LABELS[s] || s)}`).join('\n');
        return ctx.reply(
          `<b>${e(outcome.client.name)}</b> wants to sign you in as ${e(who)}.\n\nIt will be able to see:\n${scopes}`,
          { parse_mode: 'HTML', reply_markup: keyboard });
      }
    }
  }

  async function callback(ctx) {
    const data = String(ctx.callbackQuery?.data || '');
    const sep = data.indexOf(':');
    const action = sep > 0 ? data.slice(0, sep) : '';
    const arg = data.slice(sep + 1);
    if (action === 'approve') {
      const ok = oauth.approveLogin(arg, ctx.from);
      await ctx.answerCallbackQuery({ text: ok ? 'Approved! Return to your browser.' : 'This request is no longer valid.' });
      if (ok) await ctx.editMessageText('✅ Sign-in approved. You can return to your browser.');
    } else if (action === 'deny') {
      const ok = oauth.denyLogin(arg, ctx.from);
      await ctx.answerCallbackQuery({ text: ok ? 'Denied.' : 'This request is no longer valid.' });
      if (ok) await ctx.editMessageText('❌ Sign-in denied.');
    } else if (action === 'revoke') {
      const ok = oauth.revokeGrant(ctx.from.id, arg);
      await ctx.answerCallbackQuery({ text: ok ? 'Access revoked.' : 'Nothing to revoke.' });
      if (ok) await ctx.editMessageText(`🔒 Access revoked for ${arg}. That app will need your approval again.`);
    } else {
      await ctx.answerCallbackQuery();
    }
  }

  /** `/apps` — list clients the user has consented to, with revoke buttons. */
  async function apps(ctx) {
    const grants = oauth.listGrants(ctx.from.id);
    if (grants.length === 0) return ctx.reply('You have not granted access to any apps.');
    const keyboard = new InlineKeyboard();
    const lines = grants.map((g) => {
      // callback_data is limited to 64 bytes; long client ids fall back to /revoke.
      if (Buffer.byteLength(`revoke:${g.client_id}`) <= 64) keyboard.text(`Revoke ${g.name}`, `revoke:${g.client_id}`).row();
      return `• <b>${e(g.name)}</b> (<code>${e(g.client_id)}</code>): ${e(g.scopes)}`;
    });
    return ctx.reply(`Apps with access to your account:\n${lines.join('\n')}\n\nRevoke with the buttons or /revoke &lt;client_id&gt;.`,
      { parse_mode: 'HTML', reply_markup: keyboard });
  }

  /** `/revoke <client_id>` */
  async function revoke(ctx) {
    const clientId = typeof ctx.match === 'string' ? ctx.match.trim() : '';
    if (!clientId) return ctx.reply('Usage: /revoke <client_id> (see /apps)');
    const ok = oauth.revokeGrant(ctx.from.id, clientId);
    return ctx.reply(ok ? `🔒 Access revoked for ${clientId}.` : `No access found for ${clientId}.`);
  }

  return { start, callback, apps, revoke };
}

/**
 * Attach the handlers to a grammY bot.
 * @param {import('grammy').Bot} bot
 * @param {IdpContext} idp
 */
export function registerBotHandlers(bot, idp) {
  const h = createBotHandlers(idp);
  bot.command('start', h.start);
  bot.command('apps', h.apps);
  bot.command('revoke', h.revoke);
  bot.on('callback_query:data', h.callback);
  return bot;
}

/** @param {string} token */
export function createTelegramBot(token) {
  return new Bot(token);
}
