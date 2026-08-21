import { Bot, InlineKeyboard } from 'grammy';
import { config } from './config.js';
import { getAuthRequestByToken, approveAuthRequest, denyAuthRequest } from './oauth.js';
import { evaluatePolicy } from './policy.js';
import db from './db.js';

export const bot = new Bot(config.telegramBotToken);

bot.command('start', async (ctx) => {
  const payload = ctx.match;
  if (payload && payload.startsWith('auth_')) {
    const token = payload.slice(5);
    const authRequest = getAuthRequestByToken(token);
    if (!authRequest) {
      return ctx.reply('❌ Invalid or expired login request.');
    }

    // Fetch client policy
    const client = db.prepare('SELECT policy FROM oauth_clients WHERE client_id = ?').get(authRequest.client_id);
    const policy = client?.policy ? JSON.parse(client.policy) : null;

    // Evaluate policy
    const result = await evaluatePolicy(policy, ctx.from, bot);
    if (!result.pass) {
      // Deny the auth request
      denyAuthRequest(authRequest.id, result.reason || 'Policy evaluation failed');
      return ctx.reply(`❌ You do not meet the requirements to sign in: ${result.reason || 'policy denied'}`);
    }

    // Policy passed – show consent
    const keyboard = new InlineKeyboard()
      .text('✅ Approve', `approve:${authRequest.id}`)
      .text('❌ Deny', `deny:${authRequest.id}`);
    await ctx.reply(
      `Login request from **${authRequest.client_id}**\n\nAllow @${ctx.from.username || ctx.from.first_name} to sign in?`,
      { parse_mode: 'Markdown', reply_markup: keyboard }
    );
  } else {
    await ctx.reply('Welcome! Scan a QR code to sign in to third-party apps.');
  }
});

bot.on('callback_query:data', async (ctx) => {
  const data = ctx.callbackQuery.data;
  if (data.startsWith('approve:')) {
    const id = data.slice(8);
    const user = await approveAuthRequest(id, ctx.from);
    if (user) {
      await ctx.answerCallbackQuery({ text: 'Approved! Return to your browser.' });
      await ctx.editMessageText('✅ Login approved. You can close this chat.');
    } else {
      await ctx.answerCallbackQuery({ text: 'This request is no longer valid.' });
    }
  } else if (data.startsWith('deny:')) {
    const id = data.slice(5);
    const ok = denyAuthRequest(id);
    await ctx.answerCallbackQuery({ text: ok ? 'Denied.' : 'Invalid request.' });
    if (ok) await ctx.editMessageText('❌ Login denied.');
  }
});
