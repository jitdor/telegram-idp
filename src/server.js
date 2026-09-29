// Standalone server: reads the environment, opens the database and keys,
// registers the Telegram webhook and listens.
import 'dotenv/config';
import { pathToFileURL } from 'node:url';
import { Bot } from 'grammy';
import { loadConfig } from './config.js';
import { createIdp } from './index.js';

export async function start(env = process.env) {
  const config = loadConfig(env);
  if (!config.telegramBotToken) throw new Error('TELEGRAM_BOT_TOKEN is required');
  if (!config.telegramWebhookSecret || config.telegramWebhookSecret.length < 16
      || config.telegramWebhookSecret === 'change-me') {
    // Anyone who knows this secret can forge Telegram updates, i.e. approve logins as any user.
    throw new Error('TELEGRAM_WEBHOOK_SECRET must be set to a random value of at least 16 characters');
  }
  if (!/^[A-Za-z0-9_-]{16,256}$/.test(config.telegramWebhookSecret)) {
    throw new Error('TELEGRAM_WEBHOOK_SECRET may only contain A-Z a-z 0-9 _ - (Telegram restriction)');
  }

  const bot = new Bot(config.telegramBotToken);
  await bot.init();
  const { app } = await createIdp({ config, bot, logger: true });

  const webhookUrl = `${config.issuer}/telegram-webhook`;
  await bot.api.setWebhook(webhookUrl, { secret_token: config.telegramWebhookSecret });
  app.log.info(`Webhook set to ${webhookUrl}`);

  await app.listen({ port: config.port, host: config.host });
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.once(signal, () => app.close().then(() => process.exit(0)));
  }
  return app;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  start().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
