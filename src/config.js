import 'dotenv/config';

export const config = {
  port: process.env.PORT || 3000,
  baseUrl: process.env.BASE_URL || 'http://localhost:3000',
  telegramBotToken: process.env.TELEGRAM_BOT_TOKEN,
  telegramWebhookSecret: process.env.TELEGRAM_WEBHOOK_SECRET || 'change-me',
  jwtSecret: new TextEncoder().encode(process.env.JWT_SECRET || 'dev-secret-change-me'),
  dbPath: process.env.DB_PATH || './data.db',
  keysDir: process.env.KEYS_DIR || './keys',
  accessTokenTtl: '15m',
  idTokenTtl: '15m',
  authRequestTtl: 120, // seconds
  refreshTokenTtl: '30d',
};
