import { escapeHtml as e } from '../util.js';

/**
 * Every value is HTML-escaped; no request data ever lands inside a <script>.
 * @param {{ clientName: string, qrDataUrl: string, deepLink: string, statusUrl: string }} p
 */
export function loginPage({ clientName, qrDataUrl, deepLink, statusUrl }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in with Telegram</title>
<link rel="stylesheet" href="/static/login.css">
</head>
<body>
<main id="login" data-status-url="${e(statusUrl)}">
<h1>Scan with Telegram</h1>
<p class="client">to sign in to <strong>${e(clientName)}</strong></p>
<img class="qr" src="${e(qrDataUrl)}" alt="QR code for Telegram sign-in">
<p><a href="${e(deepLink)}" rel="noopener">Open in Telegram</a></p>
<p class="status" id="status">Waiting for approval…</p>
</main>
<script src="/static/login.js"></script>
</body>
</html>`;
}

/** @param {{ title: string, message: string }} p */
export function errorPage({ title, message }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${e(title)}</title>
<link rel="stylesheet" href="/static/login.css">
</head>
<body>
<main>
<h1>${e(title)}</h1>
<p>${e(message)}</p>
</main>
</body>
</html>`;
}
