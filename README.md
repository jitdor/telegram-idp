# Telegram Identity Provider (IdP)

A self-hosted **OAuth 2.0 / OpenID Connect** identity provider that uses **Telegram** for authentication. Users scan a QR code with their Telegram app and approve the login inside Telegram – no passwords required.

## Features

- QR code login via Telegram bot deep link
- OAuth 2.0 Authorization Code flow with PKCE (required)
- OpenID Connect discovery, JWKS, and `/userinfo`
- Conditional authentication policies (group membership, user ID lists, username regex, Premium status, language, logical operators)
- Persistent RSA signing keys (stored on disk, safe across restarts)
- Access tokens typed as `at+jwt` (ID tokens cannot be used as access tokens)
- DB‑backed authorization codes (single‑use, expiring, cleaned up)
- Consent management (per‑scope) with optional auto‑approval for first‑party clients
- Support for confidential clients (client secret hashing, constant‑time compare)
- SQLite storage (easy to swap)
- Caddy / reverse proxy friendly

## Requirements

- Node.js 18+
- npm 9+
- Telegram bot token from [@BotFather](https://t.me/BotFather)
- Public HTTPS URL (or ngrok for local testing)
- Caddy (optional)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/telegram-idp.git
   cd telegram-idp
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Copy `.env.example` to `.env` and fill in your values:
   ```bash
   cp .env.example .env
   ```

4. Register an OAuth client:
   ```bash
   npm run register-client
   ```

5. Start the server:
   ```bash
   npm start
   ```
   The server will automatically set the Telegram webhook and generate persistent RSA keys (in `keys/`).

## Configuration

Edit the `.env` file:

| Variable                | Description                                      | Default                 |
|-------------------------|--------------------------------------------------|-------------------------|
| `PORT`                  | HTTP port                                        | `3000`                  |
| `BASE_URL`              | Public HTTPS base URL (issuer, webhook)          | `http://localhost:3000` |
| `TELEGRAM_BOT_TOKEN`    | Your bot token                                   | *(required)*            |
| `TELEGRAM_WEBHOOK_SECRET`| Secret to verify Telegram webhook updates       | `change-me`             |
| `DB_PATH`               | SQLite database file                             | `./data.db`             |
| `KEYS_DIR`              | Directory for RSA key pair                       | `./keys`                |

On first start, the server creates `private.pem` (mode 0600) and `public.pem` in `KEYS_DIR`. **Back these up.** If you delete them, all issued tokens become invalid.

## Registering OAuth Clients

Run `npm run register-client` and answer the prompts:

- **Client ID**: unique identifier
- **Client name**: shown to users
- **Redirect URIs**: comma‑separated list
- **Client secret**: optional; leave blank for public clients (SPA/mobile)
- **Policy file**: optional path to a JSON policy file

The script stores a SHA‑256 hash of the secret (if provided) and marks the client as **third‑party** (`is_first_party = 0`). This means users will always be asked to approve, even if they have consented before.

**To enable auto‑approval for your own trusted apps**, set:

```sql
UPDATE oauth_clients SET is_first_party = 1 WHERE client_id = 'your-app';
```

This skips the consent prompt after the first approval. Use with caution – it reduces phishing protection.

## Deployment

### Caddy

Use the provided `Caddyfile`:

```
telegram-idp.example.com {
    reverse_proxy localhost:3000
}
```

### Reverse proxy (Nginx example)

```nginx
server {
    listen 443 ssl;
    server_name telegram-idp.example.com;
    # ... TLS config ...
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Ensure `BASE_URL` matches the public URL exactly.

### Systemd

Create `/etc/systemd/system/telegram-idp.service`:

```ini
[Unit]
Description=Telegram Identity Provider
After=network.target

[Service]
Type=simple
User=telegram-idp
WorkingDirectory=/opt/telegram-idp
EnvironmentFile=/opt/telegram-idp/.env
ExecStart=/usr/bin/npm start
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl enable telegram-idp
sudo systemctl start telegram-idp
```

## OAuth 2.0 / OIDC Usage

### Authorization request

```
GET /authorize
    ?client_id=YOUR_CLIENT_ID
    &redirect_uri=https://yourapp.example.com/callback
    &response_type=code
    &scope=openid%20profile%20telegram
    &state=xyz123
    &code_challenge=BASE64URL(SHA256(code_verifier))
    &code_challenge_method=S256
```

The user scans the QR code and approves. The browser is redirected to `redirect_uri?code=...&state=...`.

### Token exchange

```bash
curl -X POST https://telegram-idp.example.com/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "AUTH_CODE",
    "redirect_uri": "https://yourapp.example.com/callback",
    "client_id": "YOUR_CLIENT_ID",
    "code_verifier": "YOUR_PKCE_VERIFIER"
  }'
```

If the client is confidential, include `"client_secret": "..."`.

Response:

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "id_token": "eyJ..."
}
```

### Userinfo

```bash
curl https://telegram-idp.example.com/userinfo \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

### Discovery

- `/.well-known/openid-configuration`
- `/jwks`

## Conditional Authentication Policies

Policies are stored per client as JSON. They are evaluated before consent.

### Available conditions

| Type                  | Description                          | Parameters                          |
|-----------------------|--------------------------------------|-------------------------------------|
| `user_id_in_list`     | Telegram ID in list                  | `user_ids`: array                   |
| `user_id_not_in_list` | Telegram ID not in list              | `user_ids`: array                   |
| `username_matches`    | Username matches regex               | `pattern`: string                   |
| `group_membership`    | Member of a group                    | `chat_id`: int, `role` (optional)   |
| `any_group_membership`| Member of at least one group         | `chat_ids`: array, `role` (optional)|
| `all_group_membership`| Member of all groups                 | `chat_ids`: array, `role` (optional)|
| `is_premium`          | Has Telegram Premium                 | `value`: boolean                    |
| `language_code_in`    | Language code in list                | `codes`: array                      |

Operators: `and`, `or`, `not`.

### Example policies

**Allow only specific users:**
```json
{ "type": "user_id_in_list", "user_ids": [123456789] }
```

**Require membership in a group (supergroup ID is negative):**
```json
{ "type": "group_membership", "chat_id": -1001234567890, "role": "member" }
```

**Premium OR admin of a group:**
```json
{
  "operator": "or",
  "conditions": [
    { "type": "is_premium", "value": true },
    { "type": "group_membership", "chat_id": -1003333333333, "role": "administrator" }
  ]
}
```

## Security Notes

- PKCE mandatory
- Redirect URIs validated exactly
- Auth request tokens short‑lived, single‑use, bound to browser session
- Telegram webhook protected by secret header
- Private key file mode 0600; read errors (except ENOENT) crash server to avoid silent key regeneration
- Client secret comparison is constant‑time; single `invalid_client` error
- Access tokens carry `typ: at+jwt`; `/userinfo` verifies issuer and type
- Authorization codes stored in DB, marked used immediately, cleaned up periodically

## Known Limitations

- No refresh tokens (sessions last 15 minutes)
- No automated tests yet
- Multi‑instance requires shared filesystem for keys and a shared DB

## License

MIT
