# Telegram Identity Provider (IdP)

A self‑hosted OAuth 2.0 / OpenID Connect identity provider that uses **Telegram** as the authentication method. Users scan a **QR code** with their Telegram app and approve the login – no passwords needed.

## Features

- **QR code login** via Telegram bot deep‑link
- **OAuth 2.0 Authorization Code flow with PKCE** (required)
- **OpenID Connect** discovery, JWKS, and `/userinfo`
- **Conditional authentication policies**:
  - User ID allow/deny lists
  - Username regex matching
  - Telegram group membership (any, all, or specific group with optional role)
  - Telegram Premium status
  - Language code filtering
  - Logical AND/OR/NOT combinations
- **SQLite** storage (easy to migrate to MariaDB/PostgreSQL)
- **Caddy** for automatic HTTPS
- **Telegram webhook** with secret token verification

## Quick Start

1. **Clone the repository** and install dependencies:
   ```bash
   npm install
