# Jitdor Telegram Identity Provider (IdP)

A self-hosted **OAuth 2.0 / OpenID Connect** identity provider that uses **Telegram** as the authentication method. Users scan a **QR code** with their Telegram app and approve the login inside Telegram – no passwords needed.

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Generating Persistent Keys](#generating-persistent-keys)
- [Registering OAuth Clients](#registering-oauth-clients)
  - [Client Registration Script](#client-registration-script)
  - [Confidential vs Public Clients](#confidential-vs-public-clients)
  - [First-Party vs Third-Party Clients](#first-party-vs-third-party-clients)
- [Deployment](#deployment)
  - [Using Caddy for Automatic HTTPS](#using-caddy-for-automatic-https)
  - [Behind a Reverse Proxy](#behind-a-reverse-proxy)
  - [Running with Systemd](#running-with-systemd)
- [OAuth 2.0 / OIDC Usage](#oauth-20--oidc-usage)
  - [Authorization Code Flow with PKCE](#authorization-code-flow-with-pkce)
  - [Token Exchange](#token-exchange)
  - [Userinfo Endpoint](#userinfo-endpoint)
  - [OIDC Discovery](#oidc-discovery)
- [Conditional Authentication Policies](#conditional-authentication-policies)
  - [Policy Format](#policy-format)
  - [Available Conditions](#available-conditions)
  - [Example Policies](#example-policies)
- [Consent & Auto-Approval](#consent--auto-approval)
- [Security Considerations](#security-considerations)
- [Database Schema](#database-schema)
- [Roadmap / Known Limitations](#roadmap--known-limitations)
- [License](#license)

---

## Features

- **QR code login** via Telegram bot deep link – user scans with phone, approves inside Telegram.
- **OAuth 2.0 Authorization Code flow with PKCE** (required for all clients).
- **OpenID Connect** support: discovery, JWKS, `/userinfo`.
- **Conditional authentication policies** evaluated before consent:
  - User ID allow/deny lists
  - Username regex matching
  - Telegram group membership (any, all, or specific group with optional role)
  - Telegram Premium status
  - Language code filtering
  - Logical AND/OR/NOT combinations
- **Persistent RSA signing keys** stored on disk (no key regeneration on restart).
- **Access tokens typed as `at+jwt`** – ID tokens cannot be used as access tokens.
- **DB-backed authorization codes** – single-use, expiration, and automatic cleanup.
- **Consent management** – first-time approval, optional auto-approval for trusted first-party clients.
- **Confidential client support** – client secret hashing and constant-time verification.
- **SQLite storage** (easily swappable for PostgreSQL/MySQL with minor changes).
- **Caddy** integration for automatic HTTPS.

---

## How It Works

1. Third-party app redirects user to `/authorize` with OAuth parameters.
2. IdP renders a QR code containing a Telegram deep link (`https://t.me/<bot>?start=auth_<token>`).
3. User scans the QR code using the Telegram app.
4. Bot validates the auth request, evaluates any client-specific policies (e.g., group membership), and asks the user to approve or deny (unless auto-approval applies).
5. If approved, the auth request status changes to `approved` and the browser receives an authorization code.
6. The third-party app exchanges the code for tokens at `/token` (with PKCE).
7. Tokens are validated by the app or used to call `/userinfo`.

---

## Requirements

- **Node.js** 18+ (or 20+ recommended)
- **npm** 9+
- **A Telegram bot** created via [@BotFather](https://t.me/BotFather)
- **A publicly reachable HTTPS domain** (or a tunnel like ngrok for testing)
- **Caddy** (optional but recommended for automatic TLS)
- **SQLite** (built-in via `better-sqlite3`)

---

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/telegram-idp.git
   cd telegram-idp
