# Epic EAS OpenID Connect Identity Provider

This is a lightweight OpenID Connect (OIDC) Identity Provider (IdP) built on **Cloudflare Workers**. It is specifically designed to meet the requirements of **Epic Account Services (EAS)** for integrating external identity providers.

## Features
- Compliant with **OpenID Connect Core 1.0** and **Discovery 1.0**.
- Built using [Hono](https://hono.dev/) for fast routing and `jose` for zero-dependency JWT signing and JWKS generation.
- Implements the **Authorization Code Flow**.
- Uses a stateless approach for authorization codes by encoding context into a short-lived, signed JWT (no database or KV required).
- Auto-generates RS256 key pairs for JWT signing out of the box.

## Implemented Endpoints
- `GET /.well-known/openid-configuration` : OIDC Discovery Endpoint
- `GET /jwks.json` : JSON Web Key Set for token validation
- `GET /authorize` : Renders the login page
- `POST /authorize` : Handles login submission and returns an auth code
- `POST /token` : Exchanges the auth code for an Access Token and an ID Token
- `GET /userinfo` : Validates the Access Token and returns the user's profile claims

## Prerequisites
- [Node.js](https://nodejs.org/) (v18 or later recommended)
- A Cloudflare account

## Getting Started

### 1. Install Dependencies
Clone this repository or navigate to the project directory, then install the dependencies:
```bash
npm install
```

### 2. Local Development
Run the local Cloudflare Workers development server:
```bash
npm run dev
```
You can view your discovery endpoint locally at `http://localhost:8787/.well-known/openid-configuration`.

### 3. Key Management (Production)
By default, the worker will automatically generate an RS256 key pair on startup if it doesn't find one. However, in production, this means keys could change when the worker isolate restarts, potentially invalidating active tokens.

For production, you should generate a static PKCS#8 private key and add it to your Cloudflare Secrets:
```bash
# Generate a private key
npx wrangler secret put PRIVATE_KEY
```
*(Paste your PEM-formatted private key when prompted)*

### 4. Customizing User Authentication
Currently, the `/authorize` endpoint performs a basic, hardcoded validation (it accepts any username/password for demonstration). 
Before deploying for production use, modify `src/routes.js` to connect to your actual user database or auth service inside the `app.post('/authorize')` handler.

### 5. Deployment
Deploy the worker to your Cloudflare account:
```bash
npm run deploy
```

## Integrating with Epic Developer Portal
Once deployed, log into your [Epic Developer Portal](https://dev.epicgames.com/portal/):
1. Navigate to your Product -> **Epic Account Services** -> **Identity Providers**.
2. Add a new OpenID Provider.
3. For the **Discovery URL** (or Issuer URL), provide your worker's domain. Example:
   `https://west-journey-api-idp.<your-subdomain>.workers.dev`
4. Epic will automatically fetch the `/.well-known/openid-configuration` and configure the necessary endpoints.

## License
MIT
