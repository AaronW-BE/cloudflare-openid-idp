import { getJwks } from './keys.js';
import { generateAuthCode, verifyAuthCode, generateIdToken, generateAccessToken, verifyAccessToken } from './oidc.js';

// Helper for basic credential validation
function validateCredentials(username, password) {
  const users = {
    'testuser': 'password',
    'admin': 'admin'
  };
  return users[username] === password;
}

export function setupRoutes(app) {
  // 1. Discovery Endpoint
  app.get('/.well-known/openid-configuration', (c) => {
    // Determine the base URL dynamically from the request
    const url = new URL(c.req.url);
    const baseUrl = `${url.protocol}//${url.host}`;

    return c.json({
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
      userinfo_endpoint: `${baseUrl}/userinfo`,
      jwks_uri: `${baseUrl}/jwks.json`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce', 'name', 'preferred_username'],
      grant_types_supported: ['authorization_code', 'password'],
    });
  });

  // 2. JWKS Endpoint
  app.get('/jwks.json', async (c) => {
    const jwks = await getJwks(c.env);
    return c.json(jwks);
  });

  // 3. Authorization Endpoint (GET displays login, POST handles it)
  app.get('/authorize', async (c) => {
    const { client_id, redirect_uri, response_type, state, nonce } = c.req.query();

    if (!client_id || !redirect_uri || response_type !== 'code') {
      return c.text('Invalid authorization request. Ensure client_id, redirect_uri are provided and response_type is "code".', 400);
    }

    // Render a simple login HTML page
    const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login - Epic EAS Identity Provider</title>
        <style>
          body { font-family: 'Inter', sans-serif; background-color: #121212; color: white; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
          .login-container { background: #1e1e1e; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); width: 100%; max-width: 400px; }
          h2 { text-align: center; margin-bottom: 1.5rem; color: #fff; }
          .form-group { margin-bottom: 1rem; }
          label { display: block; margin-bottom: 0.5rem; color: #aaa; }
          input { width: 100%; padding: 0.75rem; border: 1px solid #333; border-radius: 4px; background: #2a2a2a; color: white; box-sizing: border-box; }
          button { width: 100%; padding: 0.75rem; background: #0078d4; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; margin-top: 1rem; }
          button:hover { background: #0060a8; }
        </style>
      </head>
      <body>
        <div class="login-container">
          <h2>Sign In</h2>
          <form method="POST" action="/authorize">
            <input type="hidden" name="client_id" value="${client_id}">
            <input type="hidden" name="redirect_uri" value="${redirect_uri}">
            <input type="hidden" name="state" value="${state || ''}">
            <input type="hidden" name="nonce" value="${nonce || ''}">
            
            <div class="form-group">
              <label for="username">Username (Try "testuser")</label>
              <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
              <label for="password">Password (Try "password")</label>
              <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit">Login</button>
          </form>
        </div>
      </body>
      </html>
    `;
    return c.html(html);
  });

  app.post('/authorize', async (c) => {
    const body = await c.req.parseBody();
    const { client_id, redirect_uri, state, nonce, username, password } = body;

    // VERY BASIC hardcoded authentication. 
    // In a real scenario, check against a database or user pool.
    if (!username || !password || !validateCredentials(username, password)) {
      return c.text('Invalid username or password', 401);
    }

    // Success! Generate an authorization code.
    // We encode the request context into the code for stateless verification later.
    const codePayload = {
      sub: username,
      client_id,
      redirect_uri,
      nonce
    };

    const code = await generateAuthCode(c.env, codePayload);

    // Redirect back to the client
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('code', code);
    if (state) {
      redirectUrl.searchParams.set('state', state);
    }

    return c.redirect(redirectUrl.toString());
  });

  // 4. Token Endpoint
  app.post('/token', async (c) => {
    const body = await c.req.parseBody();
    const { grant_type, code, redirect_uri, client_id, client_secret } = body;

    // Note: A real IdP should also verify client_id and client_secret if it's a confidential client.
    
    if (grant_type === 'password') {
      const { username, password } = body;
      if (!validateCredentials(username, password)) {
        return c.json({ error: 'invalid_grant', error_description: 'Invalid credentials' }, 401);
      }
      const url = new URL(c.req.url);
      const issuer = `${url.protocol}//${url.host}`;
      const idToken = await generateIdToken(c.env, username, '', client_id, issuer);
      const accessToken = await generateAccessToken(c.env, username, client_id, issuer);
      return c.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        id_token: idToken,
      });
    }

    if (grant_type !== 'authorization_code') {
      return c.json({ error: 'unsupported_grant_type' }, 400);
    }

    if (!code) {
      return c.json({ error: 'invalid_request', error_description: 'Missing code' }, 400);
    }

    try {
      const codePayload = await verifyAuthCode(c.env, code);

      if (codePayload.redirect_uri !== redirect_uri || codePayload.client_id !== client_id) {
        return c.json({ error: 'invalid_grant', error_description: 'Code mismatch' }, 400);
      }

      const url = new URL(c.req.url);
      const issuer = `${url.protocol}//${url.host}`;
      const subject = codePayload.sub;

      const idToken = await generateIdToken(c.env, subject, codePayload.nonce, client_id, issuer);
      const accessToken = await generateAccessToken(c.env, subject, client_id, issuer);

      return c.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        id_token: idToken,
      });

    } catch (e) {
      return c.json({ error: 'invalid_grant', error_description: e.message }, 400);
    }
  });

  // 5. UserInfo Endpoint
  app.get('/userinfo', async (c) => {
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'invalid_request', error_description: 'Missing Bearer token' }, 401);
    }

    const token = authHeader.replace('Bearer ', '');

    try {
      const payload = await verifyAccessToken(c.env, token);
      
      // Return user profile information based on the subject (sub)
      return c.json({
        sub: payload.sub,
        name: payload.sub === 'testuser' ? 'Test User' : payload.sub,
        preferred_username: payload.sub,
      });
    } catch (e) {
      return c.json({ error: 'invalid_token', error_description: e.message }, 401);
    }
  });
  
  // Also support POST for userinfo as per spec
  app.post('/userinfo', async (c) => {
    // Re-use the GET logic
    return app.fetch(new Request(c.req.url, {
      method: 'GET',
      headers: c.req.raw.headers
    }), c.env, c.executionCtx);
  });
}
