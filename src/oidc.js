import { SignJWT, jwtVerify } from 'jose';
import { getKeyPair } from './keys.js';

export async function generateIdToken(env, subject, nonce, audience, issuer) {
  const { privateKey } = await getKeyPair(env);
  
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 3600; // 1 hour expiration

  const jwt = new SignJWT({
    nonce: nonce,
    name: subject === 'testuser' ? 'Test User' : subject,
    preferred_username: subject,
  })
    .setProtectedHeader({ alg: 'RS256', kid: 'epic-eas-key-1' })
    .setSubject(subject)
    .setIssuedAt(iat)
    .setIssuer(issuer)
    .setAudience(audience)
    .setExpirationTime(exp);

  return jwt.sign(privateKey);
}

export async function generateAccessToken(env, subject, clientId, issuer) {
  const { privateKey } = await getKeyPair(env);
  
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 3600; // 1 hour expiration

  const jwt = new SignJWT({
    client_id: clientId,
    scope: 'openid profile',
  })
    .setProtectedHeader({ alg: 'RS256', kid: 'epic-eas-key-1' })
    .setSubject(subject)
    .setIssuedAt(iat)
    .setIssuer(issuer)
    .setAudience(clientId) // Usually the client ID, or an API audience
    .setExpirationTime(exp);

  return jwt.sign(privateKey);
}

// We'll use a stateless authorization code by encrypting/signing the state into a short-lived JWT.
export async function generateAuthCode(env, payload) {
  const { privateKey } = await getKeyPair(env);
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 300; // 5 minutes expiration for auth code

  const jwt = new SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256', kid: 'epic-eas-key-1' })
    .setIssuedAt(iat)
    .setExpirationTime(exp);

  return jwt.sign(privateKey);
}

export async function verifyAuthCode(env, code) {
  const { publicKey } = await getKeyPair(env);
  try {
    const { payload } = await jwtVerify(code, publicKey);
    return payload;
  } catch (e) {
    throw new Error('Invalid or expired authorization code');
  }
}

export async function verifyAccessToken(env, token) {
  const { publicKey } = await getKeyPair(env);
  try {
    const { payload } = await jwtVerify(token, publicKey);
    return payload;
  } catch (e) {
    throw new Error('Invalid or expired access token');
  }
}
