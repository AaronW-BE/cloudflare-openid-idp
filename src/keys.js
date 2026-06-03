import { exportJWK, generateKeyPair, importPKCS8, importJWK } from 'jose';

// In-memory cache for the key pair to avoid re-generating on every request
// Note: In a production Cloudflare Worker, you should store the private key
// in Cloudflare Secrets (e.g., env.PRIVATE_KEY) and load it here.
let cachedKeyPair = null;
let cachedJwks = null;

export async function getKeyPair(env) {
  if (cachedKeyPair) {
    return cachedKeyPair;
  }

  // If a private key and public JWK are provided via environment variables, use them.
  if (env && env.PRIVATE_KEY && env.PUBLIC_JWK) {
    try {
      const privateKey = await importPKCS8(env.PRIVATE_KEY, 'RS256');
      const publicJwk = JSON.parse(env.PUBLIC_JWK);
      const publicKey = await importJWK(publicJwk, 'RS256');
      
      cachedKeyPair = { publicKey, privateKey, publicJwk };
      return cachedKeyPair;
    } catch (e) {
      console.error("Failed to parse PRIVATE_KEY or PUBLIC_JWK from env, generating a new one.", e);
    }
  }

  // Generate a new RS256 key pair
  console.log("Generating new RS256 key pair for OIDC...");
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
  
  cachedKeyPair = { publicKey, privateKey };
  return cachedKeyPair;
}

export async function getJwks(env) {
  if (cachedJwks) {
    return cachedJwks;
  }

  const { publicKey, publicJwk } = await getKeyPair(env);
  const jwkBase = publicJwk || await exportJWK(publicKey);
  
  // Clone to avoid modifying the cached publicJwk directly
  const jwk = { ...jwkBase };
  
  // Add required fields for JWKS
  jwk.kid = 'epic-eas-key-1';
  jwk.alg = 'RS256';
  jwk.use = 'sig';

  cachedJwks = {
    keys: [jwk]
  };

  return cachedJwks;
}
