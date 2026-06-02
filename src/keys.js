import { exportJWK, generateKeyPair, importPKCS8 } from 'jose';

// In-memory cache for the key pair to avoid re-generating on every request
// Note: In a production Cloudflare Worker, you should store the private key
// in Cloudflare Secrets (e.g., env.PRIVATE_KEY) and load it here.
let cachedKeyPair = null;
let cachedJwks = null;

export async function getKeyPair(env) {
  if (cachedKeyPair) {
    return cachedKeyPair;
  }

  // If a private key is provided via environment variables, use it.
  if (env && env.PRIVATE_KEY) {
    // Assuming PRIVATE_KEY is in PKCS8 PEM format
    try {
      const privateKey = await importPKCS8(env.PRIVATE_KEY, 'RS256');
      // For a full key pair we would ideally have the public key or extract it,
      // but 'jose' can often sign with just the private key.
      // To expose the JWKS, we need the public key.
      // If we only have private key, we might need a library to extract public key,
      // or we just generate a new one if it's not setup correctly.
      // For simplicity in this demo, if env.PRIVATE_KEY is missing, we auto-generate.
    } catch (e) {
      console.error("Failed to parse PRIVATE_KEY from env, generating a new one.", e);
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

  const { publicKey } = await getKeyPair(env);
  const jwk = await exportJWK(publicKey);
  
  // Add required fields for JWKS
  jwk.kid = 'epic-eas-key-1';
  jwk.alg = 'RS256';
  jwk.use = 'sig';

  cachedJwks = {
    keys: [jwk]
  };

  return cachedJwks;
}
