import { generateKeyPair, exportPKCS8, exportJWK } from 'jose';
import fs from 'fs';

async function generate() {
  console.log("Generating RS256 key pair...");
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
  
  const privateKeyPem = await exportPKCS8(privateKey);
  const publicJwk = await exportJWK(publicKey);
  
  console.log("\n================ PRIVATE KEY ================");
  console.log("Use this value for your PRIVATE_KEY environment variable (e.g. npx wrangler secret put PRIVATE_KEY)");
  console.log(privateKeyPem);
  console.log("=============================================\n");
  
  console.log("================ PUBLIC JWK =================");
  console.log("This is the public key representation that will be exposed at /jwks.json");
  console.log(JSON.stringify(publicJwk, null, 2));
  console.log("=============================================\n");

  fs.writeFileSync('private_key.pem', privateKeyPem);
  
  // Format for .dev.vars (dotenv): enclose in quotes and preserve newlines
  const envFormat = `PRIVATE_KEY="${privateKeyPem}"\n`;
  fs.writeFileSync('.dev.vars', envFormat);
  
  console.log("✅ Private key also saved to 'private_key.pem' and injected into '.dev.vars'.");
  console.log("⚠️  SECURITY WARNING: Do not commit these files to version control!");
}

generate().catch(console.error);
