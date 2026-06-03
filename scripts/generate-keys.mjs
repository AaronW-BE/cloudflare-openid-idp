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
  // We stringify the JWK again to escape quotes correctly, or just use single quotes around the JSON for dotenv, but JSON has double quotes.
  // Best way for dotenv with JSON is to enclose the whole JSON string in single quotes or escaped double quotes.
  // Actually, for Wrangler .dev.vars, just a raw JSON string on a single line is fine.
  const envFormat = `PRIVATE_KEY="${privateKeyPem}"\nPUBLIC_JWK='${JSON.stringify(publicJwk)}'\n`;
  fs.writeFileSync('.dev.vars', envFormat);
  
  console.log("✅ Key pair saved to 'private_key.pem' and injected into '.dev.vars'.");
  console.log("⚠️  SECURITY WARNING: Do not commit these files to version control!");
}

generate().catch(console.error);
