import { SignJWT, generateKeyPair, exportJWK, importPKCS8, importSPKI, exportPKCS8, exportSPKI } from 'jose';
import { config } from './config.js';
import { readFile, writeFile, mkdir } from 'fs/promises';
import path from 'path';

let keyPairPromise;

async function loadOrCreateKeyPair() {
  const keysDir = config.keysDir || './keys';
  await mkdir(keysDir, { recursive: true });
  const privateKeyPath = path.join(keysDir, 'private.pem');
  const publicKeyPath = path.join(keysDir, 'public.pem');

  try {
    const [privatePem, publicPem] = await Promise.all([
      readFile(privateKeyPath, 'utf8'),
      readFile(publicKeyPath, 'utf8'),
    ]);
    const privateKey = await importPKCS8(privatePem, 'RS256');
    const publicKey = await importSPKI(publicPem, 'RS256');
    return { privateKey, publicKey };
  } catch (err) {
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const privatePem = await exportPKCS8(privateKey);
    const publicPem = await exportSPKI(publicKey);
    await Promise.all([
      writeFile(privateKeyPath, privatePem),
      writeFile(publicKeyPath, publicPem),
    ]);
    return { privateKey, publicKey };
  }
}

export function getKeyPair() {
  if (!keyPairPromise) {
    keyPairPromise = loadOrCreateKeyPair();
  }
  return keyPairPromise;
}

export async function createAccessToken(user, clientId, scope) {
  const { privateKey } = await getKeyPair();
  return new SignJWT({
    scope,
    client_id: clientId,
    telegram_id: user.telegram_user_id,
    username: user.telegram_username,
  })
    .setProtectedHeader({ alg: 'RS256', typ: 'at+jwt' })
    .setSubject(user.id.toString())
    .setIssuer(config.baseUrl)
    .setAudience(clientId)
    .setIssuedAt()
    .setExpirationTime(config.accessTokenTtl)
    .sign(privateKey);
}

export async function createIdToken(user, clientId, nonce) {
  const { privateKey } = await getKeyPair();
  const claims = {
    telegram_id: user.telegram_user_id,
    preferred_username: user.telegram_username,
    name: [user.first_name, user.last_name].filter(Boolean).join(' '),
    picture: user.photo_url,
  };
  if (nonce) claims.nonce = nonce;
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256' })
    .setSubject(user.id.toString())
    .setIssuer(config.baseUrl)
    .setAudience(clientId)
    .setIssuedAt()
    .setExpirationTime(config.idTokenTtl)
    .sign(privateKey);
}

export async function getJwks() {
  const { publicKey } = await getKeyPair();
  const jwk = await exportJWK(publicKey);
  return { keys: [jwk] };
}
