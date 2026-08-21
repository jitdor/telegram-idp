import { SignJWT, generateKeyPair, exportJWK } from 'jose';
import { config } from './config.js';

let keyPair;

export async function getKeyPair() {
  if (!keyPair) {
    // In production, load a persistent key from env/secret manager
    keyPair = await generateKeyPair('RS256');
  }
  return keyPair;
}

export async function createAccessToken(user, clientId, scope) {
  const { privateKey } = await getKeyPair();
  return new SignJWT({
    scope,
    client_id: clientId,
    telegram_id: user.telegram_user_id,
    username: user.telegram_username,
  })
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
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
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
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
