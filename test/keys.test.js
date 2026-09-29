import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { SignJWT, decodeProtectedHeader, exportPKCS8, generateKeyPair } from 'jose';
import { createFileKeyStore, generateKeyFile, setActiveKey } from '../src/keys.js';
import { addClient, createTestIdp, loginAndExchange } from './helpers.js';

async function tmpDir(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'tgidp-keys-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

const userinfo = (idp, token) => idp.app.inject({ url: '/userinfo', headers: { authorization: `Bearer ${token}` } });

test('JWKS entries carry kid, use and alg, and tokens reference the kid', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const jwks = (await idp.app.inject({ url: '/jwks' })).json();
  assert.equal(jwks.keys.length, 1);
  const [jwk] = jwks.keys;
  assert.equal(jwk.use, 'sig');
  assert.equal(jwk.alg, 'RS256');
  assert.ok(jwk.kid);
  assert.equal(jwk.d, undefined, 'no private material');
  const tokens = await loginAndExchange(idp);
  assert.equal(decodeProtectedHeader(tokens.access_token).kid, jwk.kid);
  assert.equal(decodeProtectedHeader(tokens.id_token).kid, jwk.kid);
});

test('key rollover: new key signs, old tokens keep verifying until the old key is retired', async (t) => {
  const dir = await tmpDir(t);
  const keysV1 = await createFileKeyStore(dir);
  const oldKid = keysV1.activeKid;

  const idp1 = await createTestIdp({ keys: keysV1 });
  await addClient(idp1.ctx);
  const oldTokens = await loginAndExchange(idp1);

  const newKid = await generateKeyFile(dir);
  await setActiveKey(dir, newKid);
  const keysV2 = await createFileKeyStore(dir);
  assert.deepEqual([...keysV2.kids].sort(), [oldKid, newKid].sort());

  const idp2 = await createTestIdp({ keys: keysV2, db: idp1.db });
  const jwks = (await idp2.app.inject({ url: '/jwks' })).json();
  assert.deepEqual(jwks.keys.map((k) => k.kid).sort(), [oldKid, newKid].sort());

  const newTokens = await loginAndExchange(idp2, { user: { id: 2002, first_name: 'Bob' } });
  assert.equal(decodeProtectedHeader(newTokens.access_token).kid, newKid);
  assert.equal((await userinfo(idp2, oldTokens.access_token)).statusCode, 200);
  assert.equal((await userinfo(idp2, newTokens.access_token)).statusCode, 200);
});

test('a legacy keys/private.pem is still loaded', async (t) => {
  const dir = await tmpDir(t);
  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  await writeFile(path.join(dir, 'private.pem'), await exportPKCS8(privateKey));
  await writeFile(path.join(dir, 'public.pem'), 'ignored');
  const keys = await createFileKeyStore(dir, { generateIfMissing: false });
  assert.equal(keys.kids.length, 1);
});

test('several keys without an active marker is an explicit error', async (t) => {
  const dir = await tmpDir(t);
  await generateKeyFile(dir);
  await generateKeyFile(dir);
  await assert.rejects(createFileKeyStore(dir), /Active signing key/);
});

test('userinfo requires the IdP audience, at+jwt type and a known kid', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const tokens = await loginAndExchange(idp);
  const { privateKey, kid } = await idp.ctx.keys.getSigningKey();
  const base = () => new SignJWT({ client_id: 'test-client', scope: 'openid', jti: 'j1' })
    .setSubject('1').setIssuer('https://idp.test').setIssuedAt(idp.clock.now()).setExpirationTime(idp.clock.now() + 60);

  // ID tokens are not access tokens.
  assert.equal((await userinfo(idp, tokens.id_token)).statusCode, 401);
  // Audience only names the client, not the IdP resource.
  const clientOnly = await base().setAudience('test-client').setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid }).sign(privateKey);
  assert.equal((await userinfo(idp, clientOnly)).statusCode, 401);
  // Unknown kid.
  const badKid = await base().setAudience('https://idp.test/userinfo').setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid: 'nope' }).sign(privateKey);
  assert.equal((await userinfo(idp, badKid)).statusCode, 401);
  // Expired.
  idp.clock.advance(901);
  const expired = await userinfo(idp, tokens.access_token);
  assert.equal(expired.statusCode, 401);
  assert.match(expired.headers['www-authenticate'], /error="invalid_token"/);
});
