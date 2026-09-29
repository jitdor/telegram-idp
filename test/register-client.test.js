import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { createDatabase } from '../src/db.js';
import { createSqliteStore } from '../src/store.js';
import { verifySecret } from '../src/secrets.js';

const run = promisify(execFile);
const SCRIPT = new URL('../scripts/register-client.js', import.meta.url).pathname;

async function cli(args, env = {}) {
  try {
    const { stdout, stderr } = await run(process.execPath, ['--disable-warning=ExperimentalWarning', SCRIPT, ...args], {
      env: { PATH: process.env.PATH, ...env },
    });
    return { code: 0, stdout, stderr };
  } catch (err) {
    return { code: err.code, stdout: err.stdout, stderr: err.stderr };
  }
}

async function tmp(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'tgidp-cli-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

test('register-client works non-interactively from flags', async (t) => {
  const dir = await tmp(t);
  const db = path.join(dir, 'idp.db');
  const policy = path.join(dir, 'policy.json');
  await writeFile(policy, JSON.stringify({ type: 'is_premium', value: true }));
  const res = await cli(['--db', db, '--client-id', 'app', '--name', 'App',
    '--redirect-uri', 'https://app.test/cb', '--redirect-uri', 'http://localhost:5173/cb',
    '--scopes', 'openid profile', '--generate-secret', '--first-party', '--policy-file', policy, '--json']);
  assert.equal(res.code, 0, res.stderr);
  const out = JSON.parse(res.stdout);
  assert.equal(out.client_id, 'app');
  assert.ok(out.client_secret.length >= 32);

  const store = createSqliteStore(createDatabase(db));
  const client = store.getClient('app');
  assert.deepEqual(client.redirectUris, ['https://app.test/cb', 'http://localhost:5173/cb']);
  assert.deepEqual(client.allowedScopes, ['openid', 'profile']);
  assert.equal(client.isFirstParty, true);
  assert.deepEqual(client.policy, { type: 'is_premium', value: true });
  assert.equal((await verifySecret(out.client_secret, client.secretHash)).ok, true);
  store.db.close();
});

test('register-client reads the environment', async (t) => {
  const dir = await tmp(t);
  const db = path.join(dir, 'idp.db');
  const res = await cli([], {
    DB_PATH: db, CLIENT_ID: 'env-app', CLIENT_NAME: 'Env App',
    CLIENT_REDIRECT_URIS: 'https://a.test/cb,https://b.test/cb',
  });
  assert.equal(res.code, 0, res.stderr);
  const store = createSqliteStore(createDatabase(db));
  assert.deepEqual(store.getClient('env-app').redirectUris, ['https://a.test/cb', 'https://b.test/cb']);
  assert.equal(store.getClient('env-app').secretHash, null);
  store.db.close();
});

test('register-client validates input', async (t) => {
  const dir = await tmp(t);
  const db = path.join(dir, 'idp.db');
  const base = ['--db', db, '--client-id', 'x', '--name', 'X'];
  assert.match((await cli([...base, '--redirect-uri', 'http://evil.test/cb'])).stderr, /must use https/);
  assert.match((await cli([...base, '--redirect-uri', 'https://a.test/cb#x'])).stderr, /fragment/);
  assert.match((await cli([...base, '--redirect-uri', 'https://a.test/cb', '--scopes', 'openid admin'])).stderr, /Unsupported scopes/);
  assert.match((await cli([...base, '--redirect-uri', 'https://a.test/cb', '--policy', '{"type":"nope"}'])).stderr, /not a known condition/);
  assert.match((await cli([...base, '--redirect-uri', 'https://a.test/cb', '--secret', 'short'])).stderr, /at least 16/);
  const missing = await cli(['--db', db, '--client-id', 'x']);
  assert.equal(missing.code, 2);
});
