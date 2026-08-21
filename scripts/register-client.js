import db from '../src/db.js';
import readline from 'readline/promises';
import fs from 'fs/promises';

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const clientId = await rl.question('Client ID: ');
const name = await rl.question('Client name: ');
const redirectUris = await rl.question('Redirect URIs (comma separated): ');
const scopes = 'openid profile telegram';
const policyFile = await rl.question('Path to policy JSON file (optional, press Enter to skip): ');

let policy = null;
if (policyFile.trim()) {
  try {
    policy = JSON.parse(await fs.readFile(policyFile.trim(), 'utf8'));
  } catch (e) {
    console.error('Invalid policy JSON:', e.message);
    process.exit(1);
  }
}

db.prepare('INSERT OR REPLACE INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, allowed_scopes, policy) VALUES (?, ?, ?, ?, ?, ?)')
  .run(clientId, null, name, JSON.stringify(redirectUris.split(',').map(s => s.trim())), scopes, policy ? JSON.stringify(policy) : null);

console.log('Client registered successfully.');
rl.close();
