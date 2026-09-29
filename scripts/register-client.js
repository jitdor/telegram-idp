#!/usr/bin/env node
// Register (or update) an OAuth client.
//
// Non-interactive (for deployments / CI):
//   node scripts/register-client.js --client-id my-app --name "My App" \
//     --redirect-uri https://app.example.com/callback [--redirect-uri …] \
//     [--scopes "openid profile telegram offline_access"] \
//     [--secret <secret> | --generate-secret] [--first-party] \
//     [--policy-file policy.json | --policy '<json>'] [--db ./data.db]
//
// Every flag can also come from the environment: CLIENT_ID, CLIENT_NAME,
// CLIENT_REDIRECT_URIS (comma separated), CLIENT_SCOPES, CLIENT_SECRET,
// CLIENT_GENERATE_SECRET=1, CLIENT_FIRST_PARTY=1, CLIENT_POLICY_FILE, CLIENT_POLICY, DB_PATH.
// Missing required values are prompted for only when stdin is a TTY (or with --interactive).
import 'dotenv/config';
import { readFile } from 'node:fs/promises';
import readline from 'node:readline/promises';
import { parseArgs } from 'node:util';
import { SUPPORTED_SCOPES } from '../src/config.js';
import { registerClient } from '../src/clients.js';
import { createDatabase } from '../src/db.js';
import { createSqliteStore } from '../src/store.js';

const HELP = `Usage: register-client [options]
  --client-id <id>          Client identifier (env CLIENT_ID)
  --name <name>             Display name shown to users (env CLIENT_NAME)
  --redirect-uri <uri>      Redirect URI; repeat for several (env CLIENT_REDIRECT_URIS, comma separated)
  --scopes <list>           Allowed scopes (default "${SUPPORTED_SCOPES.join(' ')}") (env CLIENT_SCOPES)
  --secret <secret>         Confidential client secret, min 16 chars (env CLIENT_SECRET)
  --generate-secret         Generate a random secret and print it once (env CLIENT_GENERATE_SECRET=1)
  --first-party             Skip the consent prompt once the user has consented (env CLIENT_FIRST_PARTY=1)
  --policy-file <path>      JSON policy file (env CLIENT_POLICY_FILE)
  --policy <json>           Inline JSON policy (env CLIENT_POLICY)
  --db <path>               SQLite database (env DB_PATH, default ./data.db)
  --interactive             Prompt for missing values even without a TTY
  --json                    Print the result as JSON
  -h, --help                Show this help`;

const { values } = parseArgs({
  options: {
    'client-id': { type: 'string' },
    name: { type: 'string' },
    'redirect-uri': { type: 'string', multiple: true },
    scopes: { type: 'string' },
    secret: { type: 'string' },
    'generate-secret': { type: 'boolean' },
    'first-party': { type: 'boolean' },
    'policy-file': { type: 'string' },
    policy: { type: 'string' },
    db: { type: 'string' },
    interactive: { type: 'boolean' },
    json: { type: 'boolean' },
    help: { type: 'boolean', short: 'h' },
  },
});

if (values.help) {
  console.log(HELP);
  process.exit(0);
}

const env = process.env;
const truthy = (v) => ['1', 'true', 'yes', 'y'].includes(String(v ?? '').toLowerCase());
const input = {
  clientId: values['client-id'] ?? env.CLIENT_ID,
  name: values.name ?? env.CLIENT_NAME,
  redirectUris: values['redirect-uri'] ?? (env.CLIENT_REDIRECT_URIS ? env.CLIENT_REDIRECT_URIS.split(',') : undefined),
  scopes: values.scopes ?? env.CLIENT_SCOPES,
  secret: values.secret ?? env.CLIENT_SECRET,
  generateSecret: values['generate-secret'] ?? truthy(env.CLIENT_GENERATE_SECRET),
  firstParty: values['first-party'] ?? truthy(env.CLIENT_FIRST_PARTY),
  policyFile: values['policy-file'] ?? env.CLIENT_POLICY_FILE,
  policy: values.policy ?? env.CLIENT_POLICY,
};

const interactive = values.interactive || process.stdin.isTTY;
const missing = () => !input.clientId || !input.name || !input.redirectUris?.length;

if (missing() && interactive) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  input.clientId ||= await rl.question('Client ID: ');
  input.name ||= await rl.question('Client name: ');
  if (!input.redirectUris?.length) input.redirectUris = (await rl.question('Redirect URIs (comma separated): ')).split(',');
  input.scopes ??= (await rl.question(`Allowed scopes [${SUPPORTED_SCOPES.join(' ')}]: `)) || undefined;
  if (!input.secret && !input.generateSecret) {
    const s = await rl.question('Client secret (Enter for a public client, "generate" for a random one): ');
    if (s.trim() === 'generate') input.generateSecret = true;
    else input.secret = s.trim() || undefined;
  }
  if (!input.firstParty) input.firstParty = truthy(await rl.question('Is this a first-party client? (y/N): '));
  if (!input.policyFile && !input.policy) input.policyFile = (await rl.question('Policy JSON file (Enter to skip): ')).trim() || undefined;
  rl.close();
}

if (missing()) {
  console.error('Missing required --client-id, --name or --redirect-uri.\n');
  console.error(HELP);
  process.exit(2);
}

try {
  let policy = null;
  if (input.policyFile) policy = JSON.parse(await readFile(input.policyFile, 'utf8'));
  else if (input.policy) policy = JSON.parse(input.policy);

  const db = createDatabase(values.db ?? env.DB_PATH ?? './data.db');
  const store = createSqliteStore(db);
  const existed = !!store.getClient(input.clientId);
  const result = await registerClient(store, { ...input, policy });
  db.close();

  if (values.json) {
    console.log(JSON.stringify({ client_id: result.clientId, client_secret: result.secret, updated: existed }));
  } else {
    console.log(`Client ${result.clientId} ${existed ? 'updated' : 'registered'}.`);
    if (input.generateSecret) console.log(`Client secret (shown once, store it now): ${result.secret}`);
  }
} catch (err) {
  console.error(`Error: ${err.message}`);
  process.exit(1);
}
