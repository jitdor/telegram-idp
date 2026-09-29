#!/usr/bin/env node
// Manage signing keys in KEYS_DIR (default ./keys).
//
//   keys list                 show keys and which one is active
//   keys generate             add a new key (published in JWKS, not yet signing)
//   keys activate <kid>       make <kid> the signing key
//   keys retire <kid>         delete a non-active key
//
// Rollover: generate → restart and wait longer than clients cache the JWKS
// (the IdP sends max-age=300) → activate → restart → after the longest token
// lifetime (refresh tokens are opaque, so the access/ID token TTL) → retire.
import 'dotenv/config';
import { unlink } from 'node:fs/promises';
import path from 'node:path';
import { describeKeyDir, generateKeyFile, setActiveKey } from '../src/keys.js';

const dir = process.env.KEYS_DIR || './keys';
const [command, kid] = process.argv.slice(2);

async function main() {
  const keys = await describeKeyDir(dir).catch(() => []);
  switch (command) {
    case undefined:
    case 'list':
      if (keys.length === 0) console.log(`No keys in ${dir} (one is generated on first start).`);
      for (const k of keys) console.log(`${k.active ? '*' : ' '} ${k.kid}  ${k.file}`);
      return;
    case 'generate': {
      // Pin the current key as active first so adding a second one is unambiguous.
      const current = keys.find((k) => k.active);
      if (current) await setActiveKey(dir, current.kid);
      const newKid = await generateKeyFile(dir);
      if (!current) await setActiveKey(dir, newKid);
      console.log(`Generated ${newKid}${current ? ' (inactive; run "keys activate" after clients refresh the JWKS)' : ' (active)'}`);
      return;
    }
    case 'activate':
      if (!keys.some((k) => k.kid === kid)) throw new Error(`Unknown kid ${kid}`);
      await setActiveKey(dir, kid);
      console.log(`Activated ${kid}. Restart the server to start signing with it.`);
      return;
    case 'retire': {
      const key = keys.find((k) => k.kid === kid);
      if (!key) throw new Error(`Unknown kid ${kid}`);
      if (key.active) throw new Error('Refusing to retire the active key; activate another one first');
      const dupes = keys.filter((k) => k.kid === kid);
      for (const k of dupes) await unlink(path.join(dir, k.file));
      console.log(`Retired ${kid}. Restart the server to stop publishing it.`);
      return;
    }
    default:
      throw new Error(`Unknown command ${command}. Use list | generate | activate <kid> | retire <kid>`);
  }
}

main().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
