/**
 * Generic agent key management — the generalized form of `loadOrGenerateAgentKeys` from
 * `ublp-agent` (see AGENTS.md Section 3.3/4.2). Each agent instance represents its own DID
 * and keypair; the key file is per-deployment config, no central server holds everyone's keys.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import type { KeyPair } from '../crypto/documentCrypto';

export async function loadOrGenerateAgentKeys(keysPath: string, label = 'Agent'): Promise<KeyPair> {
  if (fs.existsSync(keysPath)) {
    const raw = await fs.promises.readFile(keysPath, 'utf-8');
    console.log(`[${label}] Loaded existing P-256 key.`);
    return JSON.parse(raw) as KeyPair;
  }
  console.log(`[${label}] Generating a new EC P-256 keypair...`);
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  const keys: KeyPair = { privateKey, publicKey };
  await fs.promises.mkdir(path.dirname(keysPath), { recursive: true });
  await fs.promises.writeFile(keysPath, JSON.stringify(keys, null, 2), 'utf-8');
  return keys;
}
