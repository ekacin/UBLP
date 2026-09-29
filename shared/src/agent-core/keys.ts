/**
 * Generic agent key management — the generalized form of `loadOrGenerateAgentKeys` from
 * `ublp-agent` (see AGENTS.md Section 3.3/4.2). Each agent instance represents its own DID
 * and keypair; the key file is per-deployment config, no central server holds everyone's keys.
 *
 * `passphrase` is optional, mirroring Ministry's own key-storage UX (see ministry/src/index.ts):
 * unset -> plaintext JSON with a console warning (dev only), set -> encrypted at rest via
 * @ublp/shared's walletKeyStorage (the same helper Ministry itself migrated to). The on-disk
 * format is auto-detected on load (an encrypted file has a `ct` field; a legacy plaintext file
 * has `privateKey`/`publicKey` directly) so an existing plaintext key file keeps working and
 * transparently upgrades the moment a passphrase is supplied.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import type { KeyPair } from '../crypto/documentCrypto';
import { encryptSecretHex, decryptSecretHex } from '../crypto/walletKeyStorage';

export async function loadOrGenerateAgentKeys(keysPath: string, label = 'Agent', passphrase = ''): Promise<KeyPair> {
  if (!passphrase) {
    console.warn(`[${label}] Key passphrase not set — private key unencrypted at rest (dev only).`);
  }

  if (fs.existsSync(keysPath)) {
    const rawText = await fs.promises.readFile(keysPath, 'utf-8');
    const raw = JSON.parse(rawText) as { ct?: string } | KeyPair;

    if ('ct' in raw) {
      if (!passphrase) throw new Error(`[${label}] Encrypted key file found but no passphrase was provided.`);
      const keys = JSON.parse(decryptSecretHex(rawText, passphrase)) as KeyPair;
      console.log(`[${label}] Loaded and decrypted existing P-256 key.`);
      return keys;
    }

    const keys = raw as KeyPair;
    if (passphrase) {
      console.warn(`[${label}] Legacy plaintext key file — migrating to encrypted format...`);
      await persistAgentKeys(keysPath, keys, passphrase);
    } else {
      console.log(`[${label}] Loaded existing P-256 key.`);
    }
    return keys;
  }

  console.log(`[${label}] Generating a new EC P-256 keypair...`);
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  const keys: KeyPair = { privateKey, publicKey };
  await persistAgentKeys(keysPath, keys, passphrase);
  return keys;
}

async function persistAgentKeys(keysPath: string, keys: KeyPair, passphrase: string): Promise<void> {
  await fs.promises.mkdir(path.dirname(keysPath), { recursive: true });
  const content = passphrase ? encryptSecretHex(JSON.stringify(keys), passphrase) : JSON.stringify(keys, null, 2);
  await fs.promises.writeFile(keysPath, content, 'utf-8');
}
