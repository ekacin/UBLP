/**
 * Generic encrypted-secret-at-rest storage — AGENTS.md Section 5.21.
 *
 * Generalizes the AES-256-GCM + PBKDF2 pattern committee/index.ts and ministry/index.ts each
 * hand-rolled for their own BLS/ECDSA keys, so wallet seeds (and any future per-agent secret)
 * reuse the same proven scheme instead of a third copy.
 *
 * What this does and doesn't protect against: encrypting the file stops a stolen disk/backup
 * from exposing the secret — the passphrase itself still has to come from somewhere (env var,
 * a human, a secrets manager). Whatever protects the passphrase is where the real trust
 * boundary lives; this module only handles the encrypt/decrypt step. See AGENTS.md 5.21 for
 * the full discussion, including why production should move to KMS/HSM instead of a
 * passphrase-based file.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

export interface EncryptedPayload {
  salt: string;
  iv: string;
  tag: string;
  ct: string;
}

const PBKDF2_ITERATIONS = 600_000;

function deriveKey(passphrase: string, saltHex: string): Buffer {
  return crypto.pbkdf2Sync(passphrase, Buffer.from(saltHex, 'hex'), PBKDF2_ITERATIONS, 32, 'sha512');
}

export function encryptSecretHex(hexValue: string, passphrase: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const iv = crypto.randomBytes(12);
  const key = deriveKey(passphrase, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(hexValue, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const payload: EncryptedPayload = {
    salt,
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    ct: ct.toString('hex'),
  };
  return JSON.stringify(payload);
}

export function decryptSecretHex(encryptedJson: string, passphrase: string): string {
  const { salt, iv, tag, ct } = JSON.parse(encryptedJson) as EncryptedPayload;
  const key = deriveKey(passphrase, salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(ct, 'hex')), decipher.final()]).toString('utf8');
}

/**
 * Loads a hex secret from `filePath`, decrypting it with `passphrase`. If the file doesn't
 * exist yet, generates one via `generateSecretHex`, encrypts it, and writes it with
 * owner-only permissions (0o600) before returning it — so callers never have to special-case
 * "first run" themselves.
 */
export function loadOrCreateEncryptedSecret(
  filePath: string,
  passphrase: string,
  generateSecretHex: () => string
): string {
  if (fs.existsSync(filePath)) {
    return decryptSecretHex(fs.readFileSync(filePath, 'utf8'), passphrase);
  }
  const secretHex = generateSecretHex();
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, encryptSecretHex(secretHex, passphrase), { mode: 0o600 });
  return secretHex;
}
