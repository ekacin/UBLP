import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  encryptSecretHex,
  decryptSecretHex,
  loadOrCreateEncryptedSecret,
} from '../../../../shared/src/crypto/walletKeyStorage';

const tmpFiles: string[] = [];

function tmpPath(name: string): string {
  const p = path.join(os.tmpdir(), `ublp-wallet-key-storage-${Date.now()}-${name}`);
  tmpFiles.push(p);
  return p;
}

afterEach(() => {
  for (const f of tmpFiles.splice(0)) {
    fs.rmSync(f, { force: true });
  }
});

describe('encryptSecretHex / decryptSecretHex', () => {
  it('round-trips a hex secret', () => {
    const secret = 'a1b2c3d4'.repeat(8);
    const encrypted = encryptSecretHex(secret, 'correct horse battery staple');
    expect(decryptSecretHex(encrypted, 'correct horse battery staple')).toBe(secret);
  });

  it('produces different ciphertext each time (fresh salt/iv)', () => {
    const secret = 'a1b2c3d4'.repeat(8);
    const a = encryptSecretHex(secret, 'pw');
    const b = encryptSecretHex(secret, 'pw');
    expect(a).not.toBe(b);
  });

  it('rejects the wrong passphrase', () => {
    const encrypted = encryptSecretHex('deadbeef', 'right-passphrase');
    expect(() => decryptSecretHex(encrypted, 'wrong-passphrase')).toThrow();
  });
});

describe('loadOrCreateEncryptedSecret', () => {
  it('generates and persists a secret on first call, reuses it on subsequent calls', () => {
    const file = tmpPath('seed.json');
    let generateCalls = 0;
    const generate = () => {
      generateCalls++;
      return 'feedface'.repeat(8);
    };

    const first = loadOrCreateEncryptedSecret(file, 'pw', generate);
    const second = loadOrCreateEncryptedSecret(file, 'pw', generate);

    expect(first).toBe('feedface'.repeat(8));
    expect(second).toBe(first);
    expect(generateCalls).toBe(1); // generator only invoked once, file reused after that
  });

  it('writes the file with owner-only permissions', () => {
    const file = tmpPath('seed-perms.json');
    loadOrCreateEncryptedSecret(file, 'pw', () => 'abcd1234');
    const mode = fs.statSync(file).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it('fails to load with the wrong passphrase', () => {
    const file = tmpPath('seed-wrong-pw.json');
    loadOrCreateEncryptedSecret(file, 'right-pw', () => 'abcd1234');
    expect(() => loadOrCreateEncryptedSecret(file, 'wrong-pw', () => 'abcd1234')).toThrow();
  });
});
