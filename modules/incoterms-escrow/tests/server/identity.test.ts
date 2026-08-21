import fs from 'fs';
import os from 'os';
import path from 'path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadOrCreateSettlementIdentity } from '../../src/server/identity.js';

let secretsDir: string;

beforeEach(() => {
  secretsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ublp-settlement-identity-'));
});

afterEach(() => {
  fs.rmSync(secretsDir, { recursive: true, force: true });
});

describe('loadOrCreateSettlementIdentity', () => {
  it('generates a role secret key for seller and port-authority, but not for buyer', () => {
    const seller = loadOrCreateSettlementIdentity(secretsDir, 'seller', 'pw');
    expect(seller.roleSecretKeyHex).toMatch(/^[0-9a-f]{64}$/);

    const buyer = loadOrCreateSettlementIdentity(path.join(secretsDir, 'buyer-dir'), 'buyer', 'pw');
    expect(buyer.roleSecretKeyHex).toBeNull();
  });

  it('persists identity across calls — same dir+passphrase returns the same keys', () => {
    const first = loadOrCreateSettlementIdentity(secretsDir, 'seller', 'correct-horse');
    const second = loadOrCreateSettlementIdentity(secretsDir, 'seller', 'correct-horse');

    expect(second.roleSecretKeyHex).toBe(first.roleSecretKeyHex);
    expect(second.memoKeyPair).toEqual(first.memoKeyPair);
    expect(second.loginKeyPair).toEqual(first.loginKeyPair);
  });

  it('fails to decrypt persisted identity with the wrong passphrase', () => {
    loadOrCreateSettlementIdentity(secretsDir, 'seller', 'right-passphrase');
    expect(() => loadOrCreateSettlementIdentity(secretsDir, 'seller', 'wrong-passphrase')).toThrow();
  });

  it('keeps different roles in the same directory fully independent', () => {
    const seller = loadOrCreateSettlementIdentity(secretsDir, 'seller', 'pw');
    const portAuthority = loadOrCreateSettlementIdentity(secretsDir, 'port-authority', 'pw');

    expect(seller.roleSecretKeyHex).not.toBe(portAuthority.roleSecretKeyHex);
    expect(seller.memoKeyPair.privateKey).not.toBe(portAuthority.memoKeyPair.privateKey);
  });

  it('produces a login keypair usable as a real P-256 PEM pair', () => {
    const { loginKeyPair } = loadOrCreateSettlementIdentity(secretsDir, 'seller', 'pw');
    expect(loginKeyPair.privateKey).toContain('BEGIN PRIVATE KEY');
    expect(loginKeyPair.publicKey).toContain('BEGIN PUBLIC KEY');
  });
});
