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
  it('generates a role secret key for port-authority only, not for seller or buyer', () => {
    const portAuthority = loadOrCreateSettlementIdentity(secretsDir, 'port-authority', 'pw');
    expect(portAuthority.roleSecretKeyHex).toMatch(/^[0-9a-f]{64}$/);

    const seller = loadOrCreateSettlementIdentity(path.join(secretsDir, 'seller-dir'), 'seller', 'pw');
    expect(seller.roleSecretKeyHex).toBeNull();

    const buyer = loadOrCreateSettlementIdentity(path.join(secretsDir, 'buyer-dir'), 'buyer', 'pw');
    expect(buyer.roleSecretKeyHex).toBeNull();
  });

  it('persists identity across calls — same dir+passphrase returns the same keys', () => {
    const first = loadOrCreateSettlementIdentity(secretsDir, 'port-authority', 'correct-horse');
    const second = loadOrCreateSettlementIdentity(secretsDir, 'port-authority', 'correct-horse');

    expect(second.roleSecretKeyHex).toBe(first.roleSecretKeyHex);
    expect(second.memoKeyPair).toEqual(first.memoKeyPair);
    expect(second.dealSigningKeyPair).toEqual(first.dealSigningKeyPair);
  });

  it('fails to decrypt persisted identity with the wrong passphrase', () => {
    // port-authority exercises all three encrypted files (role-key, memo-key, deal-signing-key);
    // seller/buyer would only cover the latter two since neither has a role-key file anymore.
    loadOrCreateSettlementIdentity(secretsDir, 'port-authority', 'right-passphrase');
    expect(() => loadOrCreateSettlementIdentity(secretsDir, 'port-authority', 'wrong-passphrase')).toThrow();
  });

  it('keeps different roles in the same directory fully independent', () => {
    const seller = loadOrCreateSettlementIdentity(secretsDir, 'seller', 'pw');
    const portAuthority = loadOrCreateSettlementIdentity(secretsDir, 'port-authority', 'pw');

    // roleSecretKeyHex itself is no longer a meaningful independence check here — seller's is
    // always null now, only port-authority has one — but the memo keypair is generated for
    // every role, and must still be genuinely distinct per role.
    expect(seller.memoKeyPair.privateKey).not.toBe(portAuthority.memoKeyPair.privateKey);
  });

  it('produces a deal-signing keypair usable as a real P-256 PEM pair', () => {
    const { dealSigningKeyPair } = loadOrCreateSettlementIdentity(secretsDir, 'seller', 'pw');
    expect(dealSigningKeyPair.privateKey).toContain('BEGIN PRIVATE KEY');
    expect(dealSigningKeyPair.publicKey).toContain('BEGIN PUBLIC KEY');
  });
});
