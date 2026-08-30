import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { describe, it, expect, beforeEach } from 'vitest';
import { sampleSigningKey, signatureVerifyingKey, signData } from '@midnight-ntwrk/ledger-v8';
import { AuthStore } from '../../src/server/auth.js';

/** Signs a nonce the way a real wallet's DApp Connector `signData()` would — see auth.ts's
 * file header for why verifyChallenge checks "nonce is a substring of what was signed" rather
 * than exact equality: a real wallet may prepend its own domain-separation bytes, which this
 * helper simulates with an arbitrary prefix. */
function signNonce(sk: string, nonceHex: string, prefix = 'ublp-login:') {
  const nonceBytes = Buffer.from(nonceHex, 'hex');
  const prefixed = Buffer.concat([Buffer.from(prefix, 'utf8'), nonceBytes]);
  const signature = signData(sk, prefixed);
  return { signature, signedDataHex: prefixed.toString('hex'), verifyingKey: signatureVerifyingKey(sk) };
}

describe('AuthStore — wallet-signature challenge-response (AGENTS.md 5.26)', () => {
  const operatorKey = sampleSigningKey();
  const attackerKey = sampleSigningKey();
  let secretsDir: string;

  beforeEach(() => {
    secretsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ublp-settlement-auth-'));
  });

  it('completes a full challenge -> sign -> verify -> session round trip, bootstrapping the operator', () => {
    const auth = new AuthStore(secretsDir);
    const { challengeId, nonceHex } = auth.issueChallenge();

    const { signature, signedDataHex, verifyingKey } = signNonce(operatorKey, nonceHex);
    const result = auth.verifyChallenge(challengeId, signature, signedDataHex, verifyingKey);

    expect(result).not.toBeNull();
    expect(auth.isSessionValid(result!.sessionToken)).toBe(true);
  });

  it('persists the bootstrapped operator across separate AuthStore instances (same secretsDir)', () => {
    const first = new AuthStore(secretsDir);
    const c1 = first.issueChallenge();
    const s1 = signNonce(operatorKey, c1.nonceHex);
    expect(first.verifyChallenge(c1.challengeId, s1.signature, s1.signedDataHex, s1.verifyingKey)).not.toBeNull();

    // A fresh AuthStore instance over the same secretsDir must recognize the same operator —
    // and reject a different key — because it re-reads authorized-operator.json on construction.
    const second = new AuthStore(secretsDir);
    const c2 = second.issueChallenge();
    const s2 = signNonce(attackerKey, c2.nonceHex);
    expect(second.verifyChallenge(c2.challengeId, s2.signature, s2.signedDataHex, s2.verifyingKey)).toBeNull();
  });

  it('rejects a signature from a key that is not the registered operator key', () => {
    const auth = new AuthStore(secretsDir);
    const c1 = auth.issueChallenge();
    const s1 = signNonce(operatorKey, c1.nonceHex);
    expect(auth.verifyChallenge(c1.challengeId, s1.signature, s1.signedDataHex, s1.verifyingKey)).not.toBeNull();

    const c2 = auth.issueChallenge();
    const forged = signNonce(attackerKey, c2.nonceHex);
    const result = auth.verifyChallenge(c2.challengeId, forged.signature, forged.signedDataHex, forged.verifyingKey);

    expect(result).toBeNull();
  });

  it('rejects a well-formed signature whose signed data does not actually contain the issued nonce', () => {
    const auth = new AuthStore(secretsDir);
    const { challengeId } = auth.issueChallenge();

    // Valid signature, valid key, but over unrelated data — must not be accepted as proof of
    // this specific challenge.
    const unrelated = signNonce(operatorKey, crypto.randomBytes(32).toString('hex'));
    const result = auth.verifyChallenge(challengeId, unrelated.signature, unrelated.signedDataHex, unrelated.verifyingKey);

    expect(result).toBeNull();
  });

  it('rejects reusing the same challenge twice (one-time use)', () => {
    const auth = new AuthStore(secretsDir);
    const { challengeId, nonceHex } = auth.issueChallenge();
    const { signature, signedDataHex, verifyingKey } = signNonce(operatorKey, nonceHex);

    expect(auth.verifyChallenge(challengeId, signature, signedDataHex, verifyingKey)).not.toBeNull();
    expect(auth.verifyChallenge(challengeId, signature, signedDataHex, verifyingKey)).toBeNull();
  });

  it('rejects an unknown challengeId', () => {
    const auth = new AuthStore(secretsDir);
    expect(auth.verifyChallenge('does-not-exist', 'bogus', '00', 'bogus')).toBeNull();
  });

  it('treats an unknown/expired session token as invalid', () => {
    const auth = new AuthStore(secretsDir);
    expect(auth.isSessionValid('never-issued')).toBe(false);
  });

  it('revokes a session on demand', () => {
    const auth = new AuthStore(secretsDir);
    const { challengeId, nonceHex } = auth.issueChallenge();
    const { signature, signedDataHex, verifyingKey } = signNonce(operatorKey, nonceHex);
    const result = auth.verifyChallenge(challengeId, signature, signedDataHex, verifyingKey)!;

    auth.revokeSession(result.sessionToken);
    expect(auth.isSessionValid(result.sessionToken)).toBe(false);
  });
});
