import crypto from 'crypto';
import { describe, it, expect } from 'vitest';
import { generateKeyPair } from '@ublp/shared';
import { AuthStore } from '../../src/server/auth.js';

/** Mirrors documentCrypto.ts's verifySignatureOverHash counterpart — there's no exported
 * "sign a raw hash" helper, so the test signs the same way that function expects to verify. */
function signHashHex(hashHex: string, privateKeyPem: string): string {
  return crypto
    .sign(null, Buffer.from(hashHex, 'hex'), { key: privateKeyPem, dsaEncoding: 'ieee-p1363' })
    .toString('base64');
}

describe('AuthStore — wallet-signature challenge-response (AGENTS.md 5.26)', () => {
  const operator = generateKeyPair();
  const attacker = generateKeyPair();

  it('completes a full challenge -> sign -> verify -> session round trip', () => {
    const auth = new AuthStore(operator.publicKey);
    const { challengeId, nonceHex } = auth.issueChallenge();

    const signature = signHashHex(nonceHex, operator.privateKey);
    const result = auth.verifyChallenge(challengeId, signature);

    expect(result).not.toBeNull();
    expect(auth.isSessionValid(result!.sessionToken)).toBe(true);
  });

  it('rejects a signature from a key that is not the registered operator key', () => {
    const auth = new AuthStore(operator.publicKey);
    const { challengeId, nonceHex } = auth.issueChallenge();

    const forgedSignature = signHashHex(nonceHex, attacker.privateKey);
    const result = auth.verifyChallenge(challengeId, forgedSignature);

    expect(result).toBeNull();
  });

  it('rejects reusing the same challenge twice (one-time use)', () => {
    const auth = new AuthStore(operator.publicKey);
    const { challengeId, nonceHex } = auth.issueChallenge();
    const signature = signHashHex(nonceHex, operator.privateKey);

    expect(auth.verifyChallenge(challengeId, signature)).not.toBeNull();
    expect(auth.verifyChallenge(challengeId, signature)).toBeNull();
  });

  it('rejects an unknown challengeId', () => {
    const auth = new AuthStore(operator.publicKey);
    expect(auth.verifyChallenge('does-not-exist', 'bogus')).toBeNull();
  });

  it('treats an unknown/expired session token as invalid', () => {
    const auth = new AuthStore(operator.publicKey);
    expect(auth.isSessionValid('never-issued')).toBe(false);
  });

  it('revokes a session on demand', () => {
    const auth = new AuthStore(operator.publicKey);
    const { challengeId, nonceHex } = auth.issueChallenge();
    const signature = signHashHex(nonceHex, operator.privateKey);
    const result = auth.verifyChallenge(challengeId, signature)!;

    auth.revokeSession(result.sessionToken);
    expect(auth.isSessionValid(result.sessionToken)).toBe(false);
  });
});
