import { describe, it, expect } from 'vitest';
import {
  blsGenerateKeyPair,
  blsSign,
  blsVerify,
  blsAggregateSignatures,
  blsAggregatePublicKeys,
  blsGroupKeyHash,
  blsVerifyThreshold,
} from '../../shared/src/crypto/blsCrypto';
import { TEST_BLS_MEMBER_IDS } from '../fixtures/keys';

function generateBLSKeyPairs(n: number): Array<{ privateKey: string; publicKey: string; memberId: string }> {
  return Array.from({ length: n }, (_, i) => ({
    ...blsGenerateKeyPair(),
    memberId: TEST_BLS_MEMBER_IDS[i] ?? `member-${i}`,
  }));
}

describe('blsGenerateKeyPair', () => {
  it('produces hex-encoded keys of correct lengths', () => {
    const kp = blsGenerateKeyPair();
    expect(kp.privateKey).toHaveLength(64);
    expect(kp.publicKey).toHaveLength(96);
    expect(/^[0-9a-f]{64}$/.test(kp.privateKey)).toBe(true);
    expect(/^[0-9a-f]{96}$/.test(kp.publicKey)).toBe(true);
  });

  it('produces distinct keys each time', () => {
    const a = blsGenerateKeyPair();
    const b = blsGenerateKeyPair();
    expect(a.privateKey).not.toBe(b.privateKey);
    expect(a.publicKey).not.toBe(b.publicKey);
  });
});

describe('blsSign / blsVerify', () => {
  it('signs and verifies a message correctly', async () => {
    const kp = blsGenerateKeyPair();
    const msg = 'aabbccdd' + '1122334455667788'.repeat(4);
    const sig = await blsSign(msg, kp.privateKey);
    expect(sig).toBeTruthy();
    expect(sig.length).toBeGreaterThan(0);

    const valid = await blsVerify(sig, msg, kp.publicKey);
    expect(valid).toBe(true);
  });

  it('rejects signature with wrong public key', async () => {
    const kp = blsGenerateKeyPair();
    const other = blsGenerateKeyPair();
    const msg = 'deadbeef' + '99'.repeat(16);
    const sig = await blsSign(msg, kp.privateKey);
    const valid = await blsVerify(sig, msg, other.publicKey);
    expect(valid).toBe(false);
  });

  it('rejects signature with wrong message', async () => {
    const kp = blsGenerateKeyPair();
    const msg = 'cafebabe' + '88'.repeat(16);
    const sig = await blsSign(msg, kp.privateKey);
    const valid = await blsVerify(sig, msg + 'ff', kp.publicKey);
    expect(valid).toBe(false);
  });
});

describe('blsAggregateSignatures', () => {
  it('aggregates multiple signatures', async () => {
    const members = generateBLSKeyPairs(3);
    const msg = 'aabb' + 'ccdd'.repeat(16);
    const sigs = await Promise.all(members.map((m) => blsSign(msg, m.privateKey)));

    const aggSig = blsAggregateSignatures(sigs);
    expect(aggSig).toBeTruthy();
    expect(typeof aggSig).toBe('string');
  });

  it('aggregated signature verifies against aggregated pubkey', async () => {
    const members = generateBLSKeyPairs(3);
    const msg = '1122' + '3344'.repeat(16);
    const sigs = await Promise.all(members.map((m) => blsSign(msg, m.privateKey)));

    const aggSig = blsAggregateSignatures(sigs);
    const aggPk = blsAggregatePublicKeys(members.map((m) => m.publicKey));
    const valid = await blsVerify(aggSig, msg, aggPk);
    expect(valid).toBe(true);
  });
});

describe('blsAggregatePublicKeys', () => {
  it('aggregates public keys', () => {
    const members = generateBLSKeyPairs(3);
    const pubs = members.map((m) => m.publicKey);
    const agg = blsAggregatePublicKeys(pubs);
    expect(agg).toHaveLength(96);
    expect(/^[0-9a-f]{96}$/.test(agg)).toBe(true);
  });

  it('aggregation order does not matter', () => {
    const members = generateBLSKeyPairs(3);
    const pubs = members.map((m) => m.publicKey);
    const agg1 = blsAggregatePublicKeys(pubs);
    const agg2 = blsAggregatePublicKeys([...pubs].reverse());
    expect(agg1).toBe(agg2);
  });
});

describe('blsGroupKeyHash', () => {
  it('produces a 64-char hex hash', () => {
    const members = generateBLSKeyPairs(3);
    const pubs = members.map((m) => m.publicKey);
    const hash = blsGroupKeyHash(pubs);
    expect(hash).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(hash)).toBe(true);
  });

  it('is order-independent (sorts internally)', () => {
    const members = generateBLSKeyPairs(3);
    const pubs = members.map((m) => m.publicKey);
    const hash1 = blsGroupKeyHash(pubs);
    const hash2 = blsGroupKeyHash([...pubs].reverse());
    expect(hash1).toBe(hash2);
  });

  it('changes when member keys change', () => {
    const members = generateBLSKeyPairs(3);
    const pubs = members.map((m) => m.publicKey);
    const hash1 = blsGroupKeyHash(pubs);

    const differentMember = blsGenerateKeyPair();
    const hash2 = blsGroupKeyHash([pubs[0], pubs[1], differentMember.publicKey]);
    expect(hash1).not.toBe(hash2);
  });
});

describe('blsVerifyThreshold', () => {
  it('passes with 2/3 threshold', async () => {
    const members = generateBLSKeyPairs(3);
    const msg = 'ff00' + 'ee'.repeat(16);
    const sigs = await Promise.all(members.map((m) => blsSign(msg, m.privateKey)));

    const aggSig = blsAggregateSignatures([sigs[0], sigs[1]]);
    const signerPubs = [members[0].publicKey, members[1].publicKey];

    const result = await blsVerifyThreshold(aggSig, msg, signerPubs, 2);
    expect(result.valid).toBe(true);
  });

  it('passes with 3/3 threshold', async () => {
    const members = generateBLSKeyPairs(3);
    const msg = 'aabb' + 'cc'.repeat(16);
    const sigs = await Promise.all(members.map((m) => blsSign(msg, m.privateKey)));

    const aggSig = blsAggregateSignatures(sigs);
    const signerPubs = members.map((m) => m.publicKey);

    const result = await blsVerifyThreshold(aggSig, msg, signerPubs, 3);
    expect(result.valid).toBe(true);
  });

  it('fails with insufficient signers (1 signer, threshold 2)', async () => {
    const members = generateBLSKeyPairs(3);
    const msg = '1122' + '33'.repeat(16);
    const sigs = await Promise.all(members.map((m) => blsSign(msg, m.privateKey)));

    const aggSig = blsAggregateSignatures([sigs[0]]);
    const signerPubs = [members[0].publicKey];

    const result = await blsVerifyThreshold(aggSig, msg, signerPubs, 2);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Eşik');
  });

  it('fails with wrong message', async () => {
    const members = generateBLSKeyPairs(3);
    const msg = 'abcd' + 'ef'.repeat(16);
    const sigs = await Promise.all(members.map((m) => blsSign(msg, m.privateKey)));

    const aggSig = blsAggregateSignatures([sigs[0], sigs[1]]);
    const signerPubs = [members[0].publicKey, members[1].publicKey];

    const result = await blsVerifyThreshold(aggSig, 'different' + '00'.repeat(16), signerPubs, 2);
    expect(result.valid).toBe(false);
  });

  it('fails with wrong signer public keys', async () => {
    const members = generateBLSKeyPairs(3);
    const outsiders = generateBLSKeyPairs(2);
    const msg = 'ffee' + 'dd'.repeat(16);
    const sigs = await Promise.all(members.map((m) => blsSign(msg, m.privateKey)));

    const aggSig = blsAggregateSignatures([sigs[0], sigs[1]]);
    const wrongPubs = [outsiders[0].publicKey, outsiders[1].publicKey];

    const result = await blsVerifyThreshold(aggSig, msg, wrongPubs, 2);
    expect(result.valid).toBe(false);
  });

  it('handles empty signer list gracefully', async () => {
    const result = await blsVerifyThreshold('', '00'.repeat(32), [], 2);
    expect(result.valid).toBe(false);
  });
});

describe('blsCrossPackage', () => {
  it('works with combinedSignatureHash output as message', async () => {
    const members = generateBLSKeyPairs(3);
    const msg = 'aa' + 'bb'.repeat(31);
    const sigs = await Promise.all(members.map((m) => blsSign(msg, m.privateKey)));
    const aggSig = blsAggregateSignatures([sigs[0], sigs[1]]);
    const signerPubs = [members[0].publicKey, members[1].publicKey];

    const result = await blsVerifyThreshold(aggSig, msg, signerPubs, 2);
    expect(result.valid).toBe(true);
  });
});
