import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import {
  generateKeyPair,
  signDocument,
  verifySignature,
  verifySignatureOverHash,
  sha256HashDocument,
  sha256Hash,
  combinedSignatureHash,
  holderProofHash,
  canonicalJson,
  generateMockZKProof,
  generateZKProof,
} from '../../shared/src/crypto/mockCrypto';

import {
  blsGenerateKeyPair,
  blsSign,
  blsVerify,
  blsAggregateSignatures,
  blsAggregatePublicKeys,
  blsGroupKeyHash,
  blsVerifyThreshold,
} from '../../shared/src/crypto/blsCrypto';

const ministryKeys = generateKeyPair();
const agentKeys = generateKeyPair();
const attackerKeys = generateKeyPair();

function createSampleDoc(id: string, val?: string) {
  return {
    documentId: id,
    holderDid: 'did:ublp:agent:test',
    exporterName: 'Test Co.',
    totalValue: val ?? '10000 USD',
  };
}

describe('Negative: Signature Attacks', () => {
  it('rejects signature with wrong document content (post-approval tampering)', () => {
    const doc = createSampleDoc('DOC-NEG-001');
    const docIdHash = sha256Hash(doc.documentId);
    const sig = signDocument(doc, ministryKeys.privateKey, docIdHash);

    const tamperedDoc = { ...doc, totalValue: '99999999 USD' };
    const isValid = verifySignature(tamperedDoc, sig, ministryKeys.publicKey, docIdHash);
    expect(isValid).toBe(false);
  });

  it('rejects replay with same documentId but different content', () => {
    const doc1 = createSampleDoc('DOC-NEG-002', '10000 USD');
    const doc2 = createSampleDoc('DOC-NEG-002', '99999999 USD');
    const idHash = sha256Hash('DOC-NEG-002');

    const sig1 = signDocument(doc1, ministryKeys.privateKey, idHash);
    const sig2 = signDocument(doc2, attackerKeys.privateKey, idHash);

    const validForDoc1 = verifySignature(doc1, sig1, ministryKeys.publicKey, idHash);
    const validForDoc2 = verifySignature(doc2, sig2, ministryKeys.publicKey, idHash);

    expect(validForDoc1).toBe(true);
    expect(validForDoc2).toBe(false);
  });

  it('rejects signature from different key', () => {
    const doc = createSampleDoc('DOC-NEG-003');
    const idHash = sha256Hash(doc.documentId);
    const attackerSig = signDocument(doc, attackerKeys.privateKey, idHash);

    const isValid = verifySignature(doc, attackerSig, ministryKeys.publicKey, idHash);
    expect(isValid).toBe(false);
  });

  it('rejects signature on wrong documentIdHash', () => {
    const doc = createSampleDoc('DOC-NEG-004');
    const idHash = sha256Hash(doc.documentId);
    const wrongIdHash = sha256Hash('different-doc-id');
    const sig = signDocument(doc, ministryKeys.privateKey, idHash);

    const isValid = verifySignature(doc, sig, ministryKeys.publicKey, wrongIdHash);
    expect(isValid).toBe(false);
  });

  it('verifySignatureOverHash rejects wrong combined hash', () => {
    const doc = createSampleDoc('DOC-NEG-005');
    const docHash = sha256HashDocument(doc);
    const idHash = sha256Hash(doc.documentId);
    const sig = signDocument(doc, ministryKeys.privateKey, idHash);

    const wrongCombined = combinedSignatureHash(sha256Hash('wrong-doc'), idHash);
    const valid = verifySignatureOverHash(wrongCombined, sig, ministryKeys.publicKey);
    expect(valid).toBe(false);
  });
});

describe('Negative: ZK Proof Attacks', () => {
  const doc = createSampleDoc('DOC-ZK-NEG-001');
  const docHash = sha256HashDocument(doc);
  const idHash = sha256Hash(doc.documentId);
  const validSig = signDocument(doc, ministryKeys.privateKey, idHash);

  // Holder sig must be over holderProofHash (not signDocument), matching ZK circuit
  const holderPayload = holderProofHash(docHash, idHash, 'did:ublp:agent:test');
  const holderSigBuffer = crypto.sign(null, Buffer.from(holderPayload, 'hex'),
    { key: agentKeys.privateKey, dsaEncoding: 'ieee-p1363' });
  const holderSig = holderSigBuffer.toString('base64');

  it('ZK proof fails with invalid ministry signature', () => {
    const wrongSig = signDocument(doc, attackerKeys.privateKey, idHash);
    const proof = generateMockZKProof(
      { rawDocument: doc, salt: '', signature: wrongSig, holderSignature: holderSig, holderPublicKey: agentKeys.publicKey, holderDid: 'did:ublp:agent:test' },
      { documentHash: docHash, ministryPublicKey: ministryKeys.publicKey, documentIdHash: idHash }
    );
    expect(proof.status).toBe('failed');
    expect(proof.signature_valid).toBe(false);
  });

  it('ZK proof without holder auth still generates proof with empty holderPubKeyHash', () => {
    const proof = generateMockZKProof(
      { rawDocument: doc, salt: '', signature: validSig },
      { documentHash: docHash, ministryPublicKey: ministryKeys.publicKey, documentIdHash: idHash }
    );
    expect(proof.status).toBe('verified');
    expect(proof.holderPubKeyHash).toBe('');
  });

  it('ZK proof fails with wrong holder public key', () => {
    expect(() => {
      generateMockZKProof(
        { rawDocument: doc, salt: '', signature: validSig, holderSignature: holderSig, holderPublicKey: attackerKeys.publicKey, holderDid: 'did:ublp:agent:test' },
        { documentHash: docHash, ministryPublicKey: ministryKeys.publicKey, documentIdHash: idHash }
      );
    }).toThrow('holder');
  });

  it('ZK proof holder binding - wrong DID breaks verification', () => {
    const wrongDidSig = crypto.sign(
      null,
      Buffer.from(holderProofHash(docHash, idHash, 'did:ublp:agent:attacker'), 'hex'),
      { key: agentKeys.privateKey, dsaEncoding: 'ieee-p1363' }
    ).toString('base64');

    expect(() => {
      generateMockZKProof(
        { rawDocument: doc, salt: '', signature: validSig, holderSignature: wrongDidSig, holderPublicKey: agentKeys.publicKey, holderDid: 'did:ublp:agent:test' },
        { documentHash: docHash, ministryPublicKey: ministryKeys.publicKey, documentIdHash: idHash }
      );
    }).toThrow('holder');
  });
});

describe('Negative: BLS Attacks', () => {
  it('BLS verify rejects wrong public key', async () => {
    const kp = blsGenerateKeyPair();
    const msg = 'aa' + 'bb'.repeat(31);
    const sig = await blsSign(msg, kp.privateKey);
    const other = blsGenerateKeyPair();
    const valid = await blsVerify(sig, msg, other.publicKey);
    expect(valid).toBe(false);
  });

  it('BLS verify rejects wrong message', async () => {
    const kp = blsGenerateKeyPair();
    const msg = 'cc' + 'dd'.repeat(31);
    const sig = await blsSign(msg, kp.privateKey);
    const valid = await blsVerify(sig, msg + 'ff', kp.publicKey);
    expect(valid).toBe(false);
  });

  it('BLS threshold rejects too few signers', async () => {
    const members = [blsGenerateKeyPair(), blsGenerateKeyPair(), blsGenerateKeyPair()];
    const msg = 'ee' + 'ff'.repeat(31);
    const sigs = await Promise.all(members.map((m) => blsSign(msg, m.privateKey)));

    const aggSig = blsAggregateSignatures([sigs[0]]);
    const result = await blsVerifyThreshold(aggSig, msg, [members[0].publicKey], 2);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Eşik');
  });

  it('BLS threshold rejects wrong signer subset (attacker pubkeys)', async () => {
    const members = [blsGenerateKeyPair(), blsGenerateKeyPair(), blsGenerateKeyPair()];
    const attackers = [blsGenerateKeyPair(), blsGenerateKeyPair()];
    const msg = '00' + '11'.repeat(31);
    const sigs = await Promise.all(members.map((m) => blsSign(msg, m.privateKey)));

    const aggSig = blsAggregateSignatures([sigs[0], sigs[1]]);
    const wrongPubs = [attackers[0].publicKey, attackers[1].publicKey];
    const result = await blsVerifyThreshold(aggSig, msg, wrongPubs, 2);
    expect(result.valid).toBe(false);
  });

  it('BLS aggregate with empty signature list throws', () => {
    expect(() => blsAggregateSignatures([])).toThrow();
  });

  it('BLS groupKeyHash changes when any key changes', () => {
    const members = [blsGenerateKeyPair(), blsGenerateKeyPair(), blsGenerateKeyPair()];
    const original = blsGroupKeyHash(members.map(m => m.publicKey));

    const modified = [members[0].publicKey, members[1].publicKey, blsGenerateKeyPair().publicKey];
    const modifiedHash = blsGroupKeyHash(modified);
    expect(original).not.toBe(modifiedHash);
  });
});

describe('Negative: Document Hash Attacks', () => {
  it('sha256HashDocument domain separation prevents cross-protocol collision', () => {
    const doc = createSampleDoc('DOC-HASH-001');
    const docHash = sha256HashDocument(doc);
    const plainHash = sha256Hash(canonicalJson(doc));
    expect(docHash).not.toBe(plainHash);
  });

  it('holderProofHash binds holder DID to prevent MitM', () => {
    const docHash = sha256HashDocument(createSampleDoc('DOC-MITM-001'));
    const idHash = sha256Hash('DOC-MITM-001');
    const hashAlice = holderProofHash(docHash, idHash, 'did:ublp:agent:alice');
    const hashBob = holderProofHash(docHash, idHash, 'did:ublp:agent:bob');
    expect(hashAlice).not.toBe(hashBob);
  });

  it('different document IDs produce different hashes', () => {
    const doc1 = createSampleDoc('DOC-HASH-002');
    const doc2 = createSampleDoc('DOC-HASH-003');
    const h1 = sha256HashDocument(doc1);
    const h2 = sha256HashDocument(doc2);
    expect(h1).not.toBe(h2);
  });

  it('combinedSignatureHash is collision-resistant', () => {
    const h1 = combinedSignatureHash('aa'.repeat(32), 'bb'.repeat(32));
    const h2 = combinedSignatureHash('aa'.repeat(32), 'cc'.repeat(32));
    expect(h1).not.toBe(h2);
  });
});

describe('Negative: Key Generation Edge Cases', () => {
  it('consecutive key generations produce different keys', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 10; i++) {
      const kp = generateKeyPair();
      expect(seen.has(kp.publicKey)).toBe(false);
      seen.add(kp.publicKey);
    }
  });

  it('P-256 ECDSA signature is 64 bytes (IEEE P1363)', () => {
    const doc = createSampleDoc('DOC-SIG-SIZE');
    const idHash = sha256Hash(doc.documentId);
    const sig = signDocument(doc, ministryKeys.privateKey, idHash);
    const sigBytes = Buffer.from(sig, 'base64');
    expect(sigBytes.length).toBe(64);
  });
});

describe('Negative: L2 Edge Cases', () => {
  it('verifySignature returns false for malformed signatures', () => {
    const result = verifySignature(
      createSampleDoc('DOC-MALFORMED'),
      'not-a-valid-base64-signature!!!',
      ministryKeys.publicKey,
      sha256Hash('DOC-MALFORMED')
    );
    expect(result).toBe(false);
  });

  it('verifySignature returns false for empty public key', () => {
    const doc = createSampleDoc('DOC-EMPTYKEY');
    const idHash = sha256Hash(doc.documentId);
    const sig = signDocument(doc, ministryKeys.privateKey, idHash);
    const result = verifySignature(doc, sig, '', idHash);
    expect(result).toBe(false);
  });

  it('verifySignatureOverHash handles invalid signature gracefully', () => {
    const result = verifySignatureOverHash(
      '00'.repeat(32),
      'invalid-base64!!',
      ministryKeys.publicKey
    );
    expect(result).toBe(false);
  });
});
