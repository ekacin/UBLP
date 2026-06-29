import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import {
  canonicalJson,
  sha256Hash,
  sha256HashDocument,
  combinedSignatureHash,
  holderProofHash,
  generateKeyPair,
  signDocument,
  verifySignature,
  verifySignatureOverHash,
  generateMockZKProof,
} from '../../shared/src/crypto/mockCrypto';
import {
  SAMPLE_CUSTOMS_DOCUMENT,
  SAMPLE_DOCUMENT_ID,
  SAMPLE_HOLDER_DID,
} from '../fixtures/sample-documents';
import { TEST_MINISTRY_KEYS, TEST_AGENT_KEYS, TEST_UNAUTHORIZED_KEYS } from '../fixtures/keys';

describe('canonicalJson', () => {
  it('sorts object keys alphabetically', () => {
    const unordered: Record<string, unknown> = { z: 1, a: 2, m: 3 };
    const ordered = canonicalJson(unordered);
    expect(ordered).toBe('{"a":2,"m":3,"z":1}');
  });

  it('handles nested objects', () => {
    const nested = { b: { y: 1, x: 2 }, a: 3 };
    expect(canonicalJson(nested)).toBe('{"a":3,"b":{"x":2,"y":1}}');
  });

  it('handles arrays without sorting', () => {
    const withArray = { items: [3, 1, 2], id: 'test' };
    expect(canonicalJson(withArray)).toBe('{"id":"test","items":[3,1,2]}');
  });

  it('handles null and primitive values', () => {
    expect(canonicalJson(null)).toBe('null');
    expect(canonicalJson('hello')).toBe('"hello"');
    expect(canonicalJson(42)).toBe('42');
    expect(canonicalJson(true)).toBe('true');
  });

  it('produces deterministic output for same object', () => {
    const obj = { name: 'test', value: 42, nested: { a: 1, b: 2 } };
    const first = canonicalJson(obj);
    const second = canonicalJson({ ...obj });
    expect(first).toBe(second);
  });
});

describe('sha256Hash', () => {
  it('produces a 64-character hex string', () => {
    const hash = sha256Hash('test-input');
    expect(hash).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(hash)).toBe(true);
  });

  it('is deterministic', () => {
    expect(sha256Hash('hello')).toBe(sha256Hash('hello'));
  });

  it('changes when input changes', () => {
    expect(sha256Hash('hello')).not.toBe(sha256Hash('world'));
  });

  it('hashes objects via canonical JSON', () => {
    const objHash = sha256Hash({ a: 1, b: 2 });
    const canonical = sha256Hash(canonicalJson({ a: 1, b: 2 }));
    expect(objHash).toBe(canonical);
  });
});

describe('sha256HashDocument', () => {
  it('uses domain-separated prefix ublp-doc-v1:', () => {
    const docHash = sha256HashDocument(SAMPLE_CUSTOMS_DOCUMENT);
    expect(docHash).toHaveLength(64);

    const canonical = canonicalJson(SAMPLE_CUSTOMS_DOCUMENT);
    const expected = sha256Hash('ublp-doc-v1:' + canonical);
    expect(docHash).toBe(expected);
  });

  it('differs from plain sha256Hash of the same document', () => {
    const docHash = sha256HashDocument(SAMPLE_CUSTOMS_DOCUMENT);
    const plainHash = sha256Hash(canonicalJson(SAMPLE_CUSTOMS_DOCUMENT));
    expect(docHash).not.toBe(plainHash);
  });

  it('is deterministic for the same document', () => {
    const a = sha256HashDocument(SAMPLE_CUSTOMS_DOCUMENT);
    const b = sha256HashDocument({ ...SAMPLE_CUSTOMS_DOCUMENT });
    expect(a).toBe(b);
  });
});

describe('combinedSignatureHash', () => {
  it('produces 64-char hex from two hash inputs', () => {
    const docHash = sha256HashDocument(SAMPLE_CUSTOMS_DOCUMENT);
    const idHash = sha256Hash(SAMPLE_DOCUMENT_ID);
    const combined = combinedSignatureHash(docHash, idHash);
    expect(combined).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(combined)).toBe(true);
  });

  it('is deterministic', () => {
    const docHash = sha256HashDocument(SAMPLE_CUSTOMS_DOCUMENT);
    const idHash = sha256Hash(SAMPLE_DOCUMENT_ID);
    expect(combinedSignatureHash(docHash, idHash)).toBe(combinedSignatureHash(docHash, idHash));
  });

  it('changes when document hash changes', () => {
    const docHash1 = sha256HashDocument(SAMPLE_CUSTOMS_DOCUMENT);
    const docHash2 = sha256HashDocument({ ...SAMPLE_CUSTOMS_DOCUMENT, exporterName: 'Changed' });
    const idHash = sha256Hash(SAMPLE_DOCUMENT_ID);
    expect(combinedSignatureHash(docHash1, idHash)).not.toBe(combinedSignatureHash(docHash2, idHash));
  });
});

describe('holderProofHash', () => {
  it('includes holder DID in the hash binding', () => {
    const docHash = sha256HashDocument(SAMPLE_CUSTOMS_DOCUMENT);
    const idHash = sha256Hash(SAMPLE_DOCUMENT_ID);
    const hashA = holderProofHash(docHash, idHash, 'did:ublp:agent:alice');
    const hashB = holderProofHash(docHash, idHash, 'did:ublp:agent:bob');
    expect(hashA).not.toBe(hashB);
  });

  it('binds document and ID together with holder DID', () => {
    const docHash = sha256HashDocument(SAMPLE_CUSTOMS_DOCUMENT);
    const idHash = sha256Hash(SAMPLE_DOCUMENT_ID);
    const hash = holderProofHash(docHash, idHash, SAMPLE_HOLDER_DID);
    expect(hash).toHaveLength(64);
  });
});

describe('generateKeyPair', () => {
  it('produces PEM-encoded keys', () => {
    const kp = generateKeyPair();
    expect(kp.privateKey).toContain('-----BEGIN PRIVATE KEY-----');
    expect(kp.publicKey).toContain('-----BEGIN PUBLIC KEY-----');
  });

  it('produces distinct key pairs each time', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    expect(kp1.privateKey).not.toBe(kp2.privateKey);
    expect(kp1.publicKey).not.toBe(kp2.publicKey);
  });
});

describe('signDocument / verifySignature', () => {
  it('signs and verifies a document correctly', () => {
    const docHash = sha256Hash(SAMPLE_DOCUMENT_ID);
    const signature = signDocument(SAMPLE_CUSTOMS_DOCUMENT, TEST_MINISTRY_KEYS.privateKey, docHash);
    expect(signature).toBeTruthy();
    expect(typeof signature).toBe('string');

    const isValid = verifySignature(SAMPLE_CUSTOMS_DOCUMENT, signature, TEST_MINISTRY_KEYS.publicKey, docHash);
    expect(isValid).toBe(true);
  });

  it('rejects signature with wrong document', () => {
    const docHash = sha256Hash(SAMPLE_DOCUMENT_ID);
    const signature = signDocument(SAMPLE_CUSTOMS_DOCUMENT, TEST_MINISTRY_KEYS.privateKey, docHash);

    const modifiedDoc = { ...SAMPLE_CUSTOMS_DOCUMENT, totalValue: '99999 USD' };
    const isValid = verifySignature(modifiedDoc, signature, TEST_MINISTRY_KEYS.publicKey, docHash);
    expect(isValid).toBe(false);
  });

  it('rejects signature with wrong documentIdHash', () => {
    const docHash = sha256Hash(SAMPLE_DOCUMENT_ID);
    const signature = signDocument(SAMPLE_CUSTOMS_DOCUMENT, TEST_MINISTRY_KEYS.privateKey, docHash);

    const wrongIdHash = sha256Hash('different-document-id');
    const isValid = verifySignature(SAMPLE_CUSTOMS_DOCUMENT, signature, TEST_MINISTRY_KEYS.publicKey, wrongIdHash);
    expect(isValid).toBe(false);
  });

  it('rejects signature from different key', () => {
    const docHash = sha256Hash(SAMPLE_DOCUMENT_ID);
    const signature = signDocument(SAMPLE_CUSTOMS_DOCUMENT, TEST_MINISTRY_KEYS.privateKey, docHash);

    const isValid = verifySignature(SAMPLE_CUSTOMS_DOCUMENT, signature, TEST_UNAUTHORIZED_KEYS.publicKey, docHash);
    expect(isValid).toBe(false);
  });

  it('rejects tampered signature', () => {
    const docHash = sha256Hash(SAMPLE_DOCUMENT_ID);
    const signature = signDocument(SAMPLE_CUSTOMS_DOCUMENT, TEST_MINISTRY_KEYS.privateKey, docHash);

    const tampered = signature.replace(/^.{10}/, 'AAAAAAAAAA');
    const isValid = verifySignature(SAMPLE_CUSTOMS_DOCUMENT, tampered, TEST_MINISTRY_KEYS.publicKey, docHash);
    expect(isValid).toBe(false);
  });

  it('empty documentIdHash still uses valid SHA-256 (empty string is valid input)', () => {
    const signature = signDocument(SAMPLE_CUSTOMS_DOCUMENT, TEST_MINISTRY_KEYS.privateKey, '');
    const isValid = verifySignature(SAMPLE_CUSTOMS_DOCUMENT, signature, TEST_MINISTRY_KEYS.publicKey, '');
    expect(isValid).toBe(true);
  });
});

describe('verifySignatureOverHash', () => {
  it('verifies a signature over a raw hash', () => {
    const docHash = sha256HashDocument(SAMPLE_CUSTOMS_DOCUMENT);
    const idHash = sha256Hash(SAMPLE_DOCUMENT_ID);
    const combined = combinedSignatureHash(docHash, idHash);

    const signature = signDocument(SAMPLE_CUSTOMS_DOCUMENT, TEST_MINISTRY_KEYS.privateKey, idHash);
    const isValid = verifySignatureOverHash(combined, signature, TEST_MINISTRY_KEYS.publicKey);
    expect(isValid).toBe(true);
  });

  it('rejects verification with wrong hash', () => {
    const combined = combinedSignatureHash(
      sha256HashDocument({ ...SAMPLE_CUSTOMS_DOCUMENT, exporterName: 'Changed' }),
      sha256Hash(SAMPLE_DOCUMENT_ID)
    );
    const signature = signDocument(SAMPLE_CUSTOMS_DOCUMENT, TEST_MINISTRY_KEYS.privateKey, sha256Hash(SAMPLE_DOCUMENT_ID));
    const isValid = verifySignatureOverHash(combined, signature, TEST_MINISTRY_KEYS.publicKey);
    expect(isValid).toBe(false);
  });

  it('returns false for malformed signature gracefully', () => {
    const result = verifySignatureOverHash('00'.repeat(32), 'invalid-signature', TEST_MINISTRY_KEYS.publicKey);
    expect(result).toBe(false);
  });
});

describe('generateMockZKProof', () => {
  const docHash = sha256HashDocument(SAMPLE_CUSTOMS_DOCUMENT);
  const idHash = sha256Hash(SAMPLE_DOCUMENT_ID);
  const signature = signDocument(SAMPLE_CUSTOMS_DOCUMENT, TEST_MINISTRY_KEYS.privateKey, idHash);

  // Holder signature must be over holderProofHash(docHash, idHash, holderDid)
  // because generateMockZKProof verifies holder sig against that hash
  const holderPayload = holderProofHash(docHash, idHash, SAMPLE_HOLDER_DID);
  const holderSigBuffer = crypto.sign(
    null,
    Buffer.from(holderPayload, 'hex'),
    { key: TEST_AGENT_KEYS.privateKey, dsaEncoding: 'ieee-p1363' }
  );
  const holderSignature = holderSigBuffer.toString('base64');

  it('produces verified proof with valid inputs', () => {
    const proof = generateMockZKProof(
      {
        rawDocument: SAMPLE_CUSTOMS_DOCUMENT,
        salt: '',
        signature,
        holderSignature,
        holderPublicKey: TEST_AGENT_KEYS.publicKey,
        holderDid: SAMPLE_HOLDER_DID,
      },
      {
        documentHash: docHash,
        ministryPublicKey: TEST_MINISTRY_KEYS.publicKey,
        documentIdHash: idHash,
      }
    );

    expect(proof.status).toBe('verified');
    expect(proof.constraints_passed).toBe(true);
    expect(proof.signature_valid).toBe(true);
    expect(proof.proof_system).toBe('mock-ecdsa-p256');
    expect(proof.timestamp).toBeGreaterThan(0);
  });

  it('computes holderPubKeyHash correctly', () => {
    const proof = generateMockZKProof(
      {
        rawDocument: SAMPLE_CUSTOMS_DOCUMENT,
        salt: '',
        signature,
        holderSignature,
        holderPublicKey: TEST_AGENT_KEYS.publicKey,
        holderDid: SAMPLE_HOLDER_DID,
      },
      {
        documentHash: docHash,
        ministryPublicKey: TEST_MINISTRY_KEYS.publicKey,
        documentIdHash: idHash,
      }
    );

    expect(proof.holderPubKeyHash).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(proof.holderPubKeyHash)).toBe(true);
  });

  it('fails when holder signature is invalid (signed with wrong key)', () => {
    const wrongHolderSigBuffer = crypto.sign(
      null,
      Buffer.from(holderPayload, 'hex'),
      { key: TEST_UNAUTHORIZED_KEYS.privateKey, dsaEncoding: 'ieee-p1363' }
    );
    const wrongHolderSig = wrongHolderSigBuffer.toString('base64');

    expect(() => {
      generateMockZKProof(
        {
          rawDocument: SAMPLE_CUSTOMS_DOCUMENT,
          salt: '',
          signature,
          holderSignature: wrongHolderSig,
          holderPublicKey: TEST_AGENT_KEYS.publicKey,
          holderDid: SAMPLE_HOLDER_DID,
        },
        {
          documentHash: docHash,
          ministryPublicKey: TEST_MINISTRY_KEYS.publicKey,
          documentIdHash: idHash,
        }
      );
    }).toThrow('holder');
  });

  it('fails when ministry signature is invalid', () => {
    const wrongSig = signDocument(SAMPLE_CUSTOMS_DOCUMENT, TEST_UNAUTHORIZED_KEYS.privateKey, idHash);

    const proof = generateMockZKProof(
      {
        rawDocument: SAMPLE_CUSTOMS_DOCUMENT,
        salt: '',
        signature: wrongSig,
        holderSignature,
        holderPublicKey: TEST_AGENT_KEYS.publicKey,
        holderDid: SAMPLE_HOLDER_DID,
      },
      {
        documentHash: docHash,
        ministryPublicKey: TEST_MINISTRY_KEYS.publicKey,
        documentIdHash: idHash,
      }
    );

    expect(proof.status).toBe('failed');
    expect(proof.signature_valid).toBe(false);
  });

  it('provides public_inputs_hash that is deterministic', () => {
    const proof1 = generateMockZKProof(
      { rawDocument: SAMPLE_CUSTOMS_DOCUMENT, salt: '', signature, holderSignature, holderPublicKey: TEST_AGENT_KEYS.publicKey, holderDid: SAMPLE_HOLDER_DID },
      { documentHash: docHash, ministryPublicKey: TEST_MINISTRY_KEYS.publicKey, documentIdHash: idHash }
    );
    const proof2 = generateMockZKProof(
      { rawDocument: SAMPLE_CUSTOMS_DOCUMENT, salt: '', signature, holderSignature, holderPublicKey: TEST_AGENT_KEYS.publicKey, holderDid: SAMPLE_HOLDER_DID },
      { documentHash: docHash, ministryPublicKey: TEST_MINISTRY_KEYS.publicKey, documentIdHash: idHash }
    );
    expect(proof1.public_inputs_hash).toBe(proof2.public_inputs_hash);
  });
});
