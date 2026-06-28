import { describe, it, expect } from 'vitest';
import type {
  UBLPVerifiableCredential,
  UBLPVerifiablePresentation,
  CommitteeAttestation,
  VPProofPublicValues,
  L2SettleRecord,
  L2SettleResponse,
} from '../../shared/src/types/vc';

describe('VC type structure', () => {
  it('UBLPVerifiableCredential has required fields', () => {
    const vc: UBLPVerifiableCredential = {
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://ublp.io/vc/v1'],
      id: 'urn:ublp:vc:test-123',
      type: ['VerifiableCredential', 'UBLPCustomsCredential'],
      issuer: 'did:ublp:ministry',
      issuanceDate: '2025-01-15T10:00:00.000Z',
      credentialSubject: {
        id: 'did:ublp:agent:test',
        documentId: 'DOC-123',
      },
      proof: {
        type: 'EcdsaSecp256r1Signature2019',
        created: '2025-01-15T10:00:00.000Z',
        verificationMethod: 'did:ublp:ministry#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: 'base64encoded-signature',
        ministryPublicKey: '-----BEGIN PUBLIC KEY-----\n...',
      },
    };

    expect(vc['@context']).toHaveLength(2);
    expect(vc.type).toContain('VerifiableCredential');
    expect(vc.type).toContain('UBLPCustomsCredential');
    expect(vc.credentialSubject.documentId).toBe('DOC-123');
    expect(vc.proof.type).toBe('EcdsaSecp256r1Signature2019');
    expect(vc.proof.proofPurpose).toBe('assertionMethod');
  });

  it('VC does not have committeeAttestation', () => {
    const vc: UBLPVerifiableCredential = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      id: 'urn:ublp:vc:test',
      type: ['VerifiableCredential', 'UBLPCustomsCredential'],
      issuer: 'did:ublp:ministry',
      issuanceDate: '2025-01-15T10:00:00.000Z',
      credentialSubject: { id: 'did:ublp:agent:test', documentId: 'DOC-123' },
      proof: {
        type: 'EcdsaSecp256r1Signature2019',
        created: '2025-01-15T10:00:00.000Z',
        verificationMethod: 'did:ublp:ministry#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: 'sig',
        ministryPublicKey: 'key',
      },
    };

    expect((vc as Record<string, unknown>).committeeAttestation).toBeUndefined();
  });
});

describe('VP type structure', () => {
  it('UBLPVerifiablePresentation has required fields', () => {
    const vp: UBLPVerifiablePresentation = {
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://ublp.io/vc/v1'],
      type: ['VerifiablePresentation', 'UBLPZKPresentation'],
      holder: 'did:ublp:agent:test',
      verifiableCredential: [
        {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          id: 'urn:ublp:vc:test',
          type: ['VerifiableCredential', 'UBLPCustomsCredential'],
          issuer: 'did:ublp:ministry',
          issuanceDate: '2025-01-15T10:00:00.000Z',
          credentialSubject: { id: 'did:ublp:agent:test', documentId: 'DOC-123' },
          proof: {
            type: 'EcdsaSecp256r1Signature2019',
            created: '2025-01-15T10:00:00.000Z',
            verificationMethod: 'did:ublp:ministry#key-1',
            proofPurpose: 'assertionMethod',
            proofValue: 'sig',
            ministryPublicKey: 'key',
          },
        },
      ],
      proof: {
        type: 'MockECDSAProof',
        created: '2025-01-15T11:00:00.000Z',
        proofPurpose: 'authentication',
        proofSystem: 'mock-ecdsa-p256',
        publicValues: {
          documentHash: 'ab'.repeat(32),
          pubKeyHash: 'cd'.repeat(32),
          documentIdHash: 'ef'.repeat(32),
          holderPubKeyHash: '01'.repeat(32),
        },
        proofBytes: 'base64-proof-bytes',
        ministryPublicKey: 'key',
        committeeAttestation: {
          type: 'BLSThreshold',
          threshold: 2,
          totalMembers: 3,
          groupKeyHash: 'gh'.repeat(32),
          signerIds: ['did:ublp:committee:customs-authority', 'did:ublp:committee:importer-chamber'],
          aggregatedSignature: 'bls-sig-hex',
          attestedAt: '2025-01-15T11:00:00.000Z',
        },
      },
    };

    expect(vp.type).toContain('VerifiablePresentation');
    expect(vp.type).toContain('UBLPZKPresentation');
    expect(vp.verifiableCredential).toHaveLength(1);
    expect(vp.proof.committeeAttestation.type).toBe('BLSThreshold');
    expect(vp.proof.committeeAttestation.threshold).toBe(2);
    expect(vp.proof.committeeAttestation.totalMembers).toBe(3);
    expect(vp.proof.publicValues.documentHash).toHaveLength(64);
    expect(vp.proof.publicValues.holderPubKeyHash).toHaveLength(64);
  });

  it('VP proof can be SP1ZKProof type', () => {
    const vpProof: VPProofPublicValues = {
      documentHash: 'ab'.repeat(32),
      pubKeyHash: 'cd'.repeat(32),
      documentIdHash: 'ef'.repeat(32),
      holderPubKeyHash: '01'.repeat(32),
    };
    expect(vpProof.documentHash).toHaveLength(64);
    expect(vpProof.pubKeyHash).toHaveLength(64);
  });
});

describe('CommitteeAttestation', () => {
  it('enforces BLS threshold invariant', () => {
    const att: CommitteeAttestation = {
      type: 'BLSThreshold',
      threshold: 2,
      totalMembers: 3,
      groupKeyHash: 'hash',
      signerIds: ['a', 'b'],
      aggregatedSignature: 'sig',
      attestedAt: '2025-01-15T11:00:00.000Z',
    };

    expect(att.signerIds.length).toBeGreaterThanOrEqual(att.threshold);
    expect(att.signerIds.length).toBeLessThanOrEqual(att.totalMembers);
    expect(att.threshold).toBeLessThanOrEqual(att.totalMembers);
  });
});

describe('L2 types', () => {
  it('L2SettleRecord tracks status correctly', () => {
    const record: L2SettleRecord = {
      documentHash: 'ab'.repeat(32),
      documentIdHash: 'cd'.repeat(32),
      ministryPublicKeyHash: 'ef'.repeat(32),
      holderDid: 'did:ublp:agent:test',
      status: 'ONAYLANDI',
      settledAt: '2025-01-15T11:00:00.000Z',
      proofSystem: 'mock-ecdsa-p256',
    };

    expect(record.status).toBe('ONAYLANDI');
    expect(record.documentHash).toHaveLength(64);
    expect(record.documentIdHash).toHaveLength(64);
  });

  it('L2SettleRecord can be SUSPICIOUS after key revocation', () => {
    const record: L2SettleRecord = {
      documentHash: 'ab'.repeat(32),
      documentIdHash: 'cd'.repeat(32),
      ministryPublicKeyHash: 'ef'.repeat(32),
      holderDid: 'did:ublp:agent:test',
      status: 'SUSPICIOUS',
      settledAt: '2025-01-15T11:00:00.000Z',
      proofSystem: 'mock-ecdsa-p256',
    };

    expect(record.status).toBe('SUSPICIOUS');
  });

  it('L2SettleResponse wraps status and record', () => {
    const response: L2SettleResponse = {
      status: 'ONAYLANDI',
      record: {
        documentHash: 'ab'.repeat(32),
        documentIdHash: 'cd'.repeat(32),
        ministryPublicKeyHash: 'ef'.repeat(32),
        holderDid: 'did:ublp:agent:test',
        status: 'ONAYLANDI',
        settledAt: '2025-01-15T11:00:00.000Z',
        proofSystem: 'mock-ecdsa-p256',
      },
    };

    expect(response.status).toBe(response.record.status);
  });
});
