/**
 * W3C Verifiable Credentials / Verifiable Presentation types
 * Standard: https://www.w3.org/TR/vc-data-model/
 *
 * Flow (v0.3 architecture — no Committee):
 *   Ministry → ECDSA-signed VC, now gated behind a human officer review (see ministry/src/index.ts)
 *   Agent    → produces ZK Proof → sends the VP straight to L2
 *   L2       → independently verifies the ZK proof itself
 *
 * The Committee service (BLS threshold attestation) was removed: it only ever re-ran the same
 * cryptographic check L2 already performs independently (both called the identical
 * sp1VerifyProof/verifySignatureOverHash functions from @ublp/shared) — no human review or
 * distinct institutional judgment was actually happening in it, so its BLS signature added no
 * verifiable trust beyond what L2's own check already provides.
 */

// ─── Verifiable Credential (issued by the Ministry — plain ECDSA signature) ──

export interface VCCredentialSubject {
  id: string;
  documentId: string;
  // documentHash and documentIdHash REMOVED.
  // The hashes are now read from the ZK proof's publicValues block — single source of truth.
  // Repeating them in credentialSubject creates a fingerprint leak.
  rawDocument?: Record<string, unknown>;
}

export interface VCProof {
  type: 'EcdsaSecp256r1Signature2019';
  created: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  proofValue: string;
  ministryPublicKey: string;
}

export interface UBLPVerifiableCredential {
  '@context': string[];
  id: string;
  type: ['VerifiableCredential', 'UBLPCustomsCredential'];
  issuer: string;
  issuanceDate: string;
  credentialSubject: VCCredentialSubject;
  proof: VCProof;
}

// ─── Verifiable Presentation (produced by the Agent, sent to L2) ─────────────

export interface VPProofPublicValues {
  documentHash: string;
  /** SHA256(ministryPubKeyRaw) — SP1 circuit's 2nd output */
  pubKeyHash: string;
  documentIdHash: string;
  /**
   * K-3: SHA256(holderPubKeyRaw) — SP1 circuit's 4th output.
   * The raw holder public key is never sent to L2.
   */
  holderPubKeyHash: string;
}

export interface VPProof {
  type: 'SP1ZKProof' | 'MockECDSAProof';
  created: string;
  proofPurpose: 'authentication';
  proofSystem: string;
  publicValues: VPProofPublicValues;
  proofBytes: string;
  ministryPublicKey: string;
}

export interface UBLPVerifiablePresentation {
  '@context': string[];
  type: ['VerifiablePresentation', 'UBLPZKPresentation'];
  holder: string;
  verifiableCredential: [UBLPVerifiableCredential];
  proof: VPProof;
}

// ─── L2 Settle Response ───────────────────────────────────────────────────────

export interface L2SettleRecord {
  documentHash: string;
  documentIdHash: string;
  ministryPublicKeyHash: string;
  holderDid: string;
  status: 'APPROVED' | 'REJECTED' | 'SUSPICIOUS';
  settledAt: string;
  proofSystem: string;
}

export interface L2SettleResponse {
  status: 'APPROVED' | 'REJECTED';
  record: L2SettleRecord;
}
