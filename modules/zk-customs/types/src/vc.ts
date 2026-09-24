/**
 * W3C Verifiable Credentials / Verifiable Presentation types
 * Standard: https://www.w3.org/TR/vc-data-model/
 *
 * Flow (v0.2 architecture — Agent-first ZK):
 *   Ministry → ECDSA-signed VC (NO committeeAttestation)
 *   Agent    → produces ZK Proof → submits to Committee (raw document never shown)
 *   Committee→ verifies ZK → mathematical conviction → BLS signs
 *   L2       → verifies both the ZK proof and committeeAttestation in the VP
 *
 * committeeAttestation is no longer in the VC, it's inside the VP proof.
 * Reason: the committee signs based on the Agent's ZK proof, not the Ministry's blind approval.
 */

// ─── Committee BLS Threshold ──────────────────────────────────────────────────

export interface CommitteeAttestation {
  type: 'BLSThreshold';
  threshold: number;
  totalMembers: number;
  groupKeyHash: string;
  signerIds: string[];
  aggregatedSignature: string;
  attestedAt: string;
}

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
  // committeeAttestation REMOVED — now inside the VP proof.
  // The committee doesn't see the document, it sees the ZK proof; the proof is produced by the agent.
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
  /**
   * committeeAttestation MOVED HERE (from the VC to the VP).
   * The committee stamps the BLS signature after verifying the agent's ZK proof.
   * L2: independently verifies both the ZK proof and the BLS attestation.
   */
  committeeAttestation: CommitteeAttestation;
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
