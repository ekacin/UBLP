/**
 * W3C Verifiable Credentials / Verifiable Presentation tipleri
 * Standart: https://www.w3.org/TR/vc-data-model/
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

// ─── Verifiable Credential (Bakanlık üretir) ─────────────────────────────────

export interface VCCredentialSubject {
  id: string;
  documentId: string;
  documentHash: string;
  documentIdHash: string;
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
  committeeAttestation: CommitteeAttestation;
}

// ─── Verifiable Presentation (Agent üretir, L2'ye gönderir) ──────────────────

export interface VPProofPublicValues {
  documentHash: string;
  /** SHA256(ministryPubKeyRaw) — SP1 circuit 2. output */
  pubKeyHash: string;
  documentIdHash: string;
  /**
   * K-3 fix: SHA256(holderPubKeyRaw) — SP1 circuit 4. output.
   * Ham holder public key L2'ye hiç gönderilmez; sadece hash commit edilir.
   * SP1 modunda circuit içinde holder ECDSA imzası doğrulanır (private input).
   * Mock modunda agent lokal doğrular, yalnızca bu hash VP'ye girer.
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
  // holderSignature ve holderPublicKey BURADA YOKTUR — circuit private input'u
  // SP1 modunda circuit bunları ZK içinde tüketir; mock modunda agent lokal doğrular
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
  status: 'ONAYLANDI' | 'REDDEDILDI' | 'SUSPICIOUS';
  settledAt: string;
  proofSystem: string;
}

export interface L2SettleResponse {
  status: 'ONAYLANDI' | 'REDDEDILDI';
  record: L2SettleRecord;
}
