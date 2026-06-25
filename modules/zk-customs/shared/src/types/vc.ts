/**
 * W3C Verifiable Credentials / Verifiable Presentation tipleri
 * Standart: https://www.w3.org/TR/vc-data-model/
 *
 * Akış (v0.2 mimarisi — Agent-first ZK):
 *   Ministry → ECDSA imzalı VC (committeeAttestation YOK)
 *   Agent    → ZK Proof üretir → Committee'ye sunar (ham belge gösterilmez)
 *   Committee→ ZK verify eder → matematiksel ikna → BLS imzalar
 *   L2       → VP'deki ZK proof + committeeAttestation ikisini doğrular
 *
 * committeeAttestation artık VC'de değil, VP proof içinde.
 * Sebep: Kurul Bakanlığın kör onayına değil Agent'ın ZK kanıtına dayanarak imzalar.
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

// ─── Verifiable Credential (Bakanlık üretir — sade ECDSA imzası) ─────────────

export interface VCCredentialSubject {
  id: string;
  documentId: string;
  // documentHash ve documentIdHash KALDIRILDI.
  // Hash'ler artık ZK kanıtının publicValues bloğundan okunur — tek kaynak.
  // credentialSubject'te tekrarlamak fingerprint sızıntısı yaratıyor.
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
  // committeeAttestation KALDIRILDI — artık VP proof içinde.
  // Kurul belgeyi görmez, ZK kanıtını görür; kanıt agent'ta üretilir.
}

// ─── Verifiable Presentation (Agent üretir, L2'ye gönderir) ──────────────────

export interface VPProofPublicValues {
  documentHash: string;
  /** SHA256(ministryPubKeyRaw) — SP1 circuit 2. output */
  pubKeyHash: string;
  documentIdHash: string;
  /**
   * K-3: SHA256(holderPubKeyRaw) — SP1 circuit 4. output.
   * Ham holder public key L2'ye hiç gönderilmez.
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
   * committeeAttestation BURAYA TAŞINDI (VC'den VP'ye).
   * Kurul, agent'ın ZK kanıtını verify ettikten sonra BLS imzasını basıyor.
   * L2: ZK proof + BLS attestation bağımsız olarak doğrular.
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
  status: 'ONAYLANDI' | 'REDDEDILDI' | 'SUSPICIOUS';
  settledAt: string;
  proofSystem: string;
}

export interface L2SettleResponse {
  status: 'ONAYLANDI' | 'REDDEDILDI';
  record: L2SettleRecord;
}
