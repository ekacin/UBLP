/**
 * W3C Verifiable Credentials / Verifiable Presentation tipleri
 * Standart: https://www.w3.org/TR/vc-data-model/
 *
 * MVP notları:
 *   - JSON-LD context çözümleme yok; @context sadece identifier olarak taşınır
 *   - DID document registry yok; `ministryPublicKey` PEM proof içinde taşınır
 *   - `did:ublp:ministry` → L2'nin authorizedPublicKeys set'iyle whitelist kontrolü yapılır
 */

// ─── Committee BLS Threshold ──────────────────────────────────────────────────

export interface CommitteeAttestation {
  type: 'BLSThreshold';
  /** Kaç üye imzası gerekli (t-of-n) */
  threshold: number;
  totalMembers: number;
  /**
   * K-2 fix: SHA256(sorted ALL n member BLS pubkeys concatenated) — statik.
   * t < n üye imzalasa bile bu hash değişmez.
   * L2 bunu startup'ta committee'den alır; yalnızca bu hash attestation'dan kontrol edilir.
   */
  groupKeyHash: string;
  /**
   * K-2 fix: hangi üyelerin imzaladığı (memberId'ler).
   * L2 kendi deposundaki BLS pubkeys'den lookup yapar — attestation pubkey'lerine GÜVENMEZ.
   */
  signerIds: string[];
  /** BLS12-381 aggregate imza (hex G2 compressed, 96 byte) — agg(sig_i...) */
  aggregatedSignature: string;
  attestedAt: string;
}

// ─── Verifiable Credential (Bakanlık üretir) ─────────────────────────────────

export interface VCCredentialSubject {
  /** Holder DID — tır/agent kimliği: did:ublp:agent:{id} */
  id: string;
  documentId: string;
  /** SHA256(canonicalJson(rawDocument)) — ministry'nin imzaladığı değer */
  documentHash: string;
  /** SHA256(documentId) — replay dedup anahtarı */
  documentIdHash: string;
  /**
   * Gümrük verisi — ZK proof içinde gizli kalır.
   * VP içine KONULMAZ; sadece Agent'ın yerel deposunda saklanır.
   * AÇIK-2: rawDocument VP'ye dahil edilirse ZK'nın tüm amacı ortadan kalkar.
   */
  rawDocument?: Record<string, unknown>;
}

export interface VCProof {
  type: 'EcdsaSecp256r1Signature2019';
  created: string;
  /** did:ublp:ministry#key-1 */
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  /**
   * base64 IEEE P1363 ECDSA imzası.
   * AÇIK-1 fix: SHA256(documentHash_bytes || documentIdHash_bytes) üzerinde imzalanır.
   */
  proofValue: string;
  /** PEM SPKI — MVP: DID resolution olmadan key erişimi için */
  ministryPublicKey: string;
}

export interface UBLPVerifiableCredential {
  '@context': string[];
  /** urn:ublp:vc:{documentId} */
  id: string;
  type: ['VerifiableCredential', 'UBLPCustomsCredential'];
  /** did:ublp:ministry */
  issuer: string;
  issuanceDate: string;
  credentialSubject: VCCredentialSubject;
  proof: VCProof;
  /** Kurul BLS eşik imzası — bakanlık imzasını bağımsız olarak doğrular */
  committeeAttestation: CommitteeAttestation;
}

// ─── Verifiable Presentation (Agent üretir, L2'ye gönderir) ──────────────────

export interface VPProofPublicValues {
  /** SHA256(canonicalJson) — SP1 modunda circuit tarafından hesaplanır */
  documentHash: string;
  /** SHA256(ministryPubKeyRaw) — SP1 circuit output */
  pubKeyHash: string;
  /** SHA256(documentId) — proof'a bağlı; sonradan değiştirilemez */
  documentIdHash: string;
}

export interface VPProof {
  type: 'SP1ZKProof' | 'MockECDSAProof';
  created: string;
  proofPurpose: 'authentication';
  /** 'sp1-groth16' | 'sp1-plonk' | 'mock-ecdsa-p256' */
  proofSystem: string;
  publicValues: VPProofPublicValues;
  /**
   * SP1 modunda: base64 Groth16/PLONK proof bytes
   * Mock modunda: base64 IEEE P1363 ECDSA imzası (bakanlığın imzası)
   */
  proofBytes: string;
  /** PEM SPKI bakanlık anahtarı */
  ministryPublicKey: string;
  /**
   * K-3 fix: Holder (Agent) kendi P-256 anahtarıyla VP'yi imzalar.
   * Payload: SHA256(documentHash_bytes || documentIdHash_bytes || holderDid_utf8)
   * MitM saldırısında holder'ı değiştirmek imzayı kırar.
   */
  holderSignature: string;
  /** PEM SPKI Agent anahtarı — L2 holder DID'ini buna bağlar */
  holderPublicKey: string;
}

export interface UBLPVerifiablePresentation {
  '@context': string[];
  type: ['VerifiablePresentation', 'UBLPZKPresentation'];
  /** did:ublp:agent:{id} */
  holder: string;
  /**
   * AÇIK-2 fix: rawDocument dahil VC KONULMAZ.
   * VP içindeki VC yalnızca kamuya açık alanları taşır (documentHash, documentIdHash).
   */
  verifiableCredential: [UBLPVerifiableCredential];
  proof: VPProof;
}

// ─── L2 Settle Response ───────────────────────────────────────────────────────

export interface L2SettleRecord {
  documentHash: string;
  documentIdHash: string;
  ministryPublicKeyHash: string;
  holderDid: string;
  /** SUSPICIOUS: anahtar iptalinden sonra geriye dönük forensic işaretlemesi */
  status: 'ONAYLANDI' | 'REDDEDILDI' | 'SUSPICIOUS';
  settledAt: string;
  proofSystem: string;
}

export interface L2SettleResponse {
  status: 'ONAYLANDI' | 'REDDEDILDI';
  record: L2SettleRecord;
}
