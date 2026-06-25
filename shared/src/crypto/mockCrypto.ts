/**
 * UBLP Kriptografi Modülü
 *
 * Swap noktaları:
 *   sha256Hash          → Poseidon2 ile değiştirilebilir (ZK field-friendly hash)
 *                         DİKKAT: sp1-circuit/src/main.rs ile EŞ ZAMANLI değişmeli.
 *                         Sadece biri değişirse bakanlık imzası ZK devre içinde
 *                         doğrulanamaz hale gelir.
 *   generateZKProof     → SP1 prover network (SP1_PROVER_NETWORK_KEY + ELF gerekli)
 *   generateKeyPair / signDocument / verifySignature → EdDSA/BabyJubJub
 */

import crypto from 'crypto';
import { generateSP1Proof, sp1Available, sp1VerifyProof } from './sp1Client';

export { sp1VerifyProof } from './sp1Client';
export {
  blsGenerateKeyPair,
  blsSign,
  blsVerify,
  blsAggregateSignatures,
  blsAggregatePublicKeys,
  blsGroupKeyHash,
  blsVerifyThreshold,
} from './blsCrypto';
export type { BLSKeyPair } from './blsCrypto';
export type {
  UBLPVerifiableCredential,
  UBLPVerifiablePresentation,
  VCCredentialSubject,
  VCProof,
  VPProof,
  VPProofPublicValues,
  CommitteeAttestation,
  L2SettleRecord,
  L2SettleResponse,
} from '../types/vc';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface KeyPair {
  privateKey: string;
  publicKey: string;
}

export interface PrivateInputs {
  rawDocument: Record<string, unknown>;
  salt: string;
  signature: string;
  // K-3: holder auth — circuit private inputs, never exposed to L2
  holderSignature?: string;  // base64 IEEE P1363
  holderPublicKey?: string;  // PEM SPKI
  holderDid?: string;        // UTF-8 — payload binder
}

export interface PublicInputs {
  /** SHA256(canonicalJson(document)) — ministry'nin imzaladığı değer */
  documentHash: string;
  ministryPublicKey: string;
  /** SHA256(documentId) — replay dedup anahtarı; SP1 proof'a bağlı */
  documentIdHash: string;
}

export interface ZKProof {
  status: 'verified' | 'failed';
  constraints_passed: boolean;
  signature_valid: boolean;
  timestamp: number;
  proof_system: string;
  public_inputs_hash: string;
  /**
   * Mock modunda: bakanlık ECDSA imzası (base64 IEEE P1363)
   * SP1 modunda: Groth16/PLONK proof bytes (base64)
   */
  ministrySignature: string;
  /**
   * K-3: SHA256(holderPubKeyRaw) — SP1 modunda circuit 4. output; mock modunda lokal hesaplanır.
   * Ham holder public key veya imzası asla L2'ye gitmez.
   */
  holderPubKeyHash: string;
}

// ─── Canonical Serialization ──────────────────────────────────────────────────

export function canonicalJson(data: unknown): string {
  return JSON.stringify(data, (_key, value: unknown) => {
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      return Object.fromEntries(
        Object.keys(value as Record<string, unknown>)
          .sort()
          .map((k) => [k, (value as Record<string, unknown>)[k]])
      );
    }
    return value;
  });
}

// ─── Hash ─────────────────────────────────────────────────────────────────────

/**
 * SHA-256 hash fonksiyonu. İleride Poseidon2 ile değiştirilebilir.
 * UYARI: sp1-circuit/src/main.rs'deki Sha256::digest ile EŞ ZAMANLI değişmeli.
 */
export function sha256Hash(data: string | Record<string, unknown>): string {
  const input = typeof data === 'string' ? data : canonicalJson(data);
  return crypto.createHash('sha256').update(input).digest('hex');
}

/**
 * AÇIK-1 fix: documentHash ve documentIdHash'i birbirine kriptografik olarak bağlar.
 * SHA256(documentHash_bytes || documentIdHash_bytes) — 32+32=64 byte input.
 */
export function combinedSignatureHash(documentHash: string, documentIdHash: string): string {
  const combined = Buffer.concat([
    Buffer.from(documentHash, 'hex'),
    Buffer.from(documentIdHash, 'hex'),
  ]);
  return crypto.createHash('sha256').update(combined).digest('hex');
}

/**
 * K-3 fix: Holder (Agent) VP imzası için payload hash.
 * SHA256(documentHash_bytes || documentIdHash_bytes || holderDid_utf8)
 * Holder DID değiştirilirse imza kırılır → MitM koruması.
 */
export function holderProofHash(
  documentHash: string,
  documentIdHash: string,
  holderDid: string
): string {
  return crypto
    .createHash('sha256')
    .update(Buffer.from(documentHash, 'hex'))
    .update(Buffer.from(documentIdHash, 'hex'))
    .update(holderDid, 'utf8')
    .digest('hex');
}

// ─── Key Generation ───────────────────────────────────────────────────────────

export function generateKeyPair(): KeyPair {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  return { privateKey, publicKey };
}

// ─── Signature ────────────────────────────────────────────────────────────────

/**
 * Belgeyi imzalar.
 * AÇIK-1 fix: SHA256(documentHash || documentIdHash) birleşik hash'i imzalanır.
 */
export function signDocument(
  doc: Record<string, unknown>,
  privateKey: string,
  documentIdHash: string
): string {
  const docHash = Buffer.from(sha256Hash(canonicalJson(doc)), 'hex');
  const idHash = Buffer.from(documentIdHash, 'hex');
  const combined = Buffer.concat([docHash, idHash]);
  const combinedHash = crypto.createHash('sha256').update(combined).digest();
  return crypto
    .sign(null, combinedHash, { key: privateKey, dsaEncoding: 'ieee-p1363' })
    .toString('base64');
}

/**
 * Belge imzasını doğrular.
 * AÇIK-1 fix: combinedSignatureHash(documentHash, documentIdHash) üzerinde verify.
 */
export function verifySignature(
  doc: Record<string, unknown>,
  signature: string,
  publicKey: string,
  documentIdHash: string
): boolean {
  try {
    const docHash = Buffer.from(sha256Hash(canonicalJson(doc)), 'hex');
    const idHash = Buffer.from(documentIdHash, 'hex');
    const combined = Buffer.concat([docHash, idHash]);
    const combinedHash = crypto.createHash('sha256').update(combined).digest();
    return crypto.verify(
      null,
      combinedHash,
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(signature, 'base64')
    );
  } catch {
    return false;
  }
}

/** L2 trustless doğrulama — belge içeriği bilinmeden hash üzerinde verify. */
export function verifySignatureOverHash(
  hashHex: string,
  signature: string,
  publicKey: string
): boolean {
  try {
    const hashBytes = Buffer.from(hashHex, 'hex');
    return crypto.verify(
      null,
      hashBytes,
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(signature, 'base64')
    );
  } catch {
    return false;
  }
}

// ─── ZK Proof ─────────────────────────────────────────────────────────────────

/** Mock ZK Proof — SP1 yokken kullanılır. */
export function generateMockZKProof(
  privateInputs: PrivateInputs,
  publicInputs: PublicInputs
): ZKProof {
  const signatureValid = verifySignature(
    privateInputs.rawDocument,
    privateInputs.signature,
    publicInputs.ministryPublicKey,
    publicInputs.documentIdHash
  );

  // K-3: holder auth — lokal doğrula, sadece hash VP'ye gider, ham key/sig asla
  let holderPubKeyHash = '';
  if (privateInputs.holderSignature && privateInputs.holderPublicKey && privateInputs.holderDid) {
    const payloadHex = holderProofHash(
      publicInputs.documentHash,
      publicInputs.documentIdHash,
      privateInputs.holderDid
    );
    const payload = Buffer.from(payloadHex, 'hex');
    const holderSigValid = crypto.verify(
      null,
      payload,
      { key: privateInputs.holderPublicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(privateInputs.holderSignature, 'base64')
    );
    if (!holderSigValid) throw new Error('Mock ZK: holder imzası geçersiz.');

    const pubKeyDer = crypto.createPublicKey(privateInputs.holderPublicKey)
      .export({ type: 'spki', format: 'der' }) as Buffer;
    const pubKeyRaw = pubKeyDer.subarray(pubKeyDer.length - 65);
    holderPubKeyHash = crypto.createHash('sha256').update(pubKeyRaw).digest('hex');
  }

  return {
    status: signatureValid ? 'verified' : 'failed',
    constraints_passed: signatureValid,
    signature_valid: signatureValid,
    timestamp: Date.now(),
    proof_system: 'mock-ecdsa-p256',
    public_inputs_hash: sha256Hash(canonicalJson(publicInputs)),
    ministrySignature: privateInputs.signature,
    holderPubKeyHash,
  };
}

/**
 * ZK Proof üretici — ana giriş noktası.
 *
 * SP1_PROVER_NETWORK_KEY + ELF → SP1 Groth16 proof
 * yoksa → mock ECDSA (geliştirme/test)
 */
export async function generateZKProof(
  privateInputs: PrivateInputs,
  publicInputs: PublicInputs
): Promise<ZKProof> {
  if (sp1Available()) {
    console.log('[ZK] SP1 prover network kullanılıyor...');
    if (!privateInputs.holderSignature || !privateInputs.holderPublicKey || !privateInputs.holderDid) {
      throw new Error('SP1 modu: holder auth (holderSignature, holderPublicKey, holderDid) zorunlu.');
    }

    // SP1 modunda ham JSON circuit'e gitmez — sadece önceden hesaplanmış documentHash.
    // Trusted issuer model: Bakanlık hash'i doğru hesaplar; circuit 32 byte alır.
    const result = await generateSP1Proof({
      documentHash: publicInputs.documentHash,
      ministrySignature: privateInputs.signature,
      ministryPublicKey: publicInputs.ministryPublicKey,
      documentIdHash: publicInputs.documentIdHash,
      // K-3: circuit private inputs — SP1 network'e gider, L2'ye asla dönmez
      holderSignature: privateInputs.holderSignature,
      holderPublicKey: privateInputs.holderPublicKey,
      holderDid: privateInputs.holderDid,
    });

    if (result.publicValues.documentHash !== publicInputs.documentHash) {
      throw new Error(
        `SP1 circuit documentHash uyuşmuyor. ` +
        `circuit=${result.publicValues.documentHash} agent=${publicInputs.documentHash}`
      );
    }
    if (result.publicValues.documentIdHash !== publicInputs.documentIdHash) {
      throw new Error(
        `SP1 circuit documentIdHash uyuşmuyor. ` +
        `circuit=${result.publicValues.documentIdHash} agent=${publicInputs.documentIdHash}`
      );
    }

    return {
      status: 'verified',
      constraints_passed: true,
      signature_valid: true,
      timestamp: Date.now(),
      proof_system: result.proofSystem,
      public_inputs_hash: sha256Hash(
        result.publicValues.documentHash +
        result.publicValues.pubKeyHash +
        result.publicValues.documentIdHash +
        result.publicValues.holderPubKeyHash
      ),
      ministrySignature: result.proofBytes,
      holderPubKeyHash: result.publicValues.holderPubKeyHash,
    };
  }

  console.log('[ZK] SP1 yok — mock proof (geliştirme modu).');
  return generateMockZKProof(privateInputs, publicInputs);
}
