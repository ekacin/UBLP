/**
 * UBLP Kriptografi Modülü
 *
 * Swap noktaları:
 *   poseidon2Hash   → Poseidon2 (ZK uyumlu hash)
 *   generateMockZKProof → snarkjs.groth16.prove(circuit, inputs)
 *   generateKeyPair / signDocument / verifySignature → EdDSA/BabyJubJub
 *
 * Arayüzler değişmez — yalnızca implementasyon değişir.
 */

import crypto from 'crypto';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface KeyPair {
  privateKey: string; // PEM (PKCS8)
  publicKey: string;  // PEM (SPKI)
}

export interface PrivateInputs {
  rawDocument: Record<string, unknown>;
  salt: string;
  signature: string;
}

export interface PublicInputs {
  documentHash: string;
  ministryPublicKey: string;
}

export interface ZKProof {
  status: 'verified' | 'failed';
  constraints_passed: boolean;
  signature_valid: boolean;
  timestamp: number;
  proof_system: string; // 'mock-sha256' | 'groth16' | 'plonk' …
  public_inputs_hash: string;
}

// ─── Key Generation ───────────────────────────────────────────────────────────

/**
 * EC P-256 anahtar çifti üretir.
 * Swap: EdDSA / BabyJubJub için namedCurve'ü değiştir.
 */
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
 * Belgeyi ECDSA/SHA-256 ile imzalar.
 * Swap: EdDSA için crypto.createSign('ed25519') kullan.
 */
export function signDocument(
  doc: Record<string, unknown>,
  privateKey: string
): string {
  const sign = crypto.createSign('SHA256');
  sign.update(JSON.stringify(doc));
  sign.end();
  return sign.sign(privateKey, 'base64');
}

/**
 * ECDSA imzasını doğrular.
 */
export function verifySignature(
  doc: Record<string, unknown>,
  signature: string,
  publicKey: string
): boolean {
  try {
    const verify = crypto.createVerify('SHA256');
    verify.update(JSON.stringify(doc));
    verify.end();
    return verify.verify(publicKey, signature, 'base64');
  } catch {
    return false;
  }
}

// ─── Hash ─────────────────────────────────────────────────────────────────────

/**
 * Swap hedef: Poseidon2 (ZK devreleriyle uyumlu, field-friendly).
 * Şimdilik SHA-256. Arayüz aynı kalır.
 */
export function poseidon2Hash(data: string | Record<string, unknown>): string {
  const input = typeof data === 'string' ? data : JSON.stringify(data);
  return crypto.createHash('sha256').update(input).digest('hex');
}

// ─── ZK Proof ─────────────────────────────────────────────────────────────────

/**
 * Mock ZK Proof üretici.
 *
 * Swap: Bu fonksiyonun gövdesini aşağıdakiyle değiştir:
 *   const { proof, publicSignals } = await snarkjs.groth16.prove(circuit, inputs);
 *   return { status: 'verified', constraints_passed: true, ... proof };
 *
 * Fonksiyon imzası ve dönüş tipi değişmez.
 */
export function generateMockZKProof(
  privateInputs: PrivateInputs,
  publicInputs: PublicInputs
): ZKProof {
  const signatureValid = verifySignature(
    privateInputs.rawDocument,
    privateInputs.signature,
    publicInputs.ministryPublicKey
  );

  return {
    status: signatureValid ? 'verified' : 'failed',
    constraints_passed: signatureValid,
    signature_valid: signatureValid,
    timestamp: Date.now(),
    proof_system: 'mock-sha256',
    public_inputs_hash: poseidon2Hash(JSON.stringify(publicInputs)),
  };
}
