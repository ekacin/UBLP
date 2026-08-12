/**
 * UBLP Cryptography Module — generic document hash/signature/ZK-proof primitives.
 *
 * Note: this file is `modules/zk-customs/shared/src/crypto/mockCrypto.ts` moved to root.
 * The VC types (UBLPVerifiableCredential etc.) aren't generic, so they didn't move here —
 * they stayed under `@ublp/zk-customs-types` (see AGENTS.md Section 3.2/3.3).
 *
 * Swap points:
 *   sha256Hash          → replaceable with Poseidon2 (ZK field-friendly hash).
 *                         WARNING: must change IN LOCKSTEP with sp1-circuit/src/main.rs —
 *                         if only one side changes, the signature becomes unverifiable
 *                         inside the ZK circuit.
 *   generateZKProof     → SP1 prover network (needs SP1_PROVER_NETWORK_KEY + ELF)
 *   generateKeyPair / signDocument / verifySignature → EdDSA/BabyJubJub
 */

import crypto from 'crypto';
import { generateSP1Proof, sp1Available } from './sp1Client';

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
  /** SHA256("ublp-doc-v1:" + canonicalJson(document)) — domain-separated, bound to the signature */
  documentHash: string;
  ministryPublicKey: string;
  /** SHA256(documentId) — replay-dedup key; bound into the SP1 proof */
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
   * Mock mode: the signer's ECDSA signature (base64 IEEE P1363).
   * SP1 mode: Groth16/PLONK proof bytes (base64).
   */
  ministrySignature: string;
  /**
   * K-3: SHA256(holderPubKeyRaw) — circuit output #4 in SP1 mode, computed locally in mock
   * mode. The raw holder public key or signature never goes to L2.
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
 * SHA-256 hash function. May be swapped for Poseidon2 later.
 * WARNING: must change IN LOCKSTEP with Sha256::digest in sp1-circuit/src/main.rs.
 */
export function sha256Hash(data: string | Record<string, unknown>): string {
  const input = typeof data === 'string' ? data : canonicalJson(data);
  return crypto.createHash('sha256').update(input).digest('hex');
}

// Domain separation prefix — cross-protocol hash collision prevention.
// Read by the circuit, the agent, and the verifier; if it changes, all three must update.
const DOCUMENT_HASH_DOMAIN = 'ublp-doc-v1:';

/**
 * SHA256("ublp-doc-v1:" + canonicalJson(doc))
 * The domain-separated variant used for document hashes. Kept separate from the generic
 * sha256Hash because documentIdHash / pubKeyHash don't use this prefix.
 */
export function sha256HashDocument(doc: Record<string, unknown>): string {
  return crypto.createHash('sha256').update(DOCUMENT_HASH_DOMAIN + canonicalJson(doc)).digest('hex');
}

/**
 * ISSUE-1 fix: cryptographically binds documentHash and documentIdHash together.
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
 * K-3 fix: payload hash for the holder's (Agent's) VP signature.
 * SHA256(documentHash_bytes || documentIdHash_bytes || holderDid_utf8)
 * If the holder DID changes, the signature breaks — MitM protection.
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
 * Signs a document.
 * ISSUE-1 fix: signs the combined hash SHA256(documentHash || documentIdHash).
 */
export function signDocument(
  doc: Record<string, unknown>,
  privateKey: string,
  documentIdHash: string
): string {
  const docHash = Buffer.from(sha256HashDocument(doc), 'hex');
  const idHash = Buffer.from(documentIdHash, 'hex');
  const combined = Buffer.concat([docHash, idHash]);
  const combinedHash = crypto.createHash('sha256').update(combined).digest();
  return crypto
    .sign(null, combinedHash, { key: privateKey, dsaEncoding: 'ieee-p1363' })
    .toString('base64');
}

/**
 * Verifies a document's signature.
 * ISSUE-1 fix: verifies against combinedSignatureHash(documentHash, documentIdHash).
 */
export function verifySignature(
  doc: Record<string, unknown>,
  signature: string,
  publicKey: string,
  documentIdHash: string
): boolean {
  try {
    const docHash = Buffer.from(sha256HashDocument(doc), 'hex');
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

/** Trustless verification — verifies against the hash without knowing the document content. */
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

/** Mock ZK Proof — used when SP1 is unavailable. */
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

  // K-3: holder auth — verified locally, only the hash goes into the VP, never the raw key/sig
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
    if (!holderSigValid) throw new Error('Mock ZK: invalid holder signature.');

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
 * ZK Proof generator — main entry point.
 *
 * SP1_PROVER_NETWORK_KEY + ELF → SP1 Groth16 proof
 * otherwise → mock ECDSA (development/test)
 */
export async function generateZKProof(
  privateInputs: PrivateInputs,
  publicInputs: PublicInputs
): Promise<ZKProof> {
  if (sp1Available()) {
    console.log('[ZK] Using SP1 prover network...');
    if (!privateInputs.holderSignature || !privateInputs.holderPublicKey || !privateInputs.holderDid) {
      throw new Error('SP1 mode: holder auth (holderSignature, holderPublicKey, holderDid) is required.');
    }

    // In SP1 mode the raw JSON never reaches the circuit — only the pre-computed
    // documentHash. Trusted-issuer model: the signer computes the hash correctly; the
    // circuit only takes 32 bytes.
    const result = await generateSP1Proof({
      documentHash: publicInputs.documentHash,
      ministrySignature: privateInputs.signature,
      ministryPublicKey: publicInputs.ministryPublicKey,
      documentIdHash: publicInputs.documentIdHash,
      // K-3: circuit private inputs — go to the SP1 network, never come back to L2
      holderSignature: privateInputs.holderSignature,
      holderPublicKey: privateInputs.holderPublicKey,
      holderDid: privateInputs.holderDid,
    });

    if (result.publicValues.documentHash !== publicInputs.documentHash) {
      throw new Error(
        `SP1 circuit documentHash mismatch. ` +
        `circuit=${result.publicValues.documentHash} agent=${publicInputs.documentHash}`
      );
    }
    if (result.publicValues.documentIdHash !== publicInputs.documentIdHash) {
      throw new Error(
        `SP1 circuit documentIdHash mismatch. ` +
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

  console.log('[ZK] SP1 unavailable — using mock proof (development mode).');
  return generateMockZKProof(privateInputs, publicInputs);
}
