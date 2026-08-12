/**
 * SP1 Prover Network Client (Succinct)
 *
 * Environment variables:
 *   SP1_PROVER_NETWORK_KEY  — Succinct API key (required)
 *   SP1_PROVER_URL          — default: https://rpc.succinct.xyz
 *   SP1_ELF_PATH            — compiled ELF (default: sp1-circuit/elf/ublp-verifier)
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

// ─── Config ───────────────────────────────────────────────────────────────────

const SP1_URL = process.env.SP1_PROVER_URL ?? 'https://rpc.succinct.xyz';
const SP1_KEY = process.env.SP1_PROVER_NETWORK_KEY ?? '';
const ELF_PATH =
  process.env.SP1_ELF_PATH ??
  path.join(__dirname, '..', '..', '..', 'sp1-circuit', 'elf', 'ublp-verifier');

export function sp1Available(): boolean {
  if (SP1_KEY.length > 0 && !fs.existsSync(ELF_PATH)) {
    console.error(
      `[SP1] ERROR: SP1_PROVER_NETWORK_KEY is set but the ELF was not found: ${ELF_PATH}\n` +
      `[SP1] Run "cargo prove build" inside sp1-circuit/ and copy the ELF.\n` +
      `[SP1] Will not silently fall back to mock mode without this security guarantee — halting.`
    );
    process.exit(1);
  }
  return SP1_KEY.length > 0 && fs.existsSync(ELF_PATH);
}

// ─── ELF / VK Hash Cache ─────────────────────────────────────────────────────

let _cachedVkHash: string | null = null;

async function getVkHash(): Promise<string> {
  if (_cachedVkHash) return _cachedVkHash;
  // The real SP1 vk_hash is produced by `cargo prove build`'s output. If
  // sp1-circuit/elf/ublp-verifier.vk_hash exists, use it. Otherwise fall back to
  // SHA256(elf) — good enough for the MVP, replace with cargo prove's vk output in production.
  const vkHashFile = ELF_PATH + '.vk_hash';
  if (fs.existsSync(vkHashFile)) {
    _cachedVkHash = (await fs.promises.readFile(vkHashFile, 'utf-8')).trim();
  } else {
    const elfBytes = await fs.promises.readFile(ELF_PATH);
    _cachedVkHash = crypto.createHash('sha256').update(elfBytes).digest('hex');
  }
  return _cachedVkHash;
}

// ─── Key Conversion ───────────────────────────────────────────────────────────

/** PEM SPKI → 65-byte uncompressed SEC1 (0x04 || x || y). What the SP1 circuit expects. */
export function pubKeyPemToRaw(pem: string): Buffer {
  const keyObject = crypto.createPublicKey(pem);
  const der = keyObject.export({ type: 'spki', format: 'der' }) as Buffer;
  if (der.length < 65) throw new Error('Unexpected SPKI DER length');
  return der.subarray(der.length - 65);
}

// ─── Types ────────────────────────────────────────────────────────────────────

type ProofMode = 'groth16' | 'plonk' | 'compressed';

interface ProofRequestBody {
  vk_hash: string;
  stdin: { type: 'bytes'; data: string[] };
  mode: ProofMode;
}

interface ProofStatus {
  proof_id: string;
  status:
    | 'PROOF_REQUESTED'
    | 'PROOF_ASSIGNED'
    | 'PROOF_PROVED'
    | 'PROOF_FULFILLED'
    | 'PROOF_UNCLAIMED';
  fulfillment?: {
    proof_bytes: string;
    public_values: string[];
  };
}

// ─── SP1 Proof Generation ─────────────────────────────────────────────────────

export interface SP1ProofResult {
  proofBytes: string;
  publicValues: {
    documentHash: string;       // hex — SHA256(canonicalJson), computed inside the circuit
    pubKeyHash: string;         // hex — SHA256(ministryPubKeyRaw)
    documentIdHash: string;     // hex — SHA256(documentId), bound into the proof
    holderPubKeyHash: string;   // hex — K-3: SHA256(holderPubKeyRaw), circuit output #4
  };
  proofSystem: 'sp1-groth16' | 'sp1-plonk';
}

export async function generateSP1Proof(params: {
  documentHash: string;           // hex, 32 bytes — SHA256(canonicalJson), pre-computed by the trusted issuer
  ministrySignature: string;      // base64 IEEE P1363, 64 bytes
  ministryPublicKey: string;      // PEM SPKI
  documentIdHash: string;         // hex, 32 bytes — ISSUE-1: bound into the proof
  // K-3: holder auth — circuit private input, never sent to L2
  holderSignature: string;        // base64 IEEE P1363, 64 bytes
  holderPublicKey: string;        // PEM SPKI — the circuit converts this to raw bytes
  holderDid: string;              // UTF-8 — used in the holder payload computation
  mode?: ProofMode;
}): Promise<SP1ProofResult> {
  if (!SP1_KEY) throw new Error('SP1_PROVER_NETWORK_KEY is not set.');
  if (!fs.existsSync(ELF_PATH)) throw new Error(`ELF not found: ${ELF_PATH}`);

  const {
    documentHash, ministrySignature, ministryPublicKey, documentIdHash,
    holderSignature, holderPublicKey, holderDid,
    mode = 'groth16',
  } = params;

  // stdin order must match main.rs's read_vec() order exactly:
  //   1. ministry_signature
  //   2. ministry_pub_key_raw
  //   3. document_hash        (32 bytes — pre-computed, raw JSON is never sent)
  //   4. document_id_hash
  //   5. holder_signature     (K-3 — private, never reaches L2)
  //   6. holder_pub_key_raw   (K-3 — private, only its hash is committed)
  //   7. holder_did           (K-3 — private, embedded in the payload)
  const sigBytes = Buffer.from(ministrySignature, 'base64');
  const pubKeyRaw = pubKeyPemToRaw(ministryPublicKey);
  const docHashBytes = Buffer.from(documentHash, 'hex');
  const idHashBytes = Buffer.from(documentIdHash, 'hex');
  const holderSigBytes = Buffer.from(holderSignature, 'base64');
  const holderPubKeyRaw = pubKeyPemToRaw(holderPublicKey);
  const holderDidBytes = Buffer.from(holderDid, 'utf8');

  if (sigBytes.length !== 64) throw new Error('Ministry signature must be 64 bytes (IEEE P1363).');
  if (pubKeyRaw.length !== 65) throw new Error('Ministry public key must be 65 bytes (uncompressed SEC1).');
  if (docHashBytes.length !== 32) throw new Error('documentHash must be 32 bytes (hex, 64 chars).');
  if (idHashBytes.length !== 32) throw new Error('documentIdHash must be 32 bytes.');
  if (holderSigBytes.length !== 64) throw new Error('Holder signature must be 64 bytes (IEEE P1363).');
  if (holderPubKeyRaw.length !== 65) throw new Error('Holder public key must be 65 bytes (uncompressed SEC1).');

  const stdin: string[] = [
    sigBytes.toString('base64'),
    pubKeyRaw.toString('base64'),
    docHashBytes.toString('base64'),
    idHashBytes.toString('base64'),
    holderSigBytes.toString('base64'),
    holderPubKeyRaw.toString('base64'),
    holderDidBytes.toString('base64'),
  ];

  const vkHash = await getVkHash();

  const reqBody: ProofRequestBody = {
    vk_hash: vkHash,
    stdin: { type: 'bytes', data: stdin },
    mode,
  };

  const submitRes = await fetch(`${SP1_URL}/v1/proof/request`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${SP1_KEY}`,
    },
    body: JSON.stringify(reqBody),
  });

  if (!submitRes.ok) {
    const errText = await submitRes.text();
    throw new Error(`SP1 proof request failed (${submitRes.status}): ${errText}`);
  }

  const { proof_id } = (await submitRes.json()) as { proof_id: string };
  console.log(`[SP1 Client] Proof request submitted. proof_id: ${proof_id}`);

  const result = await pollProof(proof_id);

  if (!result.fulfillment) throw new Error(`No SP1 fulfillment. status: ${result.status}`);

  const pv = result.fulfillment.public_values;
  if (pv.length < 4) throw new Error('SP1 public values missing (expected 4 — [docHash, pkHash, idHash, holderPkHash]).');

  return {
    proofBytes: result.fulfillment.proof_bytes,
    publicValues: {
      documentHash: Buffer.from(pv[0], 'base64').toString('hex'),
      pubKeyHash: Buffer.from(pv[1], 'base64').toString('hex'),
      documentIdHash: Buffer.from(pv[2], 'base64').toString('hex'),
      holderPubKeyHash: Buffer.from(pv[3], 'base64').toString('hex'),
    },
    proofSystem: mode === 'groth16' ? 'sp1-groth16' : 'sp1-plonk',
  };
}

async function pollProof(
  proofId: string,
  maxWaitMs = 600_000,
  intervalMs = 5_000
): Promise<ProofStatus> {
  const deadline = Date.now() + maxWaitMs;
  while (Date.now() < deadline) {
    await sleep(intervalMs);
    const res = await fetch(`${SP1_URL}/v1/proof/${proofId}`, {
      headers: { Authorization: `Bearer ${SP1_KEY}` },
    });
    if (!res.ok) throw new Error(`SP1 poll failed (${res.status}): ${await res.text()}`);
    const status = (await res.json()) as ProofStatus;
    console.log(`[SP1 Client] Proof status: ${status.status}`);
    if (status.status === 'PROOF_FULFILLED') return status;
    if (status.status === 'PROOF_UNCLAIMED')
      throw new Error('SP1 proof UNCLAIMED — no prover available.');
  }
  throw new Error(`SP1 proof timed out (${maxWaitMs / 1000}s). proof_id: ${proofId}`);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ─── SP1 Proof Verification (L2) ─────────────────────────────────────────────

export interface SP1VerifyParams {
  proofBytes: string;
  documentHash: string;
  documentIdHash: string;
  ministryPublicKey: string;
  holderPubKeyHash: string;   // K-3: circuit output #4 — feeds into expectedPublicValues
}

export async function sp1VerifyProof(params: SP1VerifyParams): Promise<boolean> {
  if (!SP1_KEY || !fs.existsSync(ELF_PATH)) return false;

  const { proofBytes, documentHash, documentIdHash, ministryPublicKey, holderPubKeyHash } = params;

  const pubKeyRaw = pubKeyPemToRaw(ministryPublicKey);
  const pubKeyHash = crypto.createHash('sha256').update(pubKeyRaw).digest();

  // Circuit commit order: [documentHash, pubKeyHash, documentIdHash, holderPubKeyHash]
  const expectedPublicValues = [
    Buffer.from(documentHash, 'hex').toString('base64'),
    pubKeyHash.toString('base64'),
    Buffer.from(documentIdHash, 'hex').toString('base64'),
    Buffer.from(holderPubKeyHash, 'hex').toString('base64'),
  ];

  const vkHash = await getVkHash();

  try {
    const res = await fetch(`${SP1_URL}/v1/proof/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${SP1_KEY}`,
      },
      body: JSON.stringify({
        vk_hash: vkHash,
        proof_bytes: proofBytes,
        mode: 'groth16',
        public_values: expectedPublicValues,
      }),
    });
    if (!res.ok) return false;
    const body = (await res.json()) as { valid: boolean };
    return body.valid === true;
  } catch {
    return false;
  }
}
