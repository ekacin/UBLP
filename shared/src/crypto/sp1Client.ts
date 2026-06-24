/**
 * SP1 Prover Network Client (Succinct)
 *
 * Ortam değişkenleri:
 *   SP1_PROVER_NETWORK_KEY  — Succinct API anahtarı (zorunlu)
 *   SP1_PROVER_URL          — varsayılan: https://rpc.succinct.xyz
 *   SP1_ELF_PATH            — derlenen ELF (varsayılan: sp1-circuit/elf/ublp-verifier)
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
      `[SP1] HATA: SP1_PROVER_NETWORK_KEY set ama ELF bulunamadı: ${ELF_PATH}\n` +
      `[SP1] sp1-circuit/ içinde "cargo prove build" çalıştır, ELF'i kopyala.\n` +
      `[SP1] Güvenlik garantisi olmadan mock moda düşülmeyecek — sistem duruyor.`
    );
    process.exit(1);
  }
  return SP1_KEY.length > 0 && fs.existsSync(ELF_PATH);
}

// ─── ELF / VK Hash Cache ─────────────────────────────────────────────────────

let _cachedVkHash: string | null = null;

async function getVkHash(): Promise<string> {
  if (_cachedVkHash) return _cachedVkHash;
  // Gerçek SP1 vk_hash: `cargo prove build` çıktısından üretilir.
  // Eğer sp1-circuit/elf/ublp-verifier.vk_hash dosyası varsa onu kullan.
  // Yoksa SHA256(elf) fallback — MVP'de yeterli, üretimde cargo prove vk çıktısıyla değiştir.
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

/** PEM SPKI → 65-byte uncompressed SEC1 (0x04 || x || y). SP1 circuit bunu bekler. */
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
    documentHash: string;    // hex — SHA256(canonicalJson), circuit içinde hesaplandı
    pubKeyHash: string;      // hex — SHA256(ministryPubKeyRaw)
    documentIdHash: string;  // hex — SHA256(documentId), proof'a bağlı
  };
  proofSystem: 'sp1-groth16' | 'sp1-plonk';
}

export async function generateSP1Proof(params: {
  documentCanonicalJson: string;  // canonicalJson(document) — private, circuit hash'i hesaplar
  ministrySignature: string;      // base64 IEEE P1363, 64 byte
  ministryPublicKey: string;      // PEM SPKI
  documentIdHash: string;         // hex, 32 byte — AÇIK-1: proof'a bağlanır
  mode?: ProofMode;
}): Promise<SP1ProofResult> {
  if (!SP1_KEY) throw new Error('SP1_PROVER_NETWORK_KEY ayarlı değil.');
  if (!fs.existsSync(ELF_PATH)) throw new Error(`ELF bulunamadı: ${ELF_PATH}`);

  const { documentCanonicalJson, ministrySignature, ministryPublicKey, documentIdHash, mode = 'groth16' } = params;

  // stdin sırası main.rs'deki read_vec() sırasıyla birebir eşleşmeli:
  //   1. ministry_signature
  //   2. ministry_pub_key_raw
  //   3. document_canonical_json
  //   4. document_id_hash
  const sigBytes = Buffer.from(ministrySignature, 'base64');
  const pubKeyRaw = pubKeyPemToRaw(ministryPublicKey);
  const canonicalJsonBytes = Buffer.from(documentCanonicalJson, 'utf8');
  const idHashBytes = Buffer.from(documentIdHash, 'hex');

  if (sigBytes.length !== 64) throw new Error('İmza 64 byte olmalı (IEEE P1363).');
  if (pubKeyRaw.length !== 65) throw new Error('Public key 65 byte olmalı (uncompressed SEC1).');
  if (idHashBytes.length !== 32) throw new Error('documentIdHash 32 byte olmalı.');

  const stdin: string[] = [
    sigBytes.toString('base64'),
    pubKeyRaw.toString('base64'),
    canonicalJsonBytes.toString('base64'),
    idHashBytes.toString('base64'),
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
  console.log(`[SP1 Client] Proof isteği gönderildi. proof_id: ${proof_id}`);

  const result = await pollProof(proof_id);

  if (!result.fulfillment) throw new Error(`SP1 fulfillment yok. status: ${result.status}`);

  const pv = result.fulfillment.public_values;
  if (pv.length < 3) throw new Error('SP1 public values eksik (beklenen: 3).');

  return {
    proofBytes: result.fulfillment.proof_bytes,
    publicValues: {
      documentHash: Buffer.from(pv[0], 'base64').toString('hex'),
      pubKeyHash: Buffer.from(pv[1], 'base64').toString('hex'),
      documentIdHash: Buffer.from(pv[2], 'base64').toString('hex'),
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
    console.log(`[SP1 Client] Proof durumu: ${status.status}`);
    if (status.status === 'PROOF_FULFILLED') return status;
    if (status.status === 'PROOF_UNCLAIMED')
      throw new Error('SP1 proof UNCLAIMED — prover müsait değil.');
  }
  throw new Error(`SP1 proof zaman aşımı (${maxWaitMs / 1000}s). proof_id: ${proofId}`);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ─── SP1 Proof Verification (L2) ─────────────────────────────────────────────

export interface SP1VerifyParams {
  proofBytes: string;
  documentHash: string;
  documentIdHash: string;     // AÇIK-1: expectedPublicValues'a eklendi
  ministryPublicKey: string;
}

export async function sp1VerifyProof(params: SP1VerifyParams): Promise<boolean> {
  if (!SP1_KEY || !fs.existsSync(ELF_PATH)) return false;

  const { proofBytes, documentHash, documentIdHash, ministryPublicKey } = params;

  const pubKeyRaw = pubKeyPemToRaw(ministryPublicKey);
  const pubKeyHash = crypto.createHash('sha256').update(pubKeyRaw).digest();

  // Circuit commit sırası: [documentHash, pubKeyHash, documentIdHash]
  const expectedPublicValues = [
    Buffer.from(documentHash, 'hex').toString('base64'),
    pubKeyHash.toString('base64'),
    Buffer.from(documentIdHash, 'hex').toString('base64'),
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
