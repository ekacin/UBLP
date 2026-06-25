/**
 * BLS12-381 threshold imza primitifleri (@noble/bls12-381)
 *
 * Scheme: min-pubkey-size (G1 pubkey 48 byte, G2 sig 96 byte)
 * Aggregation: same-message — aggSig = agg(sig_i...), aggPk = agg(pk_i...)
 *              bls.verify(aggSig, msg, aggPk) === true iff all partial sigs valid
 *
 * t-of-n doğrulama:
 *   - groupKeyHash = SHA256(sorted ALL n member pubkeys) — statik, L2 sync'te alınır
 *   - Attestation yalnızca hangi t üyenin imzaladığını (signerIds) + aggSig taşır
 *   - L2 kendi deposundaki pubkeys'den lookup yapar — attestation'daki pubkey'lere güvenmez (K-2 fix)
 */

import crypto from 'crypto';
import * as bls from '@noble/bls12-381';

export interface BLSKeyPair {
  privateKey: string; // hex 32 bytes
  publicKey: string;  // hex 48 bytes compressed G1
}

export function blsGenerateKeyPair(): BLSKeyPair {
  const privBytes = bls.utils.randomPrivateKey();
  const pubBytes = bls.getPublicKey(privBytes);
  return {
    privateKey: Buffer.from(privBytes).toString('hex'),
    publicKey: Buffer.from(pubBytes).toString('hex'),
  };
}

export async function blsSign(msgHex: string, privKeyHex: string): Promise<string> {
  const msg = Buffer.from(msgHex, 'hex');
  const priv = Buffer.from(privKeyHex, 'hex');
  const sig = await bls.sign(msg, priv);
  return Buffer.from(sig).toString('hex');
}

export async function blsVerify(
  sigHex: string,
  msgHex: string,
  pubKeyHex: string
): Promise<boolean> {
  try {
    const sig = Buffer.from(sigHex, 'hex');
    const msg = Buffer.from(msgHex, 'hex');
    const pub = Buffer.from(pubKeyHex, 'hex');
    return await bls.verify(sig, msg, pub);
  } catch {
    return false;
  }
}

/** t-of-n aggregation: aggSig = agg(sig_i...) — same message assumed */
export function blsAggregateSignatures(sigHexes: string[]): string {
  const sigs = sigHexes.map((h) => Buffer.from(h, 'hex'));
  return Buffer.from(bls.aggregateSignatures(sigs)).toString('hex');
}

/** Aggregated pubkey for same-message verification */
export function blsAggregatePublicKeys(pubKeyHexes: string[]): string {
  const pubs = pubKeyHexes.map((h) => Buffer.from(h, 'hex'));
  return Buffer.from(bls.aggregatePublicKeys(pubs)).toString('hex');
}

/**
 * K-2 fix: groupKeyHash = SHA256(sorted ALL n member pubkeys concatenated)
 * Statik — tam üye listesi değişmeden değişmez.
 * Attestation içindeki signer subset'i bu hash'i etkilemez.
 */
export function blsGroupKeyHash(allMemberPubKeyHexes: string[]): string {
  const sorted = [...allMemberPubKeyHexes].sort();
  const joined = sorted.join('');
  return crypto.createHash('sha256').update(joined).digest('hex');
}

/**
 * t-of-n BLS doğrulama (K-2 fix).
 * signerPubKeyHexes: L2'nin kendi deposundan lookup'lanan pubkey'ler (attestation'dakiler değil).
 * msgHex: doğrulama mesajı (kombinasyon hash).
 */
export async function blsVerifyThreshold(
  aggSigHex: string,
  msgHex: string,
  signerPubKeyHexes: string[],
  threshold: number
): Promise<{ valid: boolean; reason?: string }> {
  if (signerPubKeyHexes.length < threshold) {
    return {
      valid: false,
      reason: `Eşik sağlanamadı: ${signerPubKeyHexes.length} < ${threshold}`,
    };
  }
  const aggPubKey = blsAggregatePublicKeys(signerPubKeyHexes);
  const ok = await blsVerify(aggSigHex, msgHex, aggPubKey);
  return ok ? { valid: true } : { valid: false, reason: 'BLS aggregate verify başarısız.' };
}
