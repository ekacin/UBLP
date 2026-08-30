/**
 * Browser-side counterpart to @ublp/shared's verifySignatureOverHash (documentCrypto.ts).
 *
 * The backend verifies with `crypto.verify(null, hashBytes, { dsaEncoding: 'ieee-p1363' }, sig)`
 * — algorithm `null` means Node signs/verifies the given bytes AS-IS, with no additional
 * hashing. The Web Crypto API has no equivalent "raw digest" mode for ECDSA — `subtle.sign`
 * always hashes its input first. Signing here with Web Crypto directly would therefore sign
 * SHA-256(nonceBytes) instead of nonceBytes itself, and verification on the backend would
 * always fail.
 *
 * Fix: use Web Crypto ONLY to parse the PKCS8 PEM into its raw private scalar (a standard,
 * well-supported operation), then hand that raw scalar to @noble/curves' p256.sign() with
 * `prehash: false` — which signs the input bytes exactly as given, matching Node's
 * `algorithm: null` semantics exactly. Output format 'compact' (raw r||s, 64 bytes for P-256)
 * matches Node's `dsaEncoding: 'ieee-p1363'`.
 */

import { p256 } from '@noble/curves/nist.js';

function pemToDer(pem: string): Uint8Array {
  const base64 = pem
    .replace(/-----BEGIN [^-]+-----/, '')
    .replace(/-----END [^-]+-----/, '')
    .replace(/\s+/g, '');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64UrlToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(b64url.length / 4) * 4, '=');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

/** Extracts the raw 32-byte P-256 private scalar from a PKCS8 PEM, via Web Crypto's PEM/JWK
 * parsing — this is the only thing Web Crypto is used for; it never performs the actual
 * signature (see file header for why). */
async function rawScalarFromPkcs8Pem(pem: string): Promise<Uint8Array> {
  const der = pemToDer(pem);
  const key = await crypto.subtle.importKey('pkcs8', der, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', key);
  if (!jwk.d) throw new Error('imported key has no private scalar (d)');
  return base64UrlToBytes(jwk.d);
}

/** Signs `nonceHex` exactly as @ublp/shared's verifySignatureOverHash expects — base64,
 * IEEE-P1363 (raw r||s), no additional hashing beyond the raw nonce bytes themselves. */
export async function signNonceHex(privateKeyPem: string, nonceHex: string): Promise<string> {
  const rawScalar = await rawScalarFromPkcs8Pem(privateKeyPem);
  const nonceBytes = hexToBytes(nonceHex);
  const sig = p256.sign(nonceBytes, rawScalar, { prehash: false });
  return bytesToBase64(sig.toBytes('compact'));
}

/** Sanity-checks a pasted PEM is at least well-formed and importable before it's stored. */
export async function validateLoginKeyPem(privateKeyPem: string): Promise<boolean> {
  try {
    await rawScalarFromPkcs8Pem(privateKeyPem);
    return true;
  } catch {
    return false;
  }
}
