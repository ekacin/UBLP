/**
 * Dual-recipient encrypted memo — AGENTS.md Section 5.18.
 *
 * Lets a piece of off-chain witness data (e.g. an escrow's coin+salt) be handed to a
 * counterparty AND recovered by its own author, using a single ciphertext stored as opaque
 * bytes on-chain — no separate off-chain channel, no risk of the handoff being forgotten.
 *
 * Static-static X25519 ECDH is commutative: ownPriv × counterpartyPub == counterpartyPriv ×
 * ownPub. Both sides derive the identical shared secret independently, so one ciphertext is
 * openable by either party with nothing but their own private key + the other's public key —
 * envelope-encrypting the payload twice (once per recipient) isn't needed for a two-party pair.
 *
 * Memo layout: [1 byte scheme][12 byte nonce][ciphertext][16 byte AEAD tag]
 * The scheme byte lets a future memo carry a different (e.g. post-quantum hybrid) scheme
 * without breaking decryption of escrows that are still open under the old one.
 */

import crypto from 'crypto';

export interface X25519KeyPair {
  privateKey: string; // hex, 32-byte raw scalar
  publicKey: string;  // hex, 32-byte raw point
}

const MEMO_SCHEME_X25519_CHACHA20 = 0x01;
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
const SCHEME_LENGTH = 1;

// Domain separation for the HKDF step — same convention as DOCUMENT_HASH_DOMAIN in
// documentCrypto.ts. Changing this invalidates every previously-encrypted memo.
const MEMO_HKDF_INFO = 'ublp:dual-recipient-memo:v1';

// Fixed ASN.1 headers that wrap a raw 32-byte X25519 key into the PKCS8/SPKI structures
// Node's crypto module requires — avoids the stricter JWK-OKP import path, which rejects
// a private-key-only JWK (no `x`) on some Node versions.
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

export function generateX25519KeyPair(): X25519KeyPair {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
  const privDer = privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer;
  const pubDer = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
  return {
    privateKey: privDer.subarray(X25519_PKCS8_PREFIX.length).toString('hex'),
    publicKey: pubDer.subarray(X25519_SPKI_PREFIX.length).toString('hex'),
  };
}

function toPrivateKeyObject(privateKeyHex: string): crypto.KeyObject {
  const der = Buffer.concat([X25519_PKCS8_PREFIX, Buffer.from(privateKeyHex, 'hex')]);
  return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}

function toPublicKeyObject(publicKeyHex: string): crypto.KeyObject {
  const der = Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(publicKeyHex, 'hex')]);
  return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
}

/**
 * ownPriv × counterpartyPub — commutative, so either side of a pair always derives the
 * same value regardless of who's "own" and who's "counterparty".
 */
function deriveSharedSecret(ownPrivateKeyHex: string, counterpartyPublicKeyHex: string): Buffer {
  return crypto.diffieHellman({
    privateKey: toPrivateKeyObject(ownPrivateKeyHex),
    publicKey: toPublicKeyObject(counterpartyPublicKeyHex),
  });
}

function deriveMemoKey(sharedSecret: Buffer): Buffer {
  return Buffer.from(crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), MEMO_HKDF_INFO, 32));
}

/**
 * Encrypts `plaintext` for a buyer/seller-style pair. `counterpartyPublicKeyHex` is whoever
 * the other side of the pair is — the resulting memo is later decryptable by both the caller
 * (self-recovery) and the counterparty, via the same shared secret.
 */
export function encryptDualRecipientMemo(
  plaintext: Buffer,
  ownPrivateKeyHex: string,
  counterpartyPublicKeyHex: string
): string {
  const key = deriveMemoKey(deriveSharedSecret(ownPrivateKeyHex, counterpartyPublicKeyHex));
  const nonce = crypto.randomBytes(NONCE_LENGTH);
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: TAG_LENGTH });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from([MEMO_SCHEME_X25519_CHACHA20]), nonce, ciphertext, tag]).toString('hex');
}

export function decryptDualRecipientMemo(
  memoHex: string,
  ownPrivateKeyHex: string,
  counterpartyPublicKeyHex: string
): Buffer {
  const memo = Buffer.from(memoHex, 'hex');
  const scheme = memo[0];
  if (scheme !== MEMO_SCHEME_X25519_CHACHA20) {
    throw new Error(`Unsupported dual-recipient memo scheme: 0x${scheme.toString(16).padStart(2, '0')}`);
  }

  const nonce = memo.subarray(SCHEME_LENGTH, SCHEME_LENGTH + NONCE_LENGTH);
  const tag = memo.subarray(memo.length - TAG_LENGTH);
  const ciphertext = memo.subarray(SCHEME_LENGTH + NONCE_LENGTH, memo.length - TAG_LENGTH);

  const key = deriveMemoKey(deriveSharedSecret(ownPrivateKeyHex, counterpartyPublicKeyHex));
  const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: TAG_LENGTH });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
