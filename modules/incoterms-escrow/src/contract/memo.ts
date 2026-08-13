/**
 * Fixed-size plaintext layouts for Escrow.compact's dual-recipient memos (AGENTS.md 5.18).
 * The contract only ever sees the encrypted bytes — encoding/decoding and the encrypt/decrypt
 * calls themselves (@ublp/shared/crypto/dualRecipientMemo) both happen here, off-chain.
 */

import { encryptDualRecipientMemo, decryptDualRecipientMemo } from '@ublp/shared';
import type { EitherAddress, ShieldedCoin } from './witnesses';

// coin.nonce(32) + coin.color(32) + coin.value(16) + depositSalt(32)
export const BUYER_MEMO_PLAINTEXT_LENGTH = 112;
// address.is_left(1) + address.left(32) + address.right(32) + addressSalt(32)
export const SELLER_MEMO_PLAINTEXT_LENGTH = 97;

function uint128ToBytes(value: bigint): Buffer {
  const buf = Buffer.alloc(16);
  buf.writeBigUInt64BE(value >> 64n, 0);
  buf.writeBigUInt64BE(value & 0xffffffffffffffffn, 8);
  return buf;
}

function bytesToUint128(buf: Buffer): bigint {
  const hi = buf.readBigUInt64BE(0);
  const lo = buf.readBigUInt64BE(8);
  return (hi << 64n) | lo;
}

export function encodeBuyerMemoPlaintext(coin: ShieldedCoin, depositSalt: Uint8Array): Buffer {
  return Buffer.concat([
    Buffer.from(coin.nonce),
    Buffer.from(coin.color),
    uint128ToBytes(coin.value),
    Buffer.from(depositSalt),
  ]);
}

export function decodeBuyerMemoPlaintext(
  plaintext: Buffer
): { coin: ShieldedCoin; depositSalt: Uint8Array } {
  if (plaintext.length !== BUYER_MEMO_PLAINTEXT_LENGTH) {
    throw new Error(
      `Buyer memo plaintext must be ${BUYER_MEMO_PLAINTEXT_LENGTH} bytes, got ${plaintext.length}.`
    );
  }
  return {
    coin: {
      nonce: new Uint8Array(plaintext.subarray(0, 32)),
      color: new Uint8Array(plaintext.subarray(32, 64)),
      value: bytesToUint128(plaintext.subarray(64, 80)),
    },
    depositSalt: new Uint8Array(plaintext.subarray(80, 112)),
  };
}

export function encodeSellerMemoPlaintext(address: EitherAddress, addressSalt: Uint8Array): Buffer {
  return Buffer.concat([
    Buffer.from([address.is_left ? 1 : 0]),
    Buffer.from(address.left.bytes),
    Buffer.from(address.right.bytes),
    Buffer.from(addressSalt),
  ]);
}

export function decodeSellerMemoPlaintext(
  plaintext: Buffer
): { address: EitherAddress; addressSalt: Uint8Array } {
  if (plaintext.length !== SELLER_MEMO_PLAINTEXT_LENGTH) {
    throw new Error(
      `Seller memo plaintext must be ${SELLER_MEMO_PLAINTEXT_LENGTH} bytes, got ${plaintext.length}.`
    );
  }
  return {
    address: {
      is_left: plaintext[0] === 1,
      left: { bytes: new Uint8Array(plaintext.subarray(1, 33)) },
      right: { bytes: new Uint8Array(plaintext.subarray(33, 65)) },
    },
    addressSalt: new Uint8Array(plaintext.subarray(65, 97)),
  };
}

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

export function encryptBuyerMemo(
  coin: ShieldedCoin,
  depositSalt: Uint8Array,
  ownPrivateKey: Uint8Array,
  counterpartyPublicKey: Uint8Array
): Uint8Array {
  const plaintext = encodeBuyerMemoPlaintext(coin, depositSalt);
  const memoHex = encryptDualRecipientMemo(plaintext, toHex(ownPrivateKey), toHex(counterpartyPublicKey));
  return new Uint8Array(Buffer.from(memoHex, 'hex'));
}

export function encryptSellerMemo(
  address: EitherAddress,
  addressSalt: Uint8Array,
  ownPrivateKey: Uint8Array,
  counterpartyPublicKey: Uint8Array
): Uint8Array {
  const plaintext = encodeSellerMemoPlaintext(address, addressSalt);
  const memoHex = encryptDualRecipientMemo(plaintext, toHex(ownPrivateKey), toHex(counterpartyPublicKey));
  return new Uint8Array(Buffer.from(memoHex, 'hex'));
}

/** Recovery path (AGENTS.md 5.18): either the buyer or the seller can call this — both
 * derive the same ECDH shared secret regardless of which side encrypted the memo. */
export function recoverBuyerMemo(
  memoBytes: Uint8Array,
  ownPrivateKey: Uint8Array,
  counterpartyPublicKey: Uint8Array
): { coin: ShieldedCoin; depositSalt: Uint8Array } {
  const plaintext = decryptDualRecipientMemo(toHex(memoBytes), toHex(ownPrivateKey), toHex(counterpartyPublicKey));
  return decodeBuyerMemoPlaintext(plaintext);
}

export function recoverSellerMemo(
  memoBytes: Uint8Array,
  ownPrivateKey: Uint8Array,
  counterpartyPublicKey: Uint8Array
): { address: EitherAddress; addressSalt: Uint8Array } {
  const plaintext = decryptDualRecipientMemo(toHex(memoBytes), toHex(ownPrivateKey), toHex(counterpartyPublicKey));
  return decodeSellerMemoPlaintext(plaintext);
}
