/**
 * Fixed-size plaintext layouts for Escrow.compact's dual-recipient memos (AGENTS.md 5.18).
 * The contract only ever sees the encrypted bytes — encoding/decoding and the encrypt/decrypt
 * calls themselves (@ublp/shared/crypto/dualRecipientMemo) both happen here, off-chain.
 */

import { encryptDualRecipientMemo, decryptDualRecipientMemo } from '@ublp/shared';
import type { EitherAddress } from './witnesses.js';

// address.is_left(1) + address.left(32) + address.right(32) + addressSalt(32) — shared shape
// for BOTH sellerMemo (propose) and buyerAddressMemo (lockEscrow, Section 5.19).
//
// A THIRD plaintext layout (coin.nonce+color+value+depositSalt, for the old `buyerMemo`)
// used to live here — removed (AGENTS.md 5.36, Discord finding #3): the seller now
// pre-commits the coin's own nonce+salt at propose() time instead of recovering them from an
// unverified, buyer-supplied memo (see src/server/actions.ts).
export const ADDRESS_MEMO_PLAINTEXT_LENGTH = 97;
export const SELLER_MEMO_PLAINTEXT_LENGTH = ADDRESS_MEMO_PLAINTEXT_LENGTH;

export function encodeAddressMemoPlaintext(address: EitherAddress, addressSalt: Uint8Array): Buffer {
  return Buffer.concat([
    Buffer.from([address.is_left ? 1 : 0]),
    Buffer.from(address.left.bytes),
    Buffer.from(address.right.bytes),
    Buffer.from(addressSalt),
  ]);
}

export function decodeAddressMemoPlaintext(
  plaintext: Buffer
): { address: EitherAddress; addressSalt: Uint8Array } {
  if (plaintext.length !== ADDRESS_MEMO_PLAINTEXT_LENGTH) {
    throw new Error(
      `Address memo plaintext must be ${ADDRESS_MEMO_PLAINTEXT_LENGTH} bytes, got ${plaintext.length}.`
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

export const encodeSellerMemoPlaintext = encodeAddressMemoPlaintext;
export const decodeSellerMemoPlaintext = decodeAddressMemoPlaintext;

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

export function encryptAddressMemo(
  address: EitherAddress,
  addressSalt: Uint8Array,
  ownPrivateKey: Uint8Array,
  counterpartyPublicKey: Uint8Array
): Uint8Array {
  const plaintext = encodeAddressMemoPlaintext(address, addressSalt);
  const memoHex = encryptDualRecipientMemo(plaintext, toHex(ownPrivateKey), toHex(counterpartyPublicKey));
  return new Uint8Array(Buffer.from(memoHex, 'hex'));
}

export const encryptSellerMemo = encryptAddressMemo;
export const encryptBuyerAddressMemo = encryptAddressMemo;

/** Recovery path (AGENTS.md 5.18): either the buyer or the seller can call this — both
 * derive the same ECDH shared secret regardless of which side encrypted the memo. */
export function recoverAddressMemo(
  memoBytes: Uint8Array,
  ownPrivateKey: Uint8Array,
  counterpartyPublicKey: Uint8Array
): { address: EitherAddress; addressSalt: Uint8Array } {
  const plaintext = decryptDualRecipientMemo(toHex(memoBytes), toHex(ownPrivateKey), toHex(counterpartyPublicKey));
  return decodeAddressMemoPlaintext(plaintext);
}

export const recoverSellerMemo = recoverAddressMemo;
export const recoverBuyerAddressMemo = recoverAddressMemo;
