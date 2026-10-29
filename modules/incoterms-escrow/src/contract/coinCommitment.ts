/**
 * TS mirror of Escrow.compact's `CoinCore` struct + its `persistentCommit` usage
 * (`heldCommitment`). Needed for AGENTS.md 5.36's Fix B — the seller independently
 * recomputes `heldCommitment` off-chain, from data it already knows (no witness/proof
 * needed), as a defense-in-depth check before trusting a `Locked` state is really safe to
 * ship against.
 *
 * The CompactType object below is copied from the compiler's own generated output
 * (contracts/managed/escrow/contract/index.js's `_CoinCore_0` class) — same technique
 * roleKeyHash.ts already uses for `persistentHash`. A drift here would surface as this
 * check disagreeing with the real on-chain `heldCommitment` on every real deal, loudly —
 * not a silent risk.
 */

import { persistentCommit, CompactTypeBytes, CompactTypeUnsignedInteger } from '@midnight-ntwrk/compact-runtime';
import type { CompactType } from '@midnight-ntwrk/compact-runtime';

export interface CoinCoreValue {
  nonce: Uint8Array;
  color: Uint8Array;
  value: bigint;
}

const bytes32 = new CompactTypeBytes(32);
const uint128 = new CompactTypeUnsignedInteger(340282366920938463463374607431768211455n, 16);

const coinCoreType: CompactType<CoinCoreValue> = {
  alignment() {
    return bytes32.alignment().concat(bytes32.alignment().concat(uint128.alignment()));
  },
  // fromValue destructively consumes from the SAME shared `value` across all three calls
  // (matching the generated code's exact pattern) — never actually invoked by
  // persistentCommit (encode-only), kept here only to satisfy the CompactType interface.
  fromValue(value) {
    return {
      nonce: bytes32.fromValue(value),
      color: bytes32.fromValue(value),
      value: uint128.fromValue(value),
    };
  },
  toValue(value: CoinCoreValue) {
    return bytes32.toValue(value.nonce).concat(bytes32.toValue(value.color).concat(uint128.toValue(value.value)));
  },
};

/** Exactly what `Escrow.compact`'s `persistentCommit<CoinCore>(core, salt)` computes. */
export function computeHeldCommitment(core: CoinCoreValue, salt: Uint8Array): Uint8Array {
  return persistentCommit(coinCoreType, core, salt);
}
