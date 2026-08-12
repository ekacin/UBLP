/**
 * Witness implementations for Escrow.compact. See AGENTS.md Section 5.14.1 — coin/address
 * data always comes from here (a witness), never as a plain circuit argument.
 *
 * ROLE SEPARATION (deliberate, least-privilege): whoever builds the proof for
 * `attestLoadingConfirmed` (C) only ever needs its own `portAuthoritySecretKey` — it never
 * touches the coin/address witnesses. Whoever builds `claimPayout` (in practice the seller's
 * own agent) needs the coin+salt (from the buyer) and its own address+salt — these can travel
 * over the existing buyer-seller negotiation channel (propose/accept); C is never involved.
 */

import type { WitnessContext } from '@midnight-ntwrk/compact-runtime';
import type { Ledger, Witnesses } from '../../contracts/managed/escrow/contract/index.js';

/** Compact's `Either<ZswapCoinPublicKey, ContractAddress>` representation — both branches
 * must be populated, `is_left` alone marks which one is active. */
export interface EitherAddress {
  is_left: boolean;
  left: { bytes: Uint8Array };
  right: { bytes: Uint8Array };
}

const ZERO_32 = new Uint8Array(32);

export function zswapRecipient(publicKeyBytes: Uint8Array): EitherAddress {
  return { is_left: true, left: { bytes: publicKeyBytes }, right: { bytes: ZERO_32 } };
}

/** For future contract-to-contract payouts. */
export function contractRecipient(addressBytes: Uint8Array): EitherAddress {
  return { is_left: false, left: { bytes: ZERO_32 }, right: { bytes: addressBytes } };
}

export interface ShieldedCoin {
  nonce: Uint8Array;
  color: Uint8Array;
  value: bigint;
}

export interface QualifiedShieldedCoin extends ShieldedCoin {
  mt_index: bigint;
}

/**
 * All local (never on-chain) data needed across an escrow instance's lifecycle. Which
 * fields are populated depends on the role of the agent holding this private state (seller /
 * buyer / C) — all three share the same type, unused fields stay `null`.
 */
export interface EscrowPrivateState {
  /** Only populated on the seller's own agent. */
  sellerSecretKey: Uint8Array | null;
  /** Only populated on C's own agent — see AGENTS.md 5.12. */
  portAuthoritySecretKey: Uint8Array | null;

  /** The payout address + salt the seller committed to at propose time. */
  sellerAddress: EitherAddress | null;
  sellerAddressSalt: Uint8Array | null;

  /** The coin + salt the buyer deposited in lockEscrow. */
  depositedCoin: ShieldedCoin | null;
  depositSalt: Uint8Array | null;

  /** Once lockEscrow lands on-chain, the coin's Merkle-tree position (mt_index) becomes
   * known — this is depositedCoin + mt_index, needed at payout time. */
  qualifiedCoin: QualifiedShieldedCoin | null;
}

export const emptyEscrowPrivateState: EscrowPrivateState = {
  sellerSecretKey: null,
  portAuthoritySecretKey: null,
  sellerAddress: null,
  sellerAddressSalt: null,
  depositedCoin: null,
  depositSalt: null,
  qualifiedCoin: null,
};

function required<T>(value: T | null, fieldName: string): T {
  if (value === null) {
    throw new Error(
      `EscrowPrivateState.${fieldName} is not set — it must be populated before this witness can be called.`
    );
  }
  return value;
}

export const escrowWitnesses: Witnesses<EscrowPrivateState> = {
  sellerSecretKey(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, Uint8Array] {
    return [context.privateState, required(context.privateState.sellerSecretKey, 'sellerSecretKey')];
  },

  portAuthoritySecretKey(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, Uint8Array] {
    return [
      context.privateState,
      required(context.privateState.portAuthoritySecretKey, 'portAuthoritySecretKey'),
    ];
  },

  depositedCoin(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, ShieldedCoin] {
    return [context.privateState, required(context.privateState.depositedCoin, 'depositedCoin')];
  },

  depositSalt(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, Uint8Array] {
    return [context.privateState, required(context.privateState.depositSalt, 'depositSalt')];
  },

  heldCoinForRelease(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, QualifiedShieldedCoin] {
    return [context.privateState, required(context.privateState.qualifiedCoin, 'qualifiedCoin')];
  },

  releaseSalt(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, Uint8Array] {
    // Section 5.14.1 Experiment 3: deposit and release must verify the same commitment, hence the same salt.
    return [context.privateState, required(context.privateState.depositSalt, 'depositSalt')];
  },

  proposedSellerAddress(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, EitherAddress] {
    return [context.privateState, required(context.privateState.sellerAddress, 'sellerAddress')];
  },

  sellerAddressSalt(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, Uint8Array] {
    return [
      context.privateState,
      required(context.privateState.sellerAddressSalt, 'sellerAddressSalt'),
    ];
  },

  payoutSellerAddress(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, EitherAddress] {
    // Same address — the only value that will match the commitment made at propose time.
    return [context.privateState, required(context.privateState.sellerAddress, 'sellerAddress')];
  },

  payoutAddressSalt(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, Uint8Array] {
    return [
      context.privateState,
      required(context.privateState.sellerAddressSalt, 'sellerAddressSalt'),
    ];
  },
};
