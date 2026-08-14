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
import { encryptBuyerMemo, encryptSellerMemo, encryptBuyerAddressMemo } from './memo.js';

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

  /** Section 5.19 — the refund address + salt the buyer commits to at lockEscrow time,
   * used only if releaseOnTimeout ends up paying the buyer instead of the seller. */
  buyerAddress: EitherAddress | null;
  buyerAddressSalt: Uint8Array | null;

  /** The coin + salt the buyer deposited in lockEscrow. */
  depositedCoin: ShieldedCoin | null;
  depositSalt: Uint8Array | null;

  /** Once lockEscrow lands on-chain, the coin's Merkle-tree position (mt_index) becomes
   * known — this is depositedCoin + mt_index, needed at payout time. */
  qualifiedCoin: QualifiedShieldedCoin | null;

  /**
   * AGENTS.md 5.18 — X25519 keypair for the dual-recipient memo, distinct from
   * sellerSecretKey/portAuthoritySecretKey (those are role-auth hashes, not ECDH keys).
   * Whichever role holds this private state (buyer or seller) fills in its own private key
   * and the counterparty's public key — same two fields serve both directions, since ECDH
   * is symmetric (see dualRecipientMemo.ts).
   */
  ownMemoPrivateKey: Uint8Array | null;
  counterpartyMemoPublicKey: Uint8Array | null;

  /**
   * The price agreed to off-chain (EscrowTerms.amount/amountSalt) — committed at propose
   * time, re-proven at lockEscrow time so the locked coin's value can't silently differ
   * from what was agreed. Same value, both roles: seller supplies it when proposing,
   * buyer supplies it (from the terms it already received) when locking.
   */
  agreedAmount: bigint | null;
  agreedAmountSalt: Uint8Array | null;
}

export const emptyEscrowPrivateState: EscrowPrivateState = {
  sellerSecretKey: null,
  portAuthoritySecretKey: null,
  sellerAddress: null,
  sellerAddressSalt: null,
  buyerAddress: null,
  buyerAddressSalt: null,
  depositedCoin: null,
  depositSalt: null,
  qualifiedCoin: null,
  ownMemoPrivateKey: null,
  counterpartyMemoPublicKey: null,
  agreedAmount: null,
  agreedAmountSalt: null,
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

  sellerEncryptedMemo(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, Uint8Array] {
    const address = required(context.privateState.sellerAddress, 'sellerAddress');
    const salt = required(context.privateState.sellerAddressSalt, 'sellerAddressSalt');
    const ownKey = required(context.privateState.ownMemoPrivateKey, 'ownMemoPrivateKey');
    const counterpartyKey = required(
      context.privateState.counterpartyMemoPublicKey,
      'counterpartyMemoPublicKey'
    );
    return [context.privateState, encryptSellerMemo(address, salt, ownKey, counterpartyKey)];
  },

  buyerEncryptedMemo(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, Uint8Array] {
    const coin = required(context.privateState.depositedCoin, 'depositedCoin');
    const salt = required(context.privateState.depositSalt, 'depositSalt');
    const ownKey = required(context.privateState.ownMemoPrivateKey, 'ownMemoPrivateKey');
    const counterpartyKey = required(
      context.privateState.counterpartyMemoPublicKey,
      'counterpartyMemoPublicKey'
    );
    return [context.privateState, encryptBuyerMemo(coin, salt, ownKey, counterpartyKey)];
  },

  agreedAmount(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, bigint] {
    return [context.privateState, required(context.privateState.agreedAmount, 'agreedAmount')];
  },

  agreedAmountSalt(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, Uint8Array] {
    return [
      context.privateState,
      required(context.privateState.agreedAmountSalt, 'agreedAmountSalt'),
    ];
  },

  lockedAmount(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, bigint] {
    // Section 5.18-style reuse: same agreed amount, re-supplied under a different witness
    // name because it's called from a different circuit (lockEscrow, not propose).
    return [context.privateState, required(context.privateState.agreedAmount, 'agreedAmount')];
  },

  lockedAmountSalt(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, Uint8Array] {
    return [
      context.privateState,
      required(context.privateState.agreedAmountSalt, 'agreedAmountSalt'),
    ];
  },

  proposedBuyerAddress(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, EitherAddress] {
    return [context.privateState, required(context.privateState.buyerAddress, 'buyerAddress')];
  },

  buyerAddressSalt(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, Uint8Array] {
    return [
      context.privateState,
      required(context.privateState.buyerAddressSalt, 'buyerAddressSalt'),
    ];
  },

  buyerAddressEncryptedMemo(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, Uint8Array] {
    const address = required(context.privateState.buyerAddress, 'buyerAddress');
    const salt = required(context.privateState.buyerAddressSalt, 'buyerAddressSalt');
    const ownKey = required(context.privateState.ownMemoPrivateKey, 'ownMemoPrivateKey');
    const counterpartyKey = required(
      context.privateState.counterpartyMemoPublicKey,
      'counterpartyMemoPublicKey'
    );
    return [context.privateState, encryptBuyerAddressMemo(address, salt, ownKey, counterpartyKey)];
  },

  payoutBuyerAddress(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, EitherAddress] {
    // Same address — the only value that will match the commitment made at lockEscrow time.
    return [context.privateState, required(context.privateState.buyerAddress, 'buyerAddress')];
  },

  payoutBuyerAddressSalt(
    context: WitnessContext<Ledger, EscrowPrivateState>
  ): [EscrowPrivateState, Uint8Array] {
    return [
      context.privateState,
      required(context.privateState.buyerAddressSalt, 'buyerAddressSalt'),
    ];
  },
};
