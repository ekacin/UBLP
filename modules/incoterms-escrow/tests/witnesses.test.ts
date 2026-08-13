import { describe, it, expect } from 'vitest';
import type { WitnessContext } from '@midnight-ntwrk/compact-runtime';
import { generateX25519KeyPair } from '@ublp/shared';
import {
  escrowWitnesses,
  emptyEscrowPrivateState,
  zswapRecipient,
  contractRecipient,
  type EscrowPrivateState,
} from '../src/contract/witnesses';
import { recoverBuyerMemo, recoverSellerMemo, recoverBuyerAddressMemo } from '../src/contract/memo';

function contextWith(privateState: EscrowPrivateState): WitnessContext<unknown, EscrowPrivateState> {
  return { ledger: {}, privateState, contractAddress: {} as never };
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

const SELLER_SK = new Uint8Array(32).fill(1);
const PORT_AUTH_SK = new Uint8Array(32).fill(2);
const SELLER_PUBKEY = new Uint8Array(32).fill(3);
const SALT_A = new Uint8Array(32).fill(4);
const SALT_B = new Uint8Array(32).fill(5);
const AMOUNT_SALT = new Uint8Array(32).fill(10);
const BUYER_PUBKEY = new Uint8Array(32).fill(11);
const SALT_C = new Uint8Array(32).fill(12);

const buyerMemoKeys = generateX25519KeyPair();
const sellerMemoKeys = generateX25519KeyPair();

const filledState: EscrowPrivateState = {
  sellerSecretKey: SELLER_SK,
  portAuthoritySecretKey: PORT_AUTH_SK,
  sellerAddress: zswapRecipient(SELLER_PUBKEY),
  sellerAddressSalt: SALT_A,
  buyerAddress: zswapRecipient(BUYER_PUBKEY),
  buyerAddressSalt: SALT_C,
  depositedCoin: { nonce: new Uint8Array(32).fill(6), color: new Uint8Array(32).fill(7), value: 1_000_000n },
  depositSalt: SALT_B,
  qualifiedCoin: {
    nonce: new Uint8Array(32).fill(6),
    color: new Uint8Array(32).fill(7),
    value: 1_000_000n,
    mt_index: 42n,
  },
  // "seller" role instance: own key = seller's, counterparty = buyer's public key
  ownMemoPrivateKey: hexToBytes(sellerMemoKeys.privateKey),
  counterpartyMemoPublicKey: hexToBytes(buyerMemoKeys.publicKey),
  agreedAmount: 1_000_000n,
  agreedAmountSalt: AMOUNT_SALT,
};

describe('zswapRecipient / contractRecipient', () => {
  it('zswapRecipient marks is_left true and fills the right branch with zero bytes', () => {
    const addr = zswapRecipient(SELLER_PUBKEY);
    expect(addr.is_left).toBe(true);
    expect(addr.left.bytes).toBe(SELLER_PUBKEY);
    expect(addr.right.bytes).toEqual(new Uint8Array(32));
  });

  it('contractRecipient marks is_left false and fills the left branch with zero bytes', () => {
    const addr = contractRecipient(SELLER_PUBKEY);
    expect(addr.is_left).toBe(false);
    expect(addr.right.bytes).toBe(SELLER_PUBKEY);
    expect(addr.left.bytes).toEqual(new Uint8Array(32));
  });
});

describe('escrowWitnesses — populated privateState', () => {
  it('returns sellerSecretKey', () => {
    const [, value] = escrowWitnesses.sellerSecretKey(contextWith(filledState));
    expect(value).toBe(SELLER_SK);
  });

  it('returns portAuthoritySecretKey', () => {
    const [, value] = escrowWitnesses.portAuthoritySecretKey(contextWith(filledState));
    expect(value).toBe(PORT_AUTH_SK);
  });

  it('returns depositedCoin', () => {
    const [, value] = escrowWitnesses.depositedCoin(contextWith(filledState));
    expect(value).toBe(filledState.depositedCoin);
  });

  it('depositSalt and releaseSalt return the SAME salt (must verify the same commitment)', () => {
    const [, depositSalt] = escrowWitnesses.depositSalt(contextWith(filledState));
    const [, releaseSalt] = escrowWitnesses.releaseSalt(contextWith(filledState));
    expect(depositSalt).toBe(SALT_B);
    expect(releaseSalt).toBe(SALT_B);
  });

  it('returns heldCoinForRelease as qualifiedCoin', () => {
    const [, value] = escrowWitnesses.heldCoinForRelease(contextWith(filledState));
    expect(value).toBe(filledState.qualifiedCoin);
  });

  it('proposedSellerAddress and payoutSellerAddress return the SAME address (must verify the same commitment)', () => {
    const [, proposed] = escrowWitnesses.proposedSellerAddress(contextWith(filledState));
    const [, payout] = escrowWitnesses.payoutSellerAddress(contextWith(filledState));
    expect(proposed).toBe(filledState.sellerAddress);
    expect(payout).toBe(filledState.sellerAddress);
  });

  it('sellerAddressSalt and payoutAddressSalt return the SAME salt', () => {
    const [, s1] = escrowWitnesses.sellerAddressSalt(contextWith(filledState));
    const [, s2] = escrowWitnesses.payoutAddressSalt(contextWith(filledState));
    expect(s1).toBe(SALT_A);
    expect(s2).toBe(SALT_A);
  });

  it('sellerEncryptedMemo produces bytes recoverable back to the original address+salt', () => {
    const [, memo] = escrowWitnesses.sellerEncryptedMemo(contextWith(filledState));
    expect(memo.length).toBe(126);
    const recovered = recoverSellerMemo(
      memo,
      filledState.ownMemoPrivateKey!,
      filledState.counterpartyMemoPublicKey!
    );
    expect(recovered.address).toEqual(filledState.sellerAddress);
    expect(recovered.addressSalt).toEqual(SALT_A);
  });

  it('buyerEncryptedMemo produces bytes recoverable back to the original coin+salt', () => {
    const [, memo] = escrowWitnesses.buyerEncryptedMemo(contextWith(filledState));
    expect(memo.length).toBe(141);
    const recovered = recoverBuyerMemo(
      memo,
      filledState.ownMemoPrivateKey!,
      filledState.counterpartyMemoPublicKey!
    );
    expect(recovered.coin).toEqual(filledState.depositedCoin);
    expect(recovered.depositSalt).toEqual(SALT_B);
  });

  it('agreedAmount and lockedAmount return the SAME amount (must verify the same commitment)', () => {
    const [, proposed] = escrowWitnesses.agreedAmount(contextWith(filledState));
    const [, locked] = escrowWitnesses.lockedAmount(contextWith(filledState));
    expect(proposed).toBe(1_000_000n);
    expect(locked).toBe(1_000_000n);
  });

  it('agreedAmountSalt and lockedAmountSalt return the SAME salt', () => {
    const [, s1] = escrowWitnesses.agreedAmountSalt(contextWith(filledState));
    const [, s2] = escrowWitnesses.lockedAmountSalt(contextWith(filledState));
    expect(s1).toBe(AMOUNT_SALT);
    expect(s2).toBe(AMOUNT_SALT);
  });

  it('proposedBuyerAddress and payoutBuyerAddress return the SAME address (Section 5.19)', () => {
    const [, proposed] = escrowWitnesses.proposedBuyerAddress(contextWith(filledState));
    const [, payout] = escrowWitnesses.payoutBuyerAddress(contextWith(filledState));
    expect(proposed).toBe(filledState.buyerAddress);
    expect(payout).toBe(filledState.buyerAddress);
  });

  it('buyerAddressSalt and payoutBuyerAddressSalt return the SAME salt', () => {
    const [, s1] = escrowWitnesses.buyerAddressSalt(contextWith(filledState));
    const [, s2] = escrowWitnesses.payoutBuyerAddressSalt(contextWith(filledState));
    expect(s1).toBe(SALT_C);
    expect(s2).toBe(SALT_C);
  });

  it('buyerAddressEncryptedMemo produces bytes recoverable back to the original buyer address+salt', () => {
    const [, memo] = escrowWitnesses.buyerAddressEncryptedMemo(contextWith(filledState));
    expect(memo.length).toBe(126);
    const recovered = recoverBuyerAddressMemo(
      memo,
      filledState.ownMemoPrivateKey!,
      filledState.counterpartyMemoPublicKey!
    );
    expect(recovered.address).toEqual(filledState.buyerAddress);
    expect(recovered.addressSalt).toEqual(SALT_C);
  });
});

describe('escrowWitnesses — empty privateState (emptyEscrowPrivateState)', () => {
  const cases: Array<keyof typeof escrowWitnesses> = [
    'sellerSecretKey',
    'portAuthoritySecretKey',
    'depositedCoin',
    'depositSalt',
    'heldCoinForRelease',
    'releaseSalt',
    'proposedSellerAddress',
    'sellerAddressSalt',
    'payoutSellerAddress',
    'payoutAddressSalt',
    'sellerEncryptedMemo',
    'buyerEncryptedMemo',
    'agreedAmount',
    'agreedAmountSalt',
    'lockedAmount',
    'lockedAmountSalt',
    'proposedBuyerAddress',
    'buyerAddressSalt',
    'buyerAddressEncryptedMemo',
    'payoutBuyerAddress',
    'payoutBuyerAddressSalt',
  ];

  for (const name of cases) {
    it(`${name} throws a clear error on missing data (never fails silently)`, () => {
      const fn = escrowWitnesses[name] as (ctx: WitnessContext<unknown, EscrowPrivateState>) => unknown;
      expect(() => fn(contextWith(emptyEscrowPrivateState))).toThrow();
    });
  }
});
