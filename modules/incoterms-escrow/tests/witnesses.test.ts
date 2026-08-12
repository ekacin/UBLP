import { describe, it, expect } from 'vitest';
import type { WitnessContext } from '@midnight-ntwrk/compact-runtime';
import {
  escrowWitnesses,
  emptyEscrowPrivateState,
  zswapRecipient,
  contractRecipient,
  type EscrowPrivateState,
} from '../src/contract/witnesses';

function contextWith(privateState: EscrowPrivateState): WitnessContext<unknown, EscrowPrivateState> {
  return { ledger: {}, privateState, contractAddress: {} as never };
}

const SELLER_SK = new Uint8Array(32).fill(1);
const PORT_AUTH_SK = new Uint8Array(32).fill(2);
const SELLER_PUBKEY = new Uint8Array(32).fill(3);
const SALT_A = new Uint8Array(32).fill(4);
const SALT_B = new Uint8Array(32).fill(5);

const filledState: EscrowPrivateState = {
  sellerSecretKey: SELLER_SK,
  portAuthoritySecretKey: PORT_AUTH_SK,
  sellerAddress: zswapRecipient(SELLER_PUBKEY),
  sellerAddressSalt: SALT_A,
  depositedCoin: { nonce: new Uint8Array(32).fill(6), color: new Uint8Array(32).fill(7), value: 1_000_000n },
  depositSalt: SALT_B,
  qualifiedCoin: {
    nonce: new Uint8Array(32).fill(6),
    color: new Uint8Array(32).fill(7),
    value: 1_000_000n,
    mt_index: 42n,
  },
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
  ];

  for (const name of cases) {
    it(`${name} throws a clear error on missing data (never fails silently)`, () => {
      const fn = escrowWitnesses[name] as (ctx: WitnessContext<unknown, EscrowPrivateState>) => unknown;
      expect(() => fn(contextWith(emptyEscrowPrivateState))).toThrow();
    });
  }
});
