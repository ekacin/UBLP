import { describe, it, expect } from 'vitest';
import { shieldedToken, encodeShieldedCoinInfo } from '@midnight-ntwrk/midnight-js-protocol/ledger';
import { computeDepositVerification } from '../../src/server/actions.js';
import { computeHeldCommitment } from '../../src/contract/coinCommitment.js';
import { emptyEscrowPrivateState, type EscrowPrivateState } from '../../src/contract/witnesses.js';

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

const DEPOSIT_NONCE = new Uint8Array(32).fill(7);
const DEPOSIT_SALT = new Uint8Array(32).fill(8);
const AGREED_AMOUNT = 1_000_000n;

/** Builds the exact heldCommitment lockEscrow() would have written on-chain for this nonce/
 * salt/amount — same construction actions.ts's claimDeal uses. */
function realHeldCommitment(nonce: Uint8Array): Uint8Array {
  const coin = { type: shieldedToken().raw, nonce: Buffer.from(nonce).toString('hex'), value: AGREED_AMOUNT };
  const encoded = encodeShieldedCoinInfo(coin) as any;
  return computeHeldCommitment(
    { nonce: hexToBytes(encoded.nonce ?? coin.nonce), color: hexToBytes(encoded.color), value: AGREED_AMOUNT },
    DEPOSIT_SALT
  );
}

const basePrivateState: EscrowPrivateState = {
  ...emptyEscrowPrivateState,
  depositNonce: DEPOSIT_NONCE,
  depositSalt: DEPOSIT_SALT,
  agreedAmount: AGREED_AMOUNT,
};

describe('computeDepositVerification (AGENTS.md 5.36 Fix B)', () => {
  it("returns true when the seller's own recorded data matches the on-chain heldCommitment", () => {
    expect(computeDepositVerification(basePrivateState, realHeldCommitment(DEPOSIT_NONCE))).toBe(true);
  });

  it('returns false when the on-chain heldCommitment is anything else', () => {
    const wrongCommitment = new Uint8Array(32).fill(99);
    expect(computeDepositVerification(basePrivateState, wrongCommitment)).toBe(false);
  });

  it('returns false if the locally recorded nonce does not match what was actually locked', () => {
    const differentNonce = new Uint8Array(32).fill(1);
    // on-chain commitment was built from DEPOSIT_NONCE, but local state now (wrongly) records a different one
    expect(
      computeDepositVerification(
        { ...basePrivateState, depositNonce: differentNonce },
        realHeldCommitment(DEPOSIT_NONCE)
      )
    ).toBe(false);
  });

  it('throws a clear error when deposit params are missing (nothing to verify yet) rather than failing silently', () => {
    expect(() => computeDepositVerification(emptyEscrowPrivateState, realHeldCommitment(DEPOSIT_NONCE))).toThrow(
      /No prior propose/
    );
  });
});
