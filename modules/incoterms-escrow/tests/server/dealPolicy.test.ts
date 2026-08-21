import { describe, it, expect } from 'vitest';
import { shouldAutoClaimDeal, shouldAutoReleaseTimeout } from '../../src/server/dealPolicy.js';
import type { DealStatus } from '../../src/server/actions.js';

const LOCKED = 2;
const RELEASED = 3;

function baseStatus(overrides: Partial<DealStatus> = {}): DealStatus {
  return {
    contractAddress: '0xdeal',
    state: LOCKED,
    loadingConfirmed: false,
    deadlineTimestamp: 1_000_000,
    timeoutDirection: 'buyer',
    ...overrides,
  };
}

describe('shouldAutoClaimDeal', () => {
  it('is true for the seller once C has attested on a Locked deal', () => {
    expect(shouldAutoClaimDeal('seller', baseStatus({ loadingConfirmed: true }))).toBe(true);
  });

  it('is false for the buyer or port-authority, even with a valid attestation', () => {
    expect(shouldAutoClaimDeal('buyer', baseStatus({ loadingConfirmed: true }))).toBe(false);
    expect(shouldAutoClaimDeal('port-authority', baseStatus({ loadingConfirmed: true }))).toBe(false);
  });

  it('is false before C has attested', () => {
    expect(shouldAutoClaimDeal('seller', baseStatus({ loadingConfirmed: false }))).toBe(false);
  });

  it('is false once the deal has already moved past Locked (already Released)', () => {
    expect(shouldAutoClaimDeal('seller', baseStatus({ loadingConfirmed: true, state: RELEASED }))).toBe(false);
  });
});

describe('shouldAutoReleaseTimeout', () => {
  const now = 2_000_000;

  it('is true for the buyer once the deadline has passed on an unattested Locked deal', () => {
    expect(shouldAutoReleaseTimeout('buyer', baseStatus({ deadlineTimestamp: now - 1 }), now)).toBe(true);
  });

  it('is true exactly at the deadline second (>=, not >)', () => {
    expect(shouldAutoReleaseTimeout('buyer', baseStatus({ deadlineTimestamp: now }), now)).toBe(true);
  });

  it('is false before the deadline', () => {
    expect(shouldAutoReleaseTimeout('buyer', baseStatus({ deadlineTimestamp: now + 1 }), now)).toBe(false);
  });

  it('is false for the seller or port-authority — releaseTimeoutDeal only implements the buyer path', () => {
    const status = baseStatus({ deadlineTimestamp: now - 1 });
    expect(shouldAutoReleaseTimeout('seller', status, now)).toBe(false);
    expect(shouldAutoReleaseTimeout('port-authority', status, now)).toBe(false);
  });

  it('is false once C has already attested, even past the deadline (claim should win, not refund)', () => {
    expect(
      shouldAutoReleaseTimeout('buyer', baseStatus({ deadlineTimestamp: now - 1, loadingConfirmed: true }), now)
    ).toBe(false);
  });

  it('is false when timeoutDirection is seller — that branch is not implemented, never attempt it', () => {
    expect(
      shouldAutoReleaseTimeout('buyer', baseStatus({ deadlineTimestamp: now - 1, timeoutDirection: 'seller' }), now)
    ).toBe(false);
  });

  it('is false once the deal has already moved past Locked (already Released)', () => {
    expect(
      shouldAutoReleaseTimeout('buyer', baseStatus({ deadlineTimestamp: now - 1, state: RELEASED }), now)
    ).toBe(false);
  });
});
