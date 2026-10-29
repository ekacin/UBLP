import { describe, it, expect } from 'vitest';
import { computeHeldCommitment } from '../src/contract/coinCommitment.js';

const NONCE = new Uint8Array(32).fill(1);
const COLOR = new Uint8Array(32).fill(2);
const VALUE = 1_000_000n;
const SALT = new Uint8Array(32).fill(3);

describe('computeHeldCommitment (AGENTS.md 5.36 Fix B — TS mirror of persistentCommit<CoinCore>)', () => {
  it('is deterministic and produces a 32-byte hash', () => {
    const a = computeHeldCommitment({ nonce: NONCE, color: COLOR, value: VALUE }, SALT);
    const b = computeHeldCommitment({ nonce: NONCE, color: COLOR, value: VALUE }, SALT);
    expect(a.length).toBe(32);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });

  it('changes if the nonce changes', () => {
    const a = computeHeldCommitment({ nonce: NONCE, color: COLOR, value: VALUE }, SALT);
    const differentNonce = new Uint8Array(32).fill(9);
    const b = computeHeldCommitment({ nonce: differentNonce, color: COLOR, value: VALUE }, SALT);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it('changes if the color changes', () => {
    const a = computeHeldCommitment({ nonce: NONCE, color: COLOR, value: VALUE }, SALT);
    const differentColor = new Uint8Array(32).fill(9);
    const b = computeHeldCommitment({ nonce: NONCE, color: differentColor, value: VALUE }, SALT);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it('changes if the value changes', () => {
    const a = computeHeldCommitment({ nonce: NONCE, color: COLOR, value: VALUE }, SALT);
    const b = computeHeldCommitment({ nonce: NONCE, color: COLOR, value: VALUE + 1n }, SALT);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it('changes if the salt (opening) changes', () => {
    const a = computeHeldCommitment({ nonce: NONCE, color: COLOR, value: VALUE }, SALT);
    const differentSalt = new Uint8Array(32).fill(9);
    const b = computeHeldCommitment({ nonce: NONCE, color: COLOR, value: VALUE }, differentSalt);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});
