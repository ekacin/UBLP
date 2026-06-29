import { describe, it, expect } from 'vitest';
import { pubKeyPemToRaw } from '../../shared/src/crypto/sp1Client';
import { generateKeyPair } from '../../shared/src/crypto/mockCrypto';

describe('pubKeyPemToRaw', () => {
  it('converts PEM SPKI to 65-byte uncompressed SEC1', () => {
    const kp = generateKeyPair();
    const raw = pubKeyPemToRaw(kp.publicKey);
    expect(raw).toBeInstanceOf(Buffer);
    expect(raw.length).toBe(65);
    expect(raw[0]).toBe(0x04);
  });

  it('produces consistent output for same key', () => {
    const kp = generateKeyPair();
    const raw1 = pubKeyPemToRaw(kp.publicKey);
    const raw2 = pubKeyPemToRaw(kp.publicKey);
    expect(raw1.equals(raw2)).toBe(true);
  });

  it('produces different output for different keys', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();
    const raw1 = pubKeyPemToRaw(kp1.publicKey);
    const raw2 = pubKeyPemToRaw(kp2.publicKey);
    expect(raw1.equals(raw2)).toBe(false);
  });
});

describe('sp1Available', () => {
  it('returns false when SP1 env is not set', async () => {
    const { sp1Available } = await import('../../shared/src/crypto/sp1Client');
    expect(sp1Available()).toBe(false);
  });
});
