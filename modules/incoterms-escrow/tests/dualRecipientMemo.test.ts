import { describe, it, expect } from 'vitest';
import {
  generateX25519KeyPair,
  encryptDualRecipientMemo,
  decryptDualRecipientMemo,
} from '@ublp/shared';

describe('dual-recipient encrypted memo', () => {
  const buyer = generateX25519KeyPair();
  const seller = generateX25519KeyPair();
  const payload = Buffer.from(JSON.stringify({ nonce: 'abc', color: 'def', value: '1000000', salt: 'xyz' }));

  it('the counterparty can decrypt what the sender encrypted', () => {
    const memo = encryptDualRecipientMemo(payload, buyer.privateKey, seller.publicKey);
    const recovered = decryptDualRecipientMemo(memo, seller.privateKey, buyer.publicKey);
    expect(recovered.equals(payload)).toBe(true);
  });

  it('the sender can self-recover the same memo (loss-recovery case)', () => {
    const memo = encryptDualRecipientMemo(payload, buyer.privateKey, seller.publicKey);
    const recovered = decryptDualRecipientMemo(memo, buyer.privateKey, seller.publicKey);
    expect(recovered.equals(payload)).toBe(true);
  });

  it('a third party cannot decrypt the memo', () => {
    const mallory = generateX25519KeyPair();
    const memo = encryptDualRecipientMemo(payload, buyer.privateKey, seller.publicKey);
    expect(() => decryptDualRecipientMemo(memo, mallory.privateKey, buyer.publicKey)).toThrow();
  });

  it('each memo uses a fresh nonce, so encrypting the same payload twice differs', () => {
    const memoA = encryptDualRecipientMemo(payload, buyer.privateKey, seller.publicKey);
    const memoB = encryptDualRecipientMemo(payload, buyer.privateKey, seller.publicKey);
    expect(memoA).not.toBe(memoB);
  });

  it('starts with the 0x01 scheme byte', () => {
    const memo = encryptDualRecipientMemo(payload, buyer.privateKey, seller.publicKey);
    expect(memo.startsWith('01')).toBe(true);
  });

  it('rejects a memo with an unknown scheme byte', () => {
    const memo = encryptDualRecipientMemo(payload, buyer.privateKey, seller.publicKey);
    const tampered = 'ff' + memo.slice(2);
    expect(() => decryptDualRecipientMemo(tampered, seller.privateKey, buyer.publicKey)).toThrow(
      /Unsupported dual-recipient memo scheme/
    );
  });

  it('rejects a tampered ciphertext (AEAD tag mismatch)', () => {
    const memo = encryptDualRecipientMemo(payload, buyer.privateKey, seller.publicKey);
    const tamperedByte = ((parseInt(memo.slice(-2), 16) ^ 0xff) & 0xff).toString(16).padStart(2, '0');
    const tampered = memo.slice(0, -2) + tamperedByte;
    expect(() => decryptDualRecipientMemo(tampered, seller.privateKey, buyer.publicKey)).toThrow();
  });
});
