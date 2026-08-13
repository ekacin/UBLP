import { describe, it, expect } from 'vitest';
import { generateKeyPair, generateX25519KeyPair } from '@ublp/shared';
import type { UBLPDid, ShipmentId } from '@ublp/shared';
import {
  proposeEscrow,
  verifyProposal,
  acceptEscrow,
  sellerMemoKeys,
  buyerMemoKeys,
  type EscrowTerms,
} from '../src/escrow';

const seller = generateKeyPair();
const attacker = generateKeyPair();
const sellerMemo = generateX25519KeyPair();
const buyerMemo = generateX25519KeyPair();

const SELLER_DID: UBLPDid = 'did:ublp:seller:acme-export';
const BUYER_DID: UBLPDid = 'did:ublp:buyer:acme-import';
const PORT_AUTHORITY: UBLPDid = 'did:ublp:port-authority:pendik-roro';

function baseTerms(): EscrowTerms {
  const shipmentId: ShipmentId = `shp:${crypto.randomUUID()}`;
  return {
    shipmentId,
    sellerDid: SELLER_DID,
    buyerDid: BUYER_DID,
    portAuthorityDid: PORT_AUTHORITY,
    incoterm: 'FOB',
    amount: '1000000',
    amountSalt: Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('hex'),
    deadlineTimestamp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
    timeoutDirection: 'buyer',
    sellerMemoPublicKey: sellerMemo.publicKey,
    buyerMemoPublicKey: buyerMemo.publicKey,
  };
}

describe('proposeEscrow / verifyProposal', () => {
  it('produces a proposal whose signature verifies', () => {
    const proposal = proposeEscrow(baseTerms(), seller.privateKey, seller.publicKey);
    expect(verifyProposal(proposal)).toBe(true);
  });

  it('fails verification if the terms are tampered with after signing', () => {
    const proposal = proposeEscrow(baseTerms(), seller.privateKey, seller.publicKey);
    const tampered = { ...proposal, terms: { ...proposal.terms, amount: '999999999' } };
    expect(verifyProposal(tampered)).toBe(false);
  });

  it('fails verification if signed by a key other than the claimed sellerPublicKey', () => {
    const proposal = proposeEscrow(baseTerms(), attacker.privateKey, seller.publicKey);
    expect(verifyProposal(proposal)).toBe(false);
  });
});

describe('acceptEscrow', () => {
  it('accepts a validly-signed proposal for the designated buyer', () => {
    const proposal = proposeEscrow(baseTerms(), seller.privateKey, seller.publicKey);
    const state = acceptEscrow(proposal, BUYER_DID);
    expect(state.status).toBe('accepted');
  });

  it('rejects a proposal not addressed to this buyer', () => {
    const proposal = proposeEscrow(baseTerms(), seller.privateKey, seller.publicKey);
    const impostorBuyer: UBLPDid = 'did:ublp:buyer:someone-else';
    expect(() => acceptEscrow(proposal, impostorBuyer)).toThrow();
  });

  it('rejects a proposal with an invalid seller signature', () => {
    const proposal = proposeEscrow(baseTerms(), attacker.privateKey, seller.publicKey);
    expect(() => acceptEscrow(proposal, BUYER_DID)).toThrow();
  });

  it('rejects a non-positive amount', () => {
    const proposal = proposeEscrow({ ...baseTerms(), amount: '0' }, seller.privateKey, seller.publicKey);
    expect(() => acceptEscrow(proposal, BUYER_DID)).toThrow();
  });
});

describe('sellerMemoKeys / buyerMemoKeys', () => {
  it('each side resolves the counterparty key from the same agreed terms, no separate exchange', () => {
    const terms = baseTerms();
    const sellerKeys = sellerMemoKeys(terms, hexToBytes(sellerMemo.privateKey));
    const buyerKeys = buyerMemoKeys(terms, hexToBytes(buyerMemo.privateKey));

    expect(sellerKeys.counterpartyMemoPublicKey).toEqual(hexToBytes(buyerMemo.publicKey));
    expect(buyerKeys.counterpartyMemoPublicKey).toEqual(hexToBytes(sellerMemo.publicKey));
  });

  it('tampering with a memo public key in terms breaks the seller signature', () => {
    const proposal = proposeEscrow(baseTerms(), seller.privateKey, seller.publicKey);
    const tampered = {
      ...proposal,
      terms: { ...proposal.terms, buyerMemoPublicKey: generateX25519KeyPair().publicKey },
    };
    expect(verifyProposal(tampered)).toBe(false);
  });
});

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}
