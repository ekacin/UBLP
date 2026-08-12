import { describe, it, expect } from 'vitest';
import { generateKeyPair } from '@ublp/shared';
import type { UBLPDid, ShipmentId } from '@ublp/shared';
import { proposeEscrow, verifyProposal, acceptEscrow, type EscrowTerms } from '../src/escrow';

const seller = generateKeyPair();
const attacker = generateKeyPair();

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
    deadlineTimestamp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
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
