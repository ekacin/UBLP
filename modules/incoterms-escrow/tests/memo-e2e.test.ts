import { describe, it, expect } from 'vitest';
import type { WitnessContext } from '@midnight-ntwrk/compact-runtime';
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
import {
  escrowWitnesses,
  zswapRecipient,
  type EscrowPrivateState,
} from '../src/contract/witnesses';
import { recoverBuyerMemo, recoverSellerMemo, recoverBuyerAddressMemo } from '../src/contract/memo';

function contextWith(privateState: EscrowPrivateState): WitnessContext<unknown, EscrowPrivateState> {
  return { ledger: {}, privateState, contractAddress: {} as never };
}

/**
 * The full loop this closes (AGENTS.md 5.18): neither side ever exchanges coin/address
 * data directly — each memo is encrypted on-chain during propose/lockEscrow, using
 * counterparty keys resolved from the SAME agreed `terms` object (no separate channel),
 * and either side can recover either memo later using nothing but their own private key.
 */
describe('dual-recipient memo — end to end (terms -> propose/lockEscrow witnesses -> recovery)', () => {
  it('seller and buyer each recover the OTHER side\'s memo using only their own private key', () => {
    const sellerAuth = generateKeyPair();
    const sellerMemo = generateX25519KeyPair();
    const buyerMemo = generateX25519KeyPair();

    const SELLER_DID: UBLPDid = 'did:ublp:seller:acme-export';
    const BUYER_DID: UBLPDid = 'did:ublp:buyer:acme-import';
    const PORT_AUTHORITY: UBLPDid = 'did:ublp:port-authority:pendik-roro';

    const terms: EscrowTerms = {
      shipmentId: `shp:${crypto.randomUUID()}` as ShipmentId,
      sellerDid: SELLER_DID,
      buyerDid: BUYER_DID,
      portAuthorityDid: PORT_AUTHORITY,
      incoterm: 'FOB',
      amount: '1000000',
      amountSalt: Buffer.from(new Uint8Array(32).fill(3)).toString('hex'),
      deadlineTimestamp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
      timeoutDirection: 'buyer',
      sellerMemoPublicKey: sellerMemo.publicKey,
      buyerMemoPublicKey: buyerMemo.publicKey,
    };

    // Step 1: seller creates the offer (Section 5.12 step 1), buyer verifies + accepts.
    const proposal = proposeEscrow(terms, sellerAuth.privateKey, sellerAuth.publicKey);
    expect(verifyProposal(proposal)).toBe(true);
    const accepted = acceptEscrow(proposal, BUYER_DID);
    expect(accepted.status).toBe('accepted');

    // Step 2: seller's own agent builds its EscrowPrivateState and calls the `propose`
    // circuit — sellerEncryptedMemo witness fires, encrypting address+salt for the buyer.
    const sellerAddressSalt = new Uint8Array(32).fill(9);
    const sellerAddress = zswapRecipient(new Uint8Array(32).fill(8));
    const sellerState: EscrowPrivateState = {
      sellerSecretKey: new Uint8Array(32).fill(1),
      portAuthoritySecretKey: null,
      sellerAddress,
      sellerAddressSalt,
      buyerAddress: null,
      buyerAddressSalt: null,
      depositedCoin: null,
      depositSalt: null,
      qualifiedCoin: null,
      agreedAmount: BigInt(accepted.proposal.terms.amount),
      agreedAmountSalt: hexToBytes(accepted.proposal.terms.amountSalt),
      ...sellerMemoKeys(accepted.proposal.terms, hexToBytes(sellerMemo.privateKey)),
    };
    const [, sellerMemoCiphertext] = escrowWitnesses.sellerEncryptedMemo(contextWith(sellerState));
    const [, proposeAmount] = escrowWitnesses.agreedAmount(contextWith(sellerState));
    const [, proposeAmountSalt] = escrowWitnesses.agreedAmountSalt(contextWith(sellerState));

    // Step 3: buyer's own agent builds ITS EscrowPrivateState and calls `lockEscrow` —
    // buyerEncryptedMemo witness fires, encrypting coin+salt for the seller.
    const depositSalt = new Uint8Array(32).fill(5);
    const depositedCoin = { nonce: new Uint8Array(32).fill(6), color: new Uint8Array(32).fill(7), value: 1_000_000n };
    const buyerAddressSalt = new Uint8Array(32).fill(13);
    const buyerAddress = zswapRecipient(new Uint8Array(32).fill(14));
    const buyerState: EscrowPrivateState = {
      sellerSecretKey: null,
      portAuthoritySecretKey: null,
      sellerAddress: null,
      sellerAddressSalt: null,
      buyerAddress,
      buyerAddressSalt,
      depositedCoin,
      depositSalt,
      qualifiedCoin: null,
      agreedAmount: BigInt(accepted.proposal.terms.amount),
      agreedAmountSalt: hexToBytes(accepted.proposal.terms.amountSalt),
      ...buyerMemoKeys(accepted.proposal.terms, hexToBytes(buyerMemo.privateKey)),
    };
    const [, buyerMemoCiphertext] = escrowWitnesses.buyerEncryptedMemo(contextWith(buyerState));
    // Section 5.19 — buyer's own refund-address memo, populated at lockEscrow alongside the
    // coin memo above (separate ledger field, same reasoning as sellerMemo).
    const [, buyerAddressMemoCiphertext] = escrowWitnesses.buyerAddressEncryptedMemo(contextWith(buyerState));

    // The amount-equality fix (AGENTS.md): buyer independently re-derives the SAME agreed
    // amount+salt seller committed to at propose time, from the same terms — and the coin
    // buyer actually locks must equal it. No separate exchange, same principle as the memo
    // keys above.
    const [, lockAmount] = escrowWitnesses.lockedAmount(contextWith(buyerState));
    const [, lockAmountSalt] = escrowWitnesses.lockedAmountSalt(contextWith(buyerState));
    expect(lockAmount).toBe(proposeAmount);
    expect(lockAmountSalt).toEqual(proposeAmountSalt);
    expect(depositedCoin.value).toBe(lockAmount);

    // Step 4: these ciphertexts are what actually lands in the sellerMemo/buyerMemo ledger
    // fields on-chain. Anyone reading them off-chain later only needs their own private key
    // plus the counterparty's public key (already known from `terms`) to recover the data.

    // Buyer recovers what the SELLER encrypted (the seller's payout address+salt).
    const recoveredForBuyer = recoverSellerMemo(
      sellerMemoCiphertext,
      hexToBytes(buyerMemo.privateKey),
      hexToBytes(sellerMemo.publicKey)
    );
    expect(recoveredForBuyer.address).toEqual(sellerAddress);
    expect(recoveredForBuyer.addressSalt).toEqual(sellerAddressSalt);

    // Seller recovers what the BUYER encrypted (the locked coin + deposit salt).
    const recoveredForSeller = recoverBuyerMemo(
      buyerMemoCiphertext,
      hexToBytes(sellerMemo.privateKey),
      hexToBytes(buyerMemo.publicKey)
    );
    expect(recoveredForSeller.coin).toEqual(depositedCoin);
    expect(recoveredForSeller.depositSalt).toEqual(depositSalt);

    // Loss-recovery case: the AUTHOR of a memo can also recover their own data straight off
    // the chain, with no dependency on the counterparty at all (AGENTS.md 5.18's whole point).
    const sellerSelfRecovery = recoverSellerMemo(
      sellerMemoCiphertext,
      hexToBytes(sellerMemo.privateKey),
      hexToBytes(buyerMemo.publicKey)
    );
    expect(sellerSelfRecovery.addressSalt).toEqual(sellerAddressSalt);

    const buyerSelfRecovery = recoverBuyerMemo(
      buyerMemoCiphertext,
      hexToBytes(buyerMemo.privateKey),
      hexToBytes(sellerMemo.publicKey)
    );
    expect(buyerSelfRecovery.depositSalt).toEqual(depositSalt);

    // Section 5.19 — seller recovers buyer's refund address+salt (needed if releaseOnTimeout
    // ever has to pay the buyer back), same dual-recipient guarantee as everything else.
    const buyerAddressForSeller = recoverBuyerAddressMemo(
      buyerAddressMemoCiphertext,
      hexToBytes(sellerMemo.privateKey),
      hexToBytes(buyerMemo.publicKey)
    );
    expect(buyerAddressForSeller.address).toEqual(buyerAddress);
    expect(buyerAddressForSeller.addressSalt).toEqual(buyerAddressSalt);
  });
});

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}
