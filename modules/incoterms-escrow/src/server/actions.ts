/**
 * Settlement-agent write path — one function per circuit, each following the exact pattern
 * already proven against real local devnet in scripts/devnet/full-lifecycle.ts and
 * timeout-lifecycle.ts (deploy/findDeployedContract -> set private state -> callTx.xxx()).
 * Nothing here reinvents wallet/proving/submission — it wraps the same building blocks
 * (buildAgentWallet, buildEscrowProviders, compiledEscrowContract) an HTTP layer around them.
 *
 * AGENTS.md 5.29's three rules apply throughout:
 *   (a) the proof server this agent's providers point at must stay same-host/private network
 *       (enforced today simply by NetworkConfig only ever wiring an `undeployed`/localhost
 *       proof server — see deploy/networks.ts);
 *   (b) mt_index is looked up cache-first (server/db.ts's mt_index_cache) before falling back
 *       to the real indexer scan (contract/mtIndex.ts);
 *   (c) callers are expected to have already gone through server/db.ts's pending-action
 *       in-flight check before invoking these — that check lives in routes.ts, not here, so
 *       these functions stay simple "do the chain call" primitives.
 */

import crypto from 'crypto';
import { deployContract, findDeployedContract } from '@midnight-ntwrk/midnight-js-contracts';
import {
  createShieldedCoinInfo,
  shieldedToken,
  encodeShieldedCoinInfo,
} from '@midnight-ntwrk/midnight-js-protocol/ledger';
import {
  openTransactionLog,
  logTransaction,
  queryTransactions,
  isUBLPDid,
  encryptDualRecipientMemo,
  decryptDualRecipientMemo,
  type TransactionLogDb,
  type UBLPDid,
} from '@ublp/shared';
import { ledger, TimeoutDirection } from '../../contracts/managed/escrow/contract/index.js';
import {
  compiledEscrowContract,
  EscrowPrivateStateId,
  emptyEscrowPrivateState,
  zswapRecipient,
  type EscrowPrivateState,
} from '../contract/index.js';
import { recoverBuyerMemo } from '../contract/memo.js';
import { roleKeyHash } from '../contract/roleKeyHash.js';
import { findContractCoinMtIndex, waitForContractCoinMtIndex } from '../contract/mtIndex.js';
import type { AgentWallet, AgentRole } from '../deploy/wallet.js';
import { buildEscrowProviders } from '../deploy/providers.js';
import type { NetworkConfig } from '../deploy/networks.js';
import type { SettlementIdentity } from './identity.js';
import { proposeEscrow, acceptEscrow, type EscrowTerms, type EscrowProposal } from '../escrow.js';
import {
  type SettlementDb,
  type IncomingOffer,
  getCachedMtIndex,
  setCachedMtIndex,
  saveDealPrivateState,
  loadDealPrivateState,
  createIncomingOffer,
} from './db.js';

export interface AgentContext {
  role: AgentRole;
  /** This company's own DID, e.g. `did:ublp:buyer:acme-import` — operator-configured at boot
   * (a human-chosen label, not something derivable from a key). Needed so lockDeal can check
   * an incoming EscrowProposal was actually addressed to THIS company (acceptEscrow), not
   * some other buyer's offer replayed or misdirected here. */
  did: UBLPDid;
  network: NetworkConfig;
  wallet: AgentWallet;
  providers: ReturnType<typeof buildEscrowProviders>;
  identity: SettlementIdentity;
  db: SettlementDb;
  txLog: TransactionLogDb;
  /** Per-project-memory plan: rate limiting on the unauthenticated `/deals/incoming` write
   * endpoint must be customizable, not a hardcoded constant — see index.ts for the env-var-
   * driven default. `timeWindow` matches @fastify/rate-limit's own accepted format
   * (milliseconds, or a string like '1 minute'). */
  incomingOfferRateLimit: { max: number; timeWindow: string | number };
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function randomBytes32(): Uint8Array {
  return new Uint8Array(crypto.randomBytes(32));
}

function logAction(
  ctx: AgentContext,
  dealRef: string,
  action: string,
  fields: { counterparty?: string; amount?: string; currency?: string; txId?: string; metadata?: Record<string, unknown> } = {}
): void {
  logTransaction(ctx.txLog, { module: 'incoterms-escrow', dealRef, action, ...fields });
}

/** Cache-first `mt_index` lookup — AGENTS.md 5.29(b). Only falls back to the expensive real
 * indexer scan if nothing's cached yet, then remembers the result for next time. */
async function resolveMtIndex(ctx: AgentContext, contractAddress: string, coinDescriptor: string): Promise<bigint> {
  const cached = getCachedMtIndex(ctx.db, contractAddress, coinDescriptor);
  if (cached !== null) return cached;
  const found = (await findContractCoinMtIndex(ctx.network.indexer, contractAddress)) ??
    (await waitForContractCoinMtIndex(ctx.network.indexer, contractAddress));
  setCachedMtIndex(ctx.db, contractAddress, coinDescriptor, found);
  return found;
}

// ---- propose (seller only) ----

const DEFAULT_DURATION_SECONDS = 7 * 24 * 60 * 60; // AGENTS.md 7.2's suggested default (7 days)

/**
 * Business terms the seller's operator provides. Two fields notably NOT here:
 * `amountSalt` (generated fresh, server-side — never client input, see proposeDeal) and
 * `sellerMemoPublicKey` (derived from this agent's own identity, not asked for).
 * `portAuthorityKeyHashHex`/`buyerMemoPublicKeyHex` ARE still loose inputs — that's fine,
 * they're public commitments C/buyer made themselves (like exchanging public keys), tampering
 * with them in transit is self-defeating (breaks a hash-check or breaks buyer's own memo
 * decryption), not exploitable the way an unsigned amount/salt would be.
 */
export interface ProposeDealParams {
  shipmentId: string;
  buyerDid: string;
  portAuthorityDid: string;
  portAuthorityKeyHashHex: string;
  buyerMemoPublicKeyHex: string;
  incoterm: EscrowTerms['incoterm'];
  agreedAmount: string; // integer string, smallest unit
  durationSeconds?: number;
  timeoutDirection?: 'buyer' | 'seller';
  /** The buyer's own agent base URL, if the operator already had it (e.g. from the same Fetch
   * step used for `buyerMemoPublicKeyHex`) — lets the approve step attempt automatic,
   * encrypted delivery (see `tryDeliverOfferToBuyer`) instead of relying purely on the
   * operator manually copying the signed-offer card to the buyer out-of-band. Optional: the
   * manual path stays fully functional if this is left unset. */
  buyerAgentUrl?: string;
}

export interface ProposeDealResult {
  contractAddress: string;
  txId: string;
  /**
   * The signed, portable offer (AGENTS.md 5.12/5.30's fix) — hand this whole blob to the
   * buyer via whatever out-of-band channel the two companies already use (email, EDI,
   * whatever). Unlike loose hex fields, this is self-verifying: buyer's lockDeal calls
   * acceptEscrow() on it before touching the chain, so a channel that tampers with (or
   * forges) the terms is caught, not silently trusted. See the "two separate companies on
   * two separate networks" constraint this was built against — nothing here assumes the
   * seller and buyer agents can reach each other directly.
   */
  proposal: EscrowProposal;
}

export async function proposeDeal(ctx: AgentContext, params: ProposeDealParams): Promise<ProposeDealResult> {
  if (ctx.role !== 'seller') throw new Error('propose() is only callable by the seller role.');
  if (!ctx.identity.roleSecretKeyHex) throw new Error('Seller identity is missing its role secret key.');
  if (!isUBLPDid(params.buyerDid) || !isUBLPDid(params.portAuthorityDid)) {
    throw new Error('buyerDid/portAuthorityDid must be valid did:ublp:... identifiers.');
  }

  const deployed = await deployContract(ctx.providers, {
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: emptyEscrowPrivateState,
  });
  const contractAddress = deployed.deployTxData.public.contractAddress;

  const sellerAddressSalt = randomBytes32();
  const amountSaltBytes = randomBytes32();
  const durationSeconds = params.durationSeconds ?? DEFAULT_DURATION_SECONDS;
  const timeoutDirection = params.timeoutDirection ?? 'buyer';

  const terms: EscrowTerms = {
    shipmentId: `shp:${params.shipmentId}`,
    sellerDid: ctx.did,
    buyerDid: params.buyerDid,
    portAuthorityDid: params.portAuthorityDid,
    portAuthorityKeyHashHex: params.portAuthorityKeyHashHex,
    incoterm: params.incoterm,
    amount: params.agreedAmount,
    amountSalt: Buffer.from(amountSaltBytes).toString('hex'),
    durationSeconds,
    timeoutDirection,
    sellerMemoPublicKey: ctx.identity.memoKeyPair.publicKey,
    buyerMemoPublicKey: params.buyerMemoPublicKeyHex,
  };
  // The actual security fix: seller signs the exact terms it's about to submit on-chain, with
  // a key dedicated to this purpose (identity.ts's dealSigningKeyPair, separate from login).
  // A channel that alters anything in `terms` in transit invalidates this signature — buyer's
  // lockDeal checks it before ever deriving witness data from it.
  const proposal = proposeEscrow(terms, ctx.identity.dealSigningKeyPair.privateKey, ctx.identity.dealSigningKeyPair.publicKey);

  const privateState: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    sellerSecretKey: hexToBytes(ctx.identity.roleSecretKeyHex),
    sellerAddress: zswapRecipient(hexToBytes(ctx.wallet.midnightWalletProvider.getCoinPublicKey())),
    sellerAddressSalt,
    ownMemoPrivateKey: hexToBytes(ctx.identity.memoKeyPair.privateKey),
    counterpartyMemoPublicKey: hexToBytes(params.buyerMemoPublicKeyHex),
    agreedAmount: BigInt(params.agreedAmount),
    agreedAmountSalt: amountSaltBytes,
  };
  await ctx.providers.privateStateProvider.set(EscrowPrivateStateId, privateState);
  saveDealPrivateState(ctx.db, contractAddress, privateState);

  const result = await deployed.callTx.propose(
    hexToBytes(params.portAuthorityKeyHashHex),
    BigInt(durationSeconds),
    timeoutDirection === 'buyer' ? TimeoutDirection.Buyer : TimeoutDirection.Seller
  );

  logAction(ctx, contractAddress, 'propose', {
    amount: params.agreedAmount,
    currency: 'NIGHT',
    txId: result.public.txId,
    metadata: { durationSeconds, timeoutDirection, buyerDid: params.buyerDid },
  });

  return { contractAddress, txId: result.public.txId, proposal };
}

// ---- lockEscrow (buyer only) ----

// ---- agent-to-agent proposal delivery — encrypted, no central relay (see project memory
// "agent-to-agent delivery plan": encryption is not a fast-follow, it ships with delivery) ----

export interface IncomingOfferEnvelope {
  senderMemoPublicKeyHex: string;
  ciphertextHex: string;
}

/**
 * Encrypts a just-approved propose's (contractAddress, proposal) pair for direct delivery to
 * the buyer's own agent. Reuses the X25519 dual-recipient scheme already built for the
 * on-chain memo (AGENTS.md 5.18's dualRecipientMemo.ts) — its ECDH+ChaCha20-Poly1305
 * primitive is payload-size agnostic, only the on-chain memo's fixed 141/126-byte layout is
 * chain-specific, not the encryption itself, so it applies unchanged to this larger JSON blob.
 *
 * Encrypting this is not optional: `EscrowTerms` carries the deal amount and every party's
 * DID in plaintext — exactly what the on-chain shielded-commitment/attestation design exists
 * to hide. An unencrypted copy of this JSON (sitting in an email, a chat log, or an
 * unauthenticated HTTP request body) defeats that the moment it's captured in transit or at
 * rest on either agent's disk/logs.
 */
export function encryptOfferForBuyer(
  ctx: AgentContext,
  contractAddress: string,
  proposal: EscrowProposal,
  buyerMemoPublicKeyHex: string
): IncomingOfferEnvelope {
  const plaintext = Buffer.from(JSON.stringify({ contractAddress, proposal }), 'utf8');
  const ciphertextHex = encryptDualRecipientMemo(plaintext, ctx.identity.memoKeyPair.privateKey, buyerMemoPublicKeyHex);
  return { senderMemoPublicKeyHex: ctx.identity.memoKeyPair.publicKey, ciphertextHex };
}

/**
 * Buyer side — decrypts, then runs the exact same `acceptEscrow` check the manual
 * copy-paste Lock form always required (signature + addressed-to-me). The inbound HTTP route
 * this feeds (routes.ts's `/deals/incoming`) is necessarily unauthenticated — the sender is a
 * different company with no session on this agent — so this verification IS the entire trust
 * boundary here: reject and never persist on any failure, same as today's manual flow already
 * does at lockEscrow time, just moved earlier (at receipt, not at lock).
 */
export function receiveOffer(ctx: AgentContext, envelope: IncomingOfferEnvelope): IncomingOffer {
  if (ctx.role !== 'buyer') throw new Error('Only a buyer-role agent can receive incoming offers.');
  const plaintext = decryptDualRecipientMemo(
    envelope.ciphertextHex,
    ctx.identity.memoKeyPair.privateKey,
    envelope.senderMemoPublicKeyHex
  );
  const parsed = JSON.parse(plaintext.toString('utf8')) as { contractAddress: string; proposal: EscrowProposal };
  if (!parsed.contractAddress || !parsed.proposal?.terms || !parsed.proposal?.sellerSignature) {
    throw new Error('Malformed incoming offer payload.');
  }
  acceptEscrow(parsed.proposal, ctx.did); // throws on invalid signature / wrong buyer / non-positive amount
  return createIncomingOffer(ctx.db, {
    contractAddress: parsed.contractAddress,
    proposal: parsed.proposal as unknown as Record<string, unknown>,
    senderMemoPublicKeyHex: envelope.senderMemoPublicKeyHex,
  });
}

/**
 * Best-effort push, right after a propose is approved — if `buyerAgentUrl` wasn't supplied
 * (an operator who skipped the Fetch step, or an older client) or the buyer's agent is
 * unreachable, this fails silently and PendingQueue's "Signed offer" copy/paste card remains
 * the fallback. A delivery failure must never fail the approve itself — the propose is
 * already confirmed on-chain by the time this runs.
 */
export async function tryDeliverOfferToBuyer(
  ctx: AgentContext,
  buyerAgentUrl: string | undefined,
  contractAddress: string,
  proposal: EscrowProposal,
  buyerMemoPublicKeyHex: string
): Promise<boolean> {
  if (!buyerAgentUrl) return false;
  try {
    const envelope = encryptOfferForBuyer(ctx, contractAddress, proposal, buyerMemoPublicKeyHex);
    const res = await fetch(`${buyerAgentUrl.replace(/\/$/, '')}/deals/incoming`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(envelope),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export interface LockDealParams {
  contractAddress: string;
  /** The exact signed offer the seller handed over (ProposeDealResult.proposal) — not loose
   * fields. See lockDeal: this gets cryptographically verified before anything else happens. */
  proposal: EscrowProposal;
}

export async function lockDeal(ctx: AgentContext, params: LockDealParams): Promise<{ txId: string }> {
  if (ctx.role !== 'buyer') throw new Error('lockEscrow() is only callable by the buyer role.');

  // The actual security boundary (this is *why* ProposeDealResult hands back a signed blob
  // instead of loose hex fields): acceptEscrow verifies the seller's signature over the exact
  // terms AND that they're addressed to this buyer's own DID. A channel that tampered with the
  // amount/salt/memo keys in transit — or handed this buyer an offer meant for someone else —
  // is rejected right here, before any witness data is derived or the chain is ever touched.
  // This is deliberately checked assuming seller and buyer are two unrelated agents on two
  // unrelated networks with no shared trust beyond this signature — not "we're both on the
  // same machine so I can just trust the data".
  acceptEscrow(params.proposal, ctx.did);
  const terms = params.proposal.terms;

  const amount = BigInt(terms.amount);
  const depositSalt = randomBytes32();
  const buyerAddressSalt = randomBytes32();
  const depositedCoinSdk = createShieldedCoinInfo(shieldedToken().raw, amount);
  // Same `as any` the proven devnet scripts use (full-lifecycle.ts, timeout-lifecycle.ts) —
  // encodeShieldedCoinInfo's declared return type doesn't match its actual runtime shape here.
  const depositedCoinEncoded = encodeShieldedCoinInfo(depositedCoinSdk) as any;

  const privateState: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    depositedCoin: {
      nonce: hexToBytes(depositedCoinEncoded.nonce ?? depositedCoinSdk.nonce),
      color: hexToBytes(depositedCoinEncoded.color),
      value: amount,
    },
    depositSalt,
    buyerAddress: zswapRecipient(hexToBytes(ctx.wallet.midnightWalletProvider.getCoinPublicKey())),
    buyerAddressSalt,
    ownMemoPrivateKey: hexToBytes(ctx.identity.memoKeyPair.privateKey),
    counterpartyMemoPublicKey: hexToBytes(terms.sellerMemoPublicKey),
    agreedAmount: amount,
    agreedAmountSalt: hexToBytes(terms.amountSalt),
  };

  // Two real, opposing constraints found via live E2E runs (2026-08-21), both against this
  // buyer provider's very first-ever contract interaction (nothing has called
  // deployContract/findDeployedContract on it before this point in the buyer agent's life):
  //   1. privateStateProvider.set() throws "Contract address not set" if called before
  //      findDeployedContract has ever run against this contract address on this provider —
  //      so findDeployedContract must go FIRST here (unlike claimDeal/releaseTimeoutDeal,
  //      where the seller/buyer's own earlier propose()/lockEscrow() call already established
  //      the address on that same provider, so .set() first works fine there).
  //   2. findDeployedContract appears to process — and mutate in place — the object passed as
  //      initialPrivateState, coercing bigint fields (depositedCoin.value, agreedAmount) into
  //      plain decimal strings. Passing our real privateState there and saving it afterward
  //      silently persisted the corrupted strings, which broke a type-checked circuit arg
  //      (heldCoinForRelease) days later when releaseTimeoutDeal read them back.
  // Resolution: hand findDeployedContract a disposable clone (mutate that one, we don't care),
  // keep persisting the untouched original.
  const contract = await findDeployedContract(ctx.providers, {
    contractAddress: params.contractAddress,
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: structuredClone(privateState),
  });
  await ctx.providers.privateStateProvider.set(EscrowPrivateStateId, privateState);
  saveDealPrivateState(ctx.db, params.contractAddress, privateState);

  // Escrow.compact anchors deadlineTimestamp to this value (bounded-checked against real
  // block time via blockTimeGte/blockTimeLte, tolerance 300s) rather than to whenever
  // propose() happened — see AGENTS.md 5.30 and the contract's lockEscrow() comment.
  const claimedLockTime = BigInt(Math.floor(Date.now() / 1000));
  const result = await contract.callTx.lockEscrow(claimedLockTime);
  logAction(ctx, params.contractAddress, 'lockEscrow', {
    amount: terms.amount,
    currency: 'NIGHT',
    txId: result.public.txId,
  });

  // Discover and cache mt_index NOW, while the indexer is known-reachable (we just used it),
  // instead of waiting until claimDeal/releaseTimeoutDeal — potentially days later — need it.
  // By then a temporarily-down indexer would block spending; resolving it here removes that
  // dependency entirely for the rest of this deal's lifecycle. Best-effort: a failure here
  // must not fail the lock itself (the funds are already committed on-chain regardless) —
  // resolveMtIndex's lazy cache-first lookup in claimDeal/releaseTimeoutDeal is still the
  // fallback if this doesn't manage to complete.
  try {
    await resolveMtIndex(ctx, params.contractAddress, 'deposited');
  } catch (err) {
    console.warn(
      `[lockDeal] Could not pre-resolve mt_index for ${params.contractAddress} — will retry lazily at claim/release time.`,
      err
    );
  }

  return { txId: result.public.txId };
}

// ---- attestMilestone (port-authority only) ----

export async function attestDeal(ctx: AgentContext, contractAddress: string): Promise<{ txId: string }> {
  if (ctx.role !== 'port-authority') {
    throw new Error('attestMilestone() is only callable by the port-authority role.');
  }
  if (!ctx.identity.roleSecretKeyHex) throw new Error('Port-authority identity is missing its role secret key.');

  const privateState: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    portAuthoritySecretKey: hexToBytes(ctx.identity.roleSecretKeyHex),
  };
  const contract = await findDeployedContract(ctx.providers, {
    contractAddress,
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: privateState,
  });
  const result = await contract.callTx.attestMilestone();
  logAction(ctx, contractAddress, 'attestMilestone', { txId: result.public.txId });
  return { txId: result.public.txId };
}

// ---- claimPayout (seller only) ----

export async function claimDeal(ctx: AgentContext, contractAddress: string): Promise<{ txId: string }> {
  if (ctx.role !== 'seller') throw new Error('claimPayout() is only callable by the seller role in this agent.');

  const previous = loadDealPrivateState(ctx.db, contractAddress);
  if (!previous?.sellerAddress || !previous.sellerAddressSalt || !previous.counterpartyMemoPublicKey) {
    throw new Error('No prior propose() state found for this deal on this agent — cannot claim.');
  }

  const currentState = ledger((await ctx.providers.publicDataProvider.queryContractState(contractAddress))!.data);
  const recovered = recoverBuyerMemo(
    currentState.buyerMemo,
    hexToBytes(ctx.identity.memoKeyPair.privateKey),
    previous.counterpartyMemoPublicKey
  );

  const mtIndex = await resolveMtIndex(ctx, contractAddress, 'deposited');
  const privateState: EscrowPrivateState = {
    ...previous,
    qualifiedCoin: { ...recovered.coin, mt_index: mtIndex },
    depositSalt: recovered.depositSalt,
  };
  await ctx.providers.privateStateProvider.set(EscrowPrivateStateId, privateState);
  saveDealPrivateState(ctx.db, contractAddress, privateState);

  const contract = await findDeployedContract(ctx.providers, {
    contractAddress,
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: privateState,
  });
  const result = await contract.callTx.claimPayout();
  logAction(ctx, contractAddress, 'claimPayout', {
    amount: recovered.coin.value.toString(),
    currency: 'NIGHT',
    txId: result.public.txId,
  });
  return { txId: result.public.txId };
}

// ---- releaseOnTimeout (buyer path only in this pass — see file header) ----

/**
 * v0.1 scope: only the buyer-refund direction is wired here — the far more common real path
 * (buyer reclaims its own deposit because C never attested) and the one proven end-to-end in
 * timeout-lifecycle.ts. The seller-payout direction (`timeoutDirection: Seller`) needs the
 * exact same buyerMemo-recovery dance `claimDeal` already does above; adding it is a
 * mechanical follow-up, not a new pattern, once a real deal actually exercises that branch.
 */
export async function releaseTimeoutDeal(ctx: AgentContext, contractAddress: string): Promise<{ txId: string }> {
  if (ctx.role !== 'buyer') {
    throw new Error('This agent only implements the buyer-refund releaseOnTimeout path (see file header).');
  }
  const previous = loadDealPrivateState(ctx.db, contractAddress);
  if (!previous?.depositedCoin || !previous.depositSalt || !previous.buyerAddress || !previous.buyerAddressSalt) {
    throw new Error('No prior lockEscrow() state found for this deal on this agent — cannot release.');
  }

  const mtIndex = await resolveMtIndex(ctx, contractAddress, 'deposited');
  const privateState: EscrowPrivateState = {
    ...previous,
    qualifiedCoin: { ...previous.depositedCoin, mt_index: mtIndex },
  };
  await ctx.providers.privateStateProvider.set(EscrowPrivateStateId, privateState);
  saveDealPrivateState(ctx.db, contractAddress, privateState);

  const contract = await findDeployedContract(ctx.providers, {
    contractAddress,
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: privateState,
  });
  const result = await contract.callTx.releaseOnTimeout();
  logAction(ctx, contractAddress, 'releaseOnTimeout', { txId: result.public.txId });
  return { txId: result.public.txId };
}

// ---- read path (AGENTS.md 5.28 — goes straight to the indexer, not through node) ----

export interface DealStatus {
  contractAddress: string;
  state: number; // Escrow.compact's EscrowState enum ordinal (0 Empty..3 Released)
  milestoneConfirmed: boolean;
  deadlineTimestamp: number; // unix seconds
  timeoutDirection: 'buyer' | 'seller';
  /**
   * This company's OWN bookkeeping for this deal (5.25's transaction log — logAction below),
   * never the chain. The chain deliberately never stores the amount in plaintext (only
   * heldCommitment/agreedAmountCommitment, hashes — see Escrow.compact's privacy note); this
   * is what actually lets the panel show a number at all, and only to the company whose own
   * agent already knew it (it generated or received it during off-chain negotiation). A
   * counterparty's agent has its own separate copy of this same log — nothing here is shared
   * between companies or written anywhere public.
   */
  ownRecord: Array<{ action: string; amount: string | null; currency: string | null; timestamp: number }>;
}

export async function getDealStatus(ctx: AgentContext, contractAddress: string): Promise<DealStatus | null> {
  const raw = await ctx.providers.publicDataProvider.queryContractState(contractAddress);
  if (!raw) return null;
  const state = ledger(raw.data);
  const ownRecord = queryTransactions(ctx.txLog, { module: 'incoterms-escrow', dealRef: contractAddress }).map(
    (row) => ({ action: row.action, amount: row.amount, currency: row.currency, timestamp: row.timestamp })
  );
  return {
    contractAddress,
    state: Number(state.state),
    milestoneConfirmed: state.milestoneConfirmed,
    deadlineTimestamp: Number(state.deadlineTimestamp),
    timeoutDirection: Number(state.timeoutDirection) === 0 ? 'buyer' : 'seller',
    ownRecord,
  };
}

/** Helper for deriving `portAuthorityKeyHashHex` to hand to a counterparty during off-chain
 * negotiation (AGENTS.md 5.12) — exposed so the port-authority's own agent can compute and
 * publish its own key hash without needing to know Escrow.compact's internal domain string. */
export function computePortAuthorityKeyHash(portAuthoritySecretKeyHex: string): string {
  return Buffer.from(roleKeyHash(hexToBytes(portAuthoritySecretKeyHex), 'incoterms-escrow:port-auth:v1')).toString(
    'hex'
  );
}

export { openTransactionLog };
