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
import { openTransactionLog, logTransaction, type TransactionLogDb } from '@ublp/shared';
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
import {
  type SettlementDb,
  getCachedMtIndex,
  setCachedMtIndex,
  saveDealPrivateState,
  loadDealPrivateState,
} from './db.js';

export interface AgentContext {
  role: AgentRole;
  network: NetworkConfig;
  wallet: AgentWallet;
  providers: ReturnType<typeof buildEscrowProviders>;
  identity: SettlementIdentity;
  db: SettlementDb;
  txLog: TransactionLogDb;
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

export interface ProposeParams {
  portAuthorityKeyHashHex: string; // C's roleKeyHash, shared during off-chain negotiation
  deadlineAtSeconds: number;
  /** AGENTS.md 5.19/5.20 — a per-deal negotiated term, not a protocol constant. Optional here
   * because the documented default is 'buyer' ("seçilebilir ama varsayılan buyer") — callers
   * who don't want to think about it get the suggested default; callers who negotiated
   * something else can still override it explicitly. */
  timeoutDirection?: 'buyer' | 'seller';
  agreedAmount: string; // integer string, smallest unit
  buyerMemoPublicKeyHex: string; // buyer's X25519 public key, from the negotiated terms
}

export interface ProposeResult {
  contractAddress: string;
  txId: string;
}

export async function proposeDeal(ctx: AgentContext, params: ProposeParams): Promise<ProposeResult> {
  if (ctx.role !== 'seller') throw new Error('propose() is only callable by the seller role.');
  if (!ctx.identity.roleSecretKeyHex) throw new Error('Seller identity is missing its role secret key.');

  const deployed = await deployContract(ctx.providers, {
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: emptyEscrowPrivateState,
  });
  const contractAddress = deployed.deployTxData.public.contractAddress;

  const sellerAddressSalt = randomBytes32();
  const agreedAmountSalt = randomBytes32();
  const privateState: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    sellerSecretKey: hexToBytes(ctx.identity.roleSecretKeyHex),
    sellerAddress: zswapRecipient(hexToBytes(ctx.wallet.midnightWalletProvider.getCoinPublicKey())),
    sellerAddressSalt,
    ownMemoPrivateKey: hexToBytes(ctx.identity.memoKeyPair.privateKey),
    counterpartyMemoPublicKey: hexToBytes(params.buyerMemoPublicKeyHex),
    agreedAmount: BigInt(params.agreedAmount),
    agreedAmountSalt,
  };
  await ctx.providers.privateStateProvider.set(EscrowPrivateStateId, privateState);
  saveDealPrivateState(ctx.db, contractAddress, privateState);

  const timeoutDirection = params.timeoutDirection ?? 'buyer';
  const result = await deployed.callTx.propose(
    hexToBytes(params.portAuthorityKeyHashHex),
    BigInt(params.deadlineAtSeconds),
    timeoutDirection === 'buyer' ? TimeoutDirection.Buyer : TimeoutDirection.Seller
  );

  logAction(ctx, contractAddress, 'propose', {
    amount: params.agreedAmount,
    currency: 'NIGHT',
    txId: result.public.txId,
    metadata: { deadlineAtSeconds: params.deadlineAtSeconds, timeoutDirection },
  });

  return { contractAddress, txId: result.public.txId };
}

// ---- lockEscrow (buyer only) ----

export interface LockParams {
  contractAddress: string;
  agreedAmount: string;
  sellerMemoPublicKeyHex: string; // seller's X25519 public key, from the negotiated terms
}

export async function lockDeal(ctx: AgentContext, params: LockParams): Promise<{ txId: string }> {
  if (ctx.role !== 'buyer') throw new Error('lockEscrow() is only callable by the buyer role.');

  const amount = BigInt(params.agreedAmount);
  const depositSalt = randomBytes32();
  const buyerAddressSalt = randomBytes32();
  const depositedCoinSdk = createShieldedCoinInfo(shieldedToken().raw, amount);
  // Same `as any` the proven devnet scripts use (full-lifecycle.ts, timeout-lifecycle.ts) —
  // encodeShieldedCoinInfo's declared return type doesn't match its actual runtime shape here.
  const depositedCoinEncoded = encodeShieldedCoinInfo(depositedCoinSdk) as any;

  const previous = loadDealPrivateState(ctx.db, params.contractAddress) ?? emptyEscrowPrivateState;
  const privateState: EscrowPrivateState = {
    ...previous,
    depositedCoin: {
      nonce: hexToBytes(depositedCoinEncoded.nonce ?? depositedCoinSdk.nonce),
      color: hexToBytes(depositedCoinEncoded.color),
      value: amount,
    },
    depositSalt,
    buyerAddress: zswapRecipient(hexToBytes(ctx.wallet.midnightWalletProvider.getCoinPublicKey())),
    buyerAddressSalt,
    ownMemoPrivateKey: hexToBytes(ctx.identity.memoKeyPair.privateKey),
    counterpartyMemoPublicKey: hexToBytes(params.sellerMemoPublicKeyHex),
    agreedAmount: amount,
  };

  const contract = await findDeployedContract(ctx.providers, {
    contractAddress: params.contractAddress,
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: privateState,
  });
  await ctx.providers.privateStateProvider.set(EscrowPrivateStateId, privateState);
  saveDealPrivateState(ctx.db, params.contractAddress, privateState);

  const result = await contract.callTx.lockEscrow();
  logAction(ctx, params.contractAddress, 'lockEscrow', {
    amount: params.agreedAmount,
    currency: 'NIGHT',
    txId: result.public.txId,
  });

  return { txId: result.public.txId };
}

// ---- attestLoadingConfirmed (port-authority only) ----

export async function attestDeal(ctx: AgentContext, contractAddress: string): Promise<{ txId: string }> {
  if (ctx.role !== 'port-authority') {
    throw new Error('attestLoadingConfirmed() is only callable by the port-authority role.');
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
  const result = await contract.callTx.attestLoadingConfirmed();
  logAction(ctx, contractAddress, 'attestLoadingConfirmed', { txId: result.public.txId });
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
  loadingConfirmed: boolean;
  deadlineTimestamp: number; // unix seconds
  timeoutDirection: 'buyer' | 'seller';
}

export async function getDealStatus(ctx: AgentContext, contractAddress: string): Promise<DealStatus | null> {
  const raw = await ctx.providers.publicDataProvider.queryContractState(contractAddress);
  if (!raw) return null;
  const state = ledger(raw.data);
  return {
    contractAddress,
    state: Number(state.state),
    loadingConfirmed: state.loadingConfirmed,
    deadlineTimestamp: Number(state.deadlineTimestamp),
    timeoutDirection: Number(state.timeoutDirection) === 0 ? 'buyer' : 'seller',
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
