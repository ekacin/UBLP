/**
 * Settlement-agent local state — two tables, both decided in AGENTS.md 5.28/5.29:
 *
 * - `pending_actions`: the "waiting for a human to approve in the panel" queue (5.21's approval
 *   model needs *some* place to hold a draft action between "prepared" and "submitted" — the
 *   chain has no concept of this, only finalized transactions). Also carries a
 *   `submitted_pending` status so the panel/API can refuse a second submit of the same
 *   deal+action before indexer confirmation lands — not because the contract would allow a
 *   double-spend (it can't, see 5.29), purely to avoid wasting a proof+fee on a call that's
 *   already in flight.
 * - `mt_index_cache`: once a contract-held coin's Merkle-tree index is discovered (the
 *   indexer-dump-and-regex dance in lifecycle-helpers.ts's findContractCoinMtIndex — a real,
 *   expensive gotcha, AGENTS.md 5.23), it's cached here so a later claimPayout/releaseOnTimeout
 *   doesn't have to re-discover it, and so a temporary indexer outage doesn't block spending a
 *   coin whose index is already known (5.28's indexer-liveness mitigation).
 *
 * Lives in the same physical SQLite file as the transaction-log (`@ublp/shared`'s
 * transactionLog.ts) by default — separate tables, same "one file per agent" convention.
 */

import fs from 'fs';
import path from 'path';
import Database from 'better-sqlite3';
import type { EscrowPrivateState } from '../contract/witnesses.js';

export type SettlementDb = Database.Database;

export type PendingActionStatus = 'awaiting_approval' | 'approved' | 'submitted_pending' | 'confirmed' | 'rejected' | 'failed';

export interface PendingAction {
  id: number;
  dealRef: string; // contract address, or a client-chosen temp id before deployment
  action: string; // 'propose' | 'lockEscrow' | 'attestLoadingConfirmed' | 'claimPayout' | 'releaseOnTimeout'
  status: PendingActionStatus;
  requestedBy: string; // login identity public key (PEM) of whoever queued it
  payload: Record<string, unknown>; // action-specific parameters, JSON
  txId: string | null;
  createdAt: number;
  updatedAt: number;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS pending_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  dealRef TEXT NOT NULL,
  action TEXT NOT NULL,
  status TEXT NOT NULL,
  requestedBy TEXT NOT NULL,
  payload TEXT NOT NULL,
  txId TEXT,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pending_actions_dealRef ON pending_actions(dealRef);
CREATE INDEX IF NOT EXISTS idx_pending_actions_status ON pending_actions(status);

CREATE TABLE IF NOT EXISTS mt_index_cache (
  contractAddress TEXT NOT NULL,
  coinDescriptor TEXT NOT NULL,
  mtIndex TEXT NOT NULL,
  discoveredAt INTEGER NOT NULL,
  PRIMARY KEY (contractAddress, coinDescriptor)
);

CREATE TABLE IF NOT EXISTS deal_private_state (
  dealRef TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  updatedAt INTEGER NOT NULL
);
`;

export function openSettlementDb(dbPath: string): SettlementDb {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.exec(SCHEMA);
  return db;
}

function toPendingAction(raw: any): PendingAction {
  return { ...raw, payload: JSON.parse(raw.payload) };
}

export function createPendingAction(
  db: SettlementDb,
  entry: Pick<PendingAction, 'dealRef' | 'action' | 'requestedBy' | 'payload'>
): PendingAction {
  const now = Date.now();
  const result = db
    .prepare(
      `INSERT INTO pending_actions (dealRef, action, status, requestedBy, payload, txId, createdAt, updatedAt)
       VALUES (@dealRef, @action, 'awaiting_approval', @requestedBy, @payload, NULL, @now, @now)`
    )
    .run({
      dealRef: entry.dealRef,
      action: entry.action,
      requestedBy: entry.requestedBy,
      payload: JSON.stringify(entry.payload),
      now,
    });
  return getPendingAction(db, Number(result.lastInsertRowid))!;
}

export function getPendingAction(db: SettlementDb, id: number): PendingAction | null {
  const row = db.prepare(`SELECT * FROM pending_actions WHERE id = ?`).get(id);
  return row ? toPendingAction(row) : null;
}

/** Finds an in-flight (not yet confirmed/rejected/failed) action for the same deal+action pair
 * — the check the panel/API uses to refuse a redundant resubmit (see file header). */
export function findInFlightAction(db: SettlementDb, dealRef: string, action: string): PendingAction | null {
  const row = db
    .prepare(
      `SELECT * FROM pending_actions
       WHERE dealRef = ? AND action = ? AND status IN ('awaiting_approval', 'approved', 'submitted_pending')
       ORDER BY createdAt DESC LIMIT 1`
    )
    .get(dealRef, action);
  return row ? toPendingAction(row) : null;
}

export function updatePendingActionStatus(
  db: SettlementDb,
  id: number,
  status: PendingActionStatus,
  txId?: string
): void {
  db.prepare(`UPDATE pending_actions SET status = ?, txId = COALESCE(?, txId), updatedAt = ? WHERE id = ?`).run(
    status,
    txId ?? null,
    Date.now(),
    id
  );
}

export function listPendingActions(db: SettlementDb, dealRef?: string): PendingAction[] {
  const rows = dealRef
    ? db.prepare(`SELECT * FROM pending_actions WHERE dealRef = ? ORDER BY createdAt ASC`).all(dealRef)
    : db.prepare(`SELECT * FROM pending_actions ORDER BY createdAt ASC`).all();
  return rows.map(toPendingAction);
}

// ---- mt_index cache ----

/** `coinDescriptor` distinguishes which coin within a contract this index is for (a contract
 * only ever holds one live coin at a time in the current v0.1 design, but naming it instead of
 * hardcoding "the" coin keeps this cache correct if that ever changes — e.g. "deposited"). */
export function getCachedMtIndex(db: SettlementDb, contractAddress: string, coinDescriptor: string): bigint | null {
  const row = db
    .prepare(`SELECT mtIndex FROM mt_index_cache WHERE contractAddress = ? AND coinDescriptor = ?`)
    .get(contractAddress, coinDescriptor) as { mtIndex: string } | undefined;
  return row ? BigInt(row.mtIndex) : null;
}

export function setCachedMtIndex(
  db: SettlementDb,
  contractAddress: string,
  coinDescriptor: string,
  mtIndex: bigint
): void {
  db.prepare(
    `INSERT INTO mt_index_cache (contractAddress, coinDescriptor, mtIndex, discoveredAt)
     VALUES (?, ?, ?, ?)
     ON CONFLICT (contractAddress, coinDescriptor) DO UPDATE SET mtIndex = excluded.mtIndex, discoveredAt = excluded.discoveredAt`
  ).run(contractAddress, coinDescriptor, mtIndex.toString(), Date.now());
}

// ---- per-deal private state (EscrowPrivateState survives across separate HTTP calls —
// e.g. propose() today, claimPayout() days later — so it has to be persisted somewhere; the
// chain itself never sees any of this, by design) ----

function replacer(_key: string, value: unknown): unknown {
  if (value instanceof Uint8Array) return { __u8: Buffer.from(value).toString('hex') };
  if (typeof value === 'bigint') return { __bigint: value.toString() };
  return value;
}

function reviver(_key: string, value: unknown): unknown {
  if (value && typeof value === 'object') {
    if ('__u8' in (value as Record<string, unknown>)) {
      return new Uint8Array(Buffer.from((value as { __u8: string }).__u8, 'hex'));
    }
    if ('__bigint' in (value as Record<string, unknown>)) {
      return BigInt((value as { __bigint: string }).__bigint);
    }
  }
  return value;
}

export function saveDealPrivateState(db: SettlementDb, dealRef: string, state: EscrowPrivateState): void {
  db.prepare(
    `INSERT INTO deal_private_state (dealRef, state, updatedAt) VALUES (?, ?, ?)
     ON CONFLICT (dealRef) DO UPDATE SET state = excluded.state, updatedAt = excluded.updatedAt`
  ).run(dealRef, JSON.stringify(state, replacer), Date.now());
}

export function loadDealPrivateState(db: SettlementDb, dealRef: string): EscrowPrivateState | null {
  const row = db.prepare(`SELECT state FROM deal_private_state WHERE dealRef = ?`).get(dealRef) as
    | { state: string }
    | undefined;
  return row ? (JSON.parse(row.state, reviver) as EscrowPrivateState) : null;
}

/** Every deal this agent has ever touched (propose or lockEscrow set a row) — the watcher's
 * starting point for "which deals do I even need to check". */
export function listDealRefs(db: SettlementDb): string[] {
  const rows = db.prepare(`SELECT dealRef FROM deal_private_state ORDER BY updatedAt ASC`).all() as {
    dealRef: string;
  }[];
  return rows.map((r) => r.dealRef);
}
