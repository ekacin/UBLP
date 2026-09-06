import fs from 'fs';
import os from 'os';
import path from 'path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  openSettlementDb,
  createPendingAction,
  findInFlightAction,
  getPendingAction,
  updatePendingActionStatus,
  listPendingActions,
  getCachedMtIndex,
  setCachedMtIndex,
  saveDealPrivateState,
  loadDealPrivateState,
  listDealRefs,
  type SettlementDb,
} from '../../src/server/db.js';
import { emptyEscrowPrivateState, zswapRecipient } from '../../src/contract/index.js';

let dbPath: string;
let db: SettlementDb;

beforeEach(() => {
  dbPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'ublp-settlement-db-')), 'settlement-agent.db');
  db = openSettlementDb(dbPath);
});

afterEach(() => {
  db.close();
  fs.rmSync(path.dirname(dbPath), { recursive: true, force: true });
});

describe('pending_actions', () => {
  it('round-trips a created action through get/update/list', () => {
    const created = createPendingAction(db, {
      dealRef: 'deal-1',
      action: 'lockEscrow',
      requestedBy: 'operator-pubkey',
      payload: { contractAddress: 'deal-1', agreedAmount: '1000000' },
    });
    expect(created.status).toBe('awaiting_approval');
    expect(created.payload).toEqual({ contractAddress: 'deal-1', agreedAmount: '1000000' });

    const fetched = getPendingAction(db, created.id);
    expect(fetched).toEqual(created);

    updatePendingActionStatus(db, created.id, 'confirmed', '0xabc123');
    const confirmed = getPendingAction(db, created.id)!;
    expect(confirmed.status).toBe('confirmed');
    expect(confirmed.txId).toBe('0xabc123');

    const listed = listPendingActions(db, 'deal-1');
    expect(listed).toHaveLength(1);
    expect(listed[0].id).toBe(created.id);
  });

  it('findInFlightAction only matches non-terminal statuses for the same deal+action', () => {
    const a = createPendingAction(db, { dealRef: 'deal-2', action: 'lockEscrow', requestedBy: 'op', payload: {} });
    expect(findInFlightAction(db, 'deal-2', 'lockEscrow')?.id).toBe(a.id);

    updatePendingActionStatus(db, a.id, 'confirmed');
    expect(findInFlightAction(db, 'deal-2', 'lockEscrow')).toBeNull();

    // Different action name on the same deal shouldn't match.
    createPendingAction(db, { dealRef: 'deal-2', action: 'attestMilestone', requestedBy: 'op', payload: {} });
    expect(findInFlightAction(db, 'deal-2', 'lockEscrow')).toBeNull();
  });

  it('submitted_pending counts as in-flight (this is the whole point of the status)', () => {
    const a = createPendingAction(db, { dealRef: 'deal-3', action: 'lockEscrow', requestedBy: 'op', payload: {} });
    updatePendingActionStatus(db, a.id, 'submitted_pending');
    expect(findInFlightAction(db, 'deal-3', 'lockEscrow')?.id).toBe(a.id);
  });
});

describe('mt_index_cache', () => {
  it('returns null before anything is cached, then the cached value after', () => {
    expect(getCachedMtIndex(db, '0xcontract', 'deposited')).toBeNull();
    setCachedMtIndex(db, '0xcontract', 'deposited', 46n);
    expect(getCachedMtIndex(db, '0xcontract', 'deposited')).toBe(46n);
  });

  it('overwrites a stale cached index for the same key', () => {
    setCachedMtIndex(db, '0xcontract', 'deposited', 46n);
    setCachedMtIndex(db, '0xcontract', 'deposited', 51n);
    expect(getCachedMtIndex(db, '0xcontract', 'deposited')).toBe(51n);
  });

  it('keeps different coinDescriptors for the same contract separate', () => {
    setCachedMtIndex(db, '0xcontract', 'deposited', 46n);
    setCachedMtIndex(db, '0xcontract', 'refund', 82n);
    expect(getCachedMtIndex(db, '0xcontract', 'deposited')).toBe(46n);
    expect(getCachedMtIndex(db, '0xcontract', 'refund')).toBe(82n);
  });
});

describe('deal_private_state', () => {
  it('returns null for a deal that was never saved', () => {
    expect(loadDealPrivateState(db, 'never-saved')).toBeNull();
  });

  it('round-trips Uint8Array and bigint fields exactly', () => {
    const state = {
      ...emptyEscrowPrivateState,
      sellerSecretKey: new Uint8Array([1, 2, 3, 4]),
      sellerAddress: zswapRecipient(new Uint8Array(32).fill(7)),
      agreedAmount: 1_000_000n,
      agreedAmountSalt: new Uint8Array(32).fill(9),
    };
    saveDealPrivateState(db, 'deal-4', state);

    const loaded = loadDealPrivateState(db, 'deal-4')!;
    expect(loaded.sellerSecretKey).toBeInstanceOf(Uint8Array);
    expect(Array.from(loaded.sellerSecretKey!)).toEqual([1, 2, 3, 4]);
    expect(loaded.agreedAmount).toBe(1_000_000n);
    expect(typeof loaded.agreedAmount).toBe('bigint');
    expect(Array.from(loaded.agreedAmountSalt!)).toEqual(Array.from(new Uint8Array(32).fill(9)));
    expect(loaded.sellerAddress?.is_left).toBe(true);
  });

  it('overwrites the previous state for the same dealRef', () => {
    saveDealPrivateState(db, 'deal-5', { ...emptyEscrowPrivateState, agreedAmount: 1n });
    saveDealPrivateState(db, 'deal-5', { ...emptyEscrowPrivateState, agreedAmount: 2n });
    expect(loadDealPrivateState(db, 'deal-5')!.agreedAmount).toBe(2n);
  });
});

describe('listDealRefs', () => {
  it('returns an empty list when no deal has been saved', () => {
    expect(listDealRefs(db)).toEqual([]);
  });

  it('lists every distinct dealRef that has private state saved, without duplicates', () => {
    saveDealPrivateState(db, 'deal-a', emptyEscrowPrivateState);
    saveDealPrivateState(db, 'deal-b', emptyEscrowPrivateState);
    saveDealPrivateState(db, 'deal-a', { ...emptyEscrowPrivateState, agreedAmount: 5n }); // update, not a new row

    expect(listDealRefs(db).sort()).toEqual(['deal-a', 'deal-b']);
  });
});
