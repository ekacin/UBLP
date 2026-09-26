import { describe, it, expect } from 'vitest';
import Database from 'better-sqlite3';
import {
  openReviewQueue,
  createReviewItem,
  getReviewItem,
  listReviewItems,
  decideReviewItem,
} from '../../../../shared/src/agent-core/reviewQueue';

function freshDb(): Database.Database {
  const db = new Database(':memory:');
  openReviewQueue(db);
  return db;
}

describe('reviewQueue', () => {
  it('creates an item in awaiting_approval status', () => {
    const db = freshDb();
    const item = createReviewItem(db, {
      kind: 'document-approval',
      refId: 'DOC-1',
      payload: { a: 1 },
      requestedBy: 'broker',
    });
    expect(item.status).toBe('awaiting_approval');
    expect(item.payload).toEqual({ a: 1 });
    expect(item.decidedBy).toBeNull();
    expect(getReviewItem(db, item.id)).toEqual(item);
  });

  it('lists items filtered by kind and status', () => {
    const db = freshDb();
    createReviewItem(db, { kind: 'document-approval', refId: 'DOC-1', payload: {}, requestedBy: 'broker' });
    createReviewItem(db, { kind: 'submission-approval', refId: 'SUB-1', payload: {}, requestedBy: 'operator' });

    const docs = listReviewItems(db, { kind: 'document-approval' });
    expect(docs).toHaveLength(1);
    expect(docs[0].refId).toBe('DOC-1');

    const awaiting = listReviewItems(db, { status: 'awaiting_approval' });
    expect(awaiting).toHaveLength(2);
  });

  it('approves a pending item exactly once', () => {
    const db = freshDb();
    const item = createReviewItem(db, { kind: 'document-approval', refId: 'DOC-1', payload: {}, requestedBy: 'broker' });

    const decided = decideReviewItem(db, item.id, 'approved', 'officer');
    expect(decided?.status).toBe('approved');
    expect(decided?.decidedBy).toBe('officer');

    // Already decided — a second decision is refused, not silently overwritten.
    const secondAttempt = decideReviewItem(db, item.id, 'rejected', 'officer');
    expect(secondAttempt).toBeNull();
    expect(getReviewItem(db, item.id)?.status).toBe('approved');
  });

  it('rejects with a note', () => {
    const db = freshDb();
    const item = createReviewItem(db, { kind: 'document-approval', refId: 'DOC-2', payload: {}, requestedBy: 'broker' });
    const decided = decideReviewItem(db, item.id, 'rejected', 'officer', 'missing HS code');
    expect(decided?.status).toBe('rejected');
    expect(decided?.decisionNote).toBe('missing HS code');
  });

  it('returns null when deciding or fetching a nonexistent item', () => {
    const db = freshDb();
    expect(decideReviewItem(db, 999, 'approved', 'officer')).toBeNull();
    expect(getReviewItem(db, 999)).toBeNull();
  });
});
