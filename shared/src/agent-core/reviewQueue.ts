/**
 * Generic "item awaiting a human decision" queue — shared by every UBLP module that needs a
 * human to approve or reject something before an automated pipeline continues (e.g. zk-customs'
 * Ministry reviewing a document before signing it, or a broker operator approving a submission
 * before it's sent onward).
 *
 * Modeled on incoterms-escrow's `pending_actions` table (`modules/incoterms-escrow/src/server/db.ts`),
 * generalized: `kind` replaces escrow's hardcoded circuit-name `action` column, and there's no
 * `txId`/on-chain concept baked in — a module that needs to remember a follow-on reference (e.g.
 * the VC issued after approval) stores that in its own table, keyed by this queue's `id`.
 */

import type Database from 'better-sqlite3';

export type ReviewStatus = 'awaiting_approval' | 'approved' | 'rejected';

export interface ReviewItem {
  id: number;
  /** Distinguishes what's queued when several kinds share one physical db, e.g. "document-approval". */
  kind: string;
  /** The caller's own reference for the thing being reviewed (a document id, a submission id, ...). */
  refId: string;
  status: ReviewStatus;
  payload: Record<string, unknown>;
  requestedBy: string;
  decidedBy: string | null;
  decisionNote: string | null;
  createdAt: number;
  updatedAt: number;
}

export interface ReviewItemFilter {
  kind?: string;
  status?: ReviewStatus;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS review_queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  refId TEXT NOT NULL,
  status TEXT NOT NULL,
  payload TEXT NOT NULL,
  requestedBy TEXT NOT NULL,
  decidedBy TEXT,
  decisionNote TEXT,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_review_queue_kind ON review_queue(kind);
CREATE INDEX IF NOT EXISTS idx_review_queue_status ON review_queue(status);
CREATE INDEX IF NOT EXISTS idx_review_queue_refId ON review_queue(refId);
`;

/** Creates the `review_queue` table if it doesn't exist yet. Doesn't open or own the db
 * connection — same convention as `transactionLog.ts`, the caller opens its own db file and
 * calls this (plus any of its own tables' schema) once at startup. */
export function openReviewQueue(db: Database.Database): void {
  db.exec(SCHEMA);
}

function toReviewItem(raw: any): ReviewItem {
  return { ...raw, payload: JSON.parse(raw.payload) };
}

export function createReviewItem(
  db: Database.Database,
  entry: Pick<ReviewItem, 'kind' | 'refId' | 'payload' | 'requestedBy'>
): ReviewItem {
  const now = Date.now();
  const result = db
    .prepare(
      `INSERT INTO review_queue (kind, refId, status, payload, requestedBy, decidedBy, decisionNote, createdAt, updatedAt)
       VALUES (@kind, @refId, 'awaiting_approval', @payload, @requestedBy, NULL, NULL, @now, @now)`
    )
    .run({
      kind: entry.kind,
      refId: entry.refId,
      payload: JSON.stringify(entry.payload),
      requestedBy: entry.requestedBy,
      now,
    });
  return getReviewItem(db, Number(result.lastInsertRowid))!;
}

export function getReviewItem(db: Database.Database, id: number): ReviewItem | null {
  const row = db.prepare(`SELECT * FROM review_queue WHERE id = ?`).get(id);
  return row ? toReviewItem(row) : null;
}

export function listReviewItems(db: Database.Database, filter: ReviewItemFilter = {}): ReviewItem[] {
  const clauses: string[] = [];
  const params: Record<string, unknown> = {};
  if (filter.kind !== undefined) { clauses.push('kind = @kind'); params.kind = filter.kind; }
  if (filter.status !== undefined) { clauses.push('status = @status'); params.status = filter.status; }
  const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
  const rows = db.prepare(`SELECT * FROM review_queue ${where} ORDER BY createdAt ASC`).all(params);
  return rows.map(toReviewItem);
}

/** Decides a pending item. Refuses (returns null) if the item doesn't exist or was already
 * decided — a decision is final, there's no re-deciding an item once approved/rejected. */
export function decideReviewItem(
  db: Database.Database,
  id: number,
  decision: 'approved' | 'rejected',
  decidedBy: string,
  note?: string
): ReviewItem | null {
  const existing = getReviewItem(db, id);
  if (!existing || existing.status !== 'awaiting_approval') return null;

  db.prepare(
    `UPDATE review_queue SET status = ?, decidedBy = ?, decisionNote = ?, updatedAt = ? WHERE id = ?`
  ).run(decision, decidedBy, note ?? null, Date.now(), id);
  return getReviewItem(db, id);
}
