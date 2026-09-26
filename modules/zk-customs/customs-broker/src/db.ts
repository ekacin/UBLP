/**
 * Broker's local state: the generic `review_queue` (from `@ublp/shared`, `kind:
 * 'submission-approval'` — the operator approving a prepared document before it's sent to
 * Ministry) plus a `submissions` table tracking the rest of the zk-customs pipeline, which is
 * specific to this module and doesn't belong in the generic shared primitive.
 *
 * Lifecycle: draft -> awaiting_approval -> sent_to_ministry -> awaiting_ministry_approval ->
 * vc_received -> proof_requested -> settled | rejected | failed.
 */

import fs from 'fs';
import path from 'path';
import Database from 'better-sqlite3';
import { openReviewQueue } from '@ublp/shared';
import { UBLPVerifiableCredential, UBLPVerifiablePresentation, L2SettleResponse } from '@ublp/zk-customs-types';

export type BrokerDb = Database.Database;

export type SubmissionStatus =
  | 'draft'
  | 'awaiting_approval'
  | 'sent_to_ministry'
  | 'awaiting_ministry_approval'
  | 'vc_received'
  | 'proof_requested'
  | 'settled'
  | 'rejected'
  | 'failed';

export interface Submission {
  id: number;
  reviewItemId: number;
  document: Record<string, unknown>;
  status: SubmissionStatus;
  ministryRefId: number | null;
  verifiableCredential: UBLPVerifiableCredential | null;
  presentation: UBLPVerifiablePresentation | null;
  l2Result: L2SettleResponse | null;
  error: string | null;
  createdAt: number;
  updatedAt: number;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reviewItemId INTEGER NOT NULL,
  document TEXT NOT NULL,
  status TEXT NOT NULL,
  ministryRefId INTEGER,
  verifiableCredential TEXT,
  presentation TEXT,
  l2Result TEXT,
  error TEXT,
  createdAt INTEGER NOT NULL,
  updatedAt INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);
CREATE INDEX IF NOT EXISTS idx_submissions_reviewItemId ON submissions(reviewItemId);
`;

export function openBrokerDb(dbPath: string): BrokerDb {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  openReviewQueue(db);
  db.exec(SCHEMA);
  return db;
}

function toSubmission(raw: any): Submission {
  return {
    ...raw,
    document: JSON.parse(raw.document),
    verifiableCredential: raw.verifiableCredential ? JSON.parse(raw.verifiableCredential) : null,
    presentation: raw.presentation ? JSON.parse(raw.presentation) : null,
    l2Result: raw.l2Result ? JSON.parse(raw.l2Result) : null,
  };
}

export function createSubmission(
  db: BrokerDb,
  entry: { reviewItemId: number; document: Record<string, unknown> }
): Submission {
  const now = Date.now();
  const result = db
    .prepare(
      `INSERT INTO submissions (reviewItemId, document, status, ministryRefId, verifiableCredential, presentation, l2Result, error, createdAt, updatedAt)
       VALUES (@reviewItemId, @document, 'draft', NULL, NULL, NULL, NULL, NULL, @now, @now)`
    )
    .run({ reviewItemId: entry.reviewItemId, document: JSON.stringify(entry.document), now });
  return getSubmission(db, Number(result.lastInsertRowid))!;
}

export function getSubmission(db: BrokerDb, id: number): Submission | null {
  const row = db.prepare(`SELECT * FROM submissions WHERE id = ?`).get(id);
  return row ? toSubmission(row) : null;
}

export function listSubmissions(db: BrokerDb, status?: SubmissionStatus): Submission[] {
  const rows = status
    ? db.prepare(`SELECT * FROM submissions WHERE status = ? ORDER BY createdAt DESC`).all(status)
    : db.prepare(`SELECT * FROM submissions ORDER BY createdAt DESC`).all();
  return rows.map(toSubmission);
}

export interface SubmissionUpdate {
  status?: SubmissionStatus;
  ministryRefId?: number;
  verifiableCredential?: UBLPVerifiableCredential;
  presentation?: UBLPVerifiablePresentation;
  l2Result?: L2SettleResponse;
  error?: string;
}

export function updateSubmission(db: BrokerDb, id: number, update: SubmissionUpdate): void {
  const current = getSubmission(db, id);
  if (!current) return;
  db.prepare(
    `UPDATE submissions SET status = ?, ministryRefId = ?, verifiableCredential = ?, presentation = ?, l2Result = ?, error = ?, updatedAt = ? WHERE id = ?`
  ).run(
    update.status ?? current.status,
    update.ministryRefId ?? current.ministryRefId,
    update.verifiableCredential ? JSON.stringify(update.verifiableCredential) : current.verifiableCredential ? JSON.stringify(current.verifiableCredential) : null,
    update.presentation ? JSON.stringify(update.presentation) : current.presentation ? JSON.stringify(current.presentation) : null,
    update.l2Result ? JSON.stringify(update.l2Result) : current.l2Result ? JSON.stringify(current.l2Result) : null,
    update.error ?? current.error,
    Date.now(),
    id
  );
}
