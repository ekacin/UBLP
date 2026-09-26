/**
 * Ministry's local state: the generic `review_queue` (from `@ublp/shared`, `kind:
 * 'document-approval'`) plus a `documents` table holding the VC issued once an officer approves
 * a queued item — `GET /api/documents/:submissionId` (Broker's poller) reads from here.
 */

import fs from 'fs';
import path from 'path';
import Database from 'better-sqlite3';
import { openReviewQueue } from '@ublp/shared';
import { UBLPVerifiableCredential } from '@ublp/zk-customs-types';

export type MinistryDb = Database.Database;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS documents (
  submissionId INTEGER PRIMARY KEY,
  status TEXT NOT NULL,
  verifiableCredential TEXT,
  updatedAt INTEGER NOT NULL
);
`;

export function openMinistryDb(dbPath: string): MinistryDb {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  openReviewQueue(db);
  db.exec(SCHEMA);
  return db;
}

export interface DocumentRecord {
  submissionId: number;
  status: 'awaiting_approval' | 'approved' | 'rejected';
  verifiableCredential: UBLPVerifiableCredential | null;
  updatedAt: number;
}

function toDocumentRecord(raw: any): DocumentRecord {
  return { ...raw, verifiableCredential: raw.verifiableCredential ? JSON.parse(raw.verifiableCredential) : null };
}

export function upsertDocumentRecord(
  db: MinistryDb,
  submissionId: number,
  status: DocumentRecord['status'],
  verifiableCredential: UBLPVerifiableCredential | null
): void {
  db.prepare(
    `INSERT INTO documents (submissionId, status, verifiableCredential, updatedAt)
     VALUES (@submissionId, @status, @verifiableCredential, @now)
     ON CONFLICT (submissionId) DO UPDATE SET status = excluded.status,
       verifiableCredential = excluded.verifiableCredential, updatedAt = excluded.updatedAt`
  ).run({
    submissionId,
    status,
    verifiableCredential: verifiableCredential ? JSON.stringify(verifiableCredential) : null,
    now: Date.now(),
  });
}

export function getDocumentRecord(db: MinistryDb, submissionId: number): DocumentRecord | null {
  const row = db.prepare(`SELECT * FROM documents WHERE submissionId = ?`).get(submissionId);
  return row ? toDocumentRecord(row) : null;
}
