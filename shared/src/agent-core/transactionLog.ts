/**
 * Generic, SQLite-backed transaction audit log — shared by every UBLP agent (ublp-agent, the
 * incoterms-escrow settlement agent, and any future module). See AGENTS.md Section 5.21/5.24's
 * "company's own accounting" discussion: this is NOT a privacy/viewing-key mechanism — it's a
 * normal internal record store. The agent already knows every plaintext detail of its own
 * transactions (it generated the witness data), so it can simply log them; the chain's privacy
 * guarantees are about hiding this data from outside observers, not from the company's own
 * bookkeeping.
 *
 * `module` distinguishes which agent wrote a given row (e.g. "incoterms-escrow", "zk-customs"),
 * so every agent can share one physical database file if convenient, without their rows
 * colliding. `metadata` carries whatever extra, module-specific fields don't fit the common
 * columns (see e.g. incoterms-escrow's TimeoutDirection, or zk-customs' claim types).
 */

import fs from 'fs';
import path from 'path';
import Database from 'better-sqlite3';
import ExcelJS from 'exceljs';

export interface TransactionLogEntry {
  /** Which agent/module wrote this row, e.g. "incoterms-escrow". */
  module: string;
  /** The deal/shipment/case this transaction belongs to. */
  dealRef: string;
  /** The circuit or action name, e.g. "propose", "lockEscrow", "claimPayout". */
  action: string;
  /** The counterparty's address/DID, if this action has one. */
  counterparty?: string;
  /** As a string (not number/bigint) — avoids float precision loss and JSON/SQLite bigint issues. */
  amount?: string;
  currency?: string;
  /** The real on-chain transaction ID, once known. */
  txId?: string;
  /** Unix milliseconds. Defaults to Date.now() if omitted when logging. */
  timestamp?: number;
  /** Module-specific extra fields, stored as a JSON blob. */
  metadata?: Record<string, unknown>;
}

export interface TransactionLogRow extends Required<Pick<TransactionLogEntry, 'module' | 'dealRef' | 'action' | 'timestamp'>> {
  id: number;
  counterparty: string | null;
  amount: string | null;
  currency: string | null;
  txId: string | null;
  metadata: Record<string, unknown> | null;
}

export interface TransactionLogFilter {
  module?: string;
  dealRef?: string;
  action?: string;
  /** Unix milliseconds, inclusive. */
  from?: number;
  /** Unix milliseconds, inclusive. */
  to?: number;
}

export type TransactionLogDb = Database.Database;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS transaction_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  module TEXT NOT NULL,
  dealRef TEXT NOT NULL,
  action TEXT NOT NULL,
  counterparty TEXT,
  amount TEXT,
  currency TEXT,
  txId TEXT,
  timestamp INTEGER NOT NULL,
  metadata TEXT
);
CREATE INDEX IF NOT EXISTS idx_transaction_log_dealRef ON transaction_log(dealRef);
CREATE INDEX IF NOT EXISTS idx_transaction_log_module ON transaction_log(module);
CREATE INDEX IF NOT EXISTS idx_transaction_log_timestamp ON transaction_log(timestamp);
`;

/** Opens (creating if needed, including the parent directory) the SQLite-backed transaction
 * log at `dbPath`. */
export function openTransactionLog(dbPath: string): TransactionLogDb {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.exec(SCHEMA);
  return db;
}

export function logTransaction(db: TransactionLogDb, entry: TransactionLogEntry): void {
  db.prepare(
    `INSERT INTO transaction_log (module, dealRef, action, counterparty, amount, currency, txId, timestamp, metadata)
     VALUES (@module, @dealRef, @action, @counterparty, @amount, @currency, @txId, @timestamp, @metadata)`
  ).run({
    module: entry.module,
    dealRef: entry.dealRef,
    action: entry.action,
    counterparty: entry.counterparty ?? null,
    amount: entry.amount ?? null,
    currency: entry.currency ?? null,
    txId: entry.txId ?? null,
    timestamp: entry.timestamp ?? Date.now(),
    metadata: entry.metadata ? JSON.stringify(entry.metadata) : null,
  });
}

function toRow(raw: any): TransactionLogRow {
  return { ...raw, metadata: raw.metadata ? JSON.parse(raw.metadata) : null };
}

export function queryTransactions(db: TransactionLogDb, filter: TransactionLogFilter = {}): TransactionLogRow[] {
  const clauses: string[] = [];
  const params: Record<string, unknown> = {};
  if (filter.module !== undefined) { clauses.push('module = @module'); params.module = filter.module; }
  if (filter.dealRef !== undefined) { clauses.push('dealRef = @dealRef'); params.dealRef = filter.dealRef; }
  if (filter.action !== undefined) { clauses.push('action = @action'); params.action = filter.action; }
  if (filter.from !== undefined) { clauses.push('timestamp >= @from'); params.from = filter.from; }
  if (filter.to !== undefined) { clauses.push('timestamp <= @to'); params.to = filter.to; }
  const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
  const rows = db.prepare(`SELECT * FROM transaction_log ${where} ORDER BY timestamp ASC`).all(params);
  return rows.map(toRow);
}

const CSV_COLUMNS: (keyof TransactionLogRow)[] = [
  'id', 'module', 'dealRef', 'action', 'counterparty', 'amount', 'currency', 'txId', 'timestamp',
];

function csvEscape(value: unknown): string {
  if (value === null || value === undefined) return '';
  const s = String(value);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** Plain CSV — the simplest, most universally-compatible export. Excel opens this directly. */
export function exportTransactionsToCsv(rows: TransactionLogRow[]): string {
  const header = CSV_COLUMNS.join(',');
  const lines = rows.map((r) => CSV_COLUMNS.map((c) => csvEscape(r[c])).join(','));
  return [header, ...lines].join('\n');
}

/** Real .xlsx with a formatted header row — for when CSV's lack of styling isn't good enough. */
export async function exportTransactionsToXlsx(rows: TransactionLogRow[]): Promise<Buffer> {
  const workbook = new ExcelJS.Workbook();
  const sheet = workbook.addWorksheet('Transactions');
  sheet.columns = CSV_COLUMNS.map((c) => ({ header: c, key: c, width: c === 'txId' ? 40 : 20 }));
  sheet.getRow(1).font = { bold: true };
  for (const row of rows) {
    sheet.addRow(Object.fromEntries(CSV_COLUMNS.map((c) => [c, row[c]])));
  }
  const buffer = await workbook.xlsx.writeBuffer();
  return Buffer.from(buffer);
}
