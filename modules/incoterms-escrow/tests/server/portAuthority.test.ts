import fs from 'fs';
import os from 'os';
import path from 'path';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { DidWeb } from '@ublp/shared';
import { openSettlementDb, type SettlementDb } from '../../src/server/db.js';
import { resolvePortAuthorityKeyHash } from '../../src/server/portAuthority.js';

let dbPath: string;
let db: SettlementDb;

beforeEach(() => {
  dbPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'ublp-port-authority-db-')), 'settlement-agent.db');
  db = openSettlementDb(dbPath);
});

afterEach(() => {
  db.close();
  fs.rmSync(path.dirname(dbPath), { recursive: true, force: true });
  vi.unstubAllGlobals();
});

function mockFetchOnce(body: unknown): void {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => body,
    })
  );
}

const DID: DidWeb = 'did:web:liman.example.com';
const HASH_A = 'aa'.repeat(32);
const HASH_B = 'bb'.repeat(32);

describe('resolvePortAuthorityKeyHash (AGENTS.md 5.35 — did:web double-commitment check)', () => {
  it('first sighting of a domain: TOFU-trusts it and records it', async () => {
    mockFetchOnce({ portAuthorityKeyHashHex: HASH_A, did: DID });
    const result = await resolvePortAuthorityKeyHash(db, DID);
    expect(result.roleKeyHashHex).toBe(HASH_A);
    expect(result.domain).toBe('liman.example.com');
    expect(result.firstSeen).toBe(true);
  });

  it('second sighting with the SAME hash: passes, no longer firstSeen', async () => {
    mockFetchOnce({ portAuthorityKeyHashHex: HASH_A });
    await resolvePortAuthorityKeyHash(db, DID);

    mockFetchOnce({ portAuthorityKeyHashHex: HASH_A });
    const result = await resolvePortAuthorityKeyHash(db, DID);
    expect(result.firstSeen).toBe(false);
  });

  it('second sighting with a DIFFERENT hash throws (TOFU violation) instead of silently updating', async () => {
    mockFetchOnce({ portAuthorityKeyHashHex: HASH_A });
    await resolvePortAuthorityKeyHash(db, DID);

    mockFetchOnce({ portAuthorityKeyHashHex: HASH_B });
    await expect(resolvePortAuthorityKeyHash(db, DID)).rejects.toThrow(/TOFU violation/);

    // The original trusted hash must still be the one on record — the rejected attempt must
    // not have silently overwritten it.
    mockFetchOnce({ portAuthorityKeyHashHex: HASH_A });
    const result = await resolvePortAuthorityKeyHash(db, DID);
    expect(result.firstSeen).toBe(false);
  });

  it('rejects a document missing a valid portAuthorityKeyHashHex field', async () => {
    mockFetchOnce({ somethingElse: true });
    await expect(resolvePortAuthorityKeyHash(db, DID)).rejects.toThrow(/portAuthorityKeyHashHex/);
  });

  it('normalizes the host (case-folding via domainToASCII), so a mixed-case DID still keys the same TOFU record', async () => {
    mockFetchOnce({ portAuthorityKeyHashHex: HASH_A });
    await resolvePortAuthorityKeyHash(db, DID);

    mockFetchOnce({ portAuthorityKeyHashHex: HASH_A });
    const mixedCaseDid = 'did:web:LIMAN.example.com' as DidWeb;
    const result = await resolvePortAuthorityKeyHash(db, mixedCaseDid);
    expect(result.domain).toBe('liman.example.com');
    expect(result.firstSeen).toBe(false); // same normalized domain as the DID above, already trusted
  });
});
