import { beforeAll, afterAll } from 'vitest';

process.env.PROOF_MODE = 'dev';
process.env.MINISTRY_KEY_PASSPHRASE = '';
process.env.COMMITTEE_KEY_PASSPHRASE = '';

let serverCleanups: Array<() => Promise<void>> = [];

export function registerCleanup(fn: () => Promise<void>): void {
  serverCleanups.push(fn);
}

afterAll(async () => {
  for (const cleanup of serverCleanups) {
    try {
      await cleanup();
    } catch {
      // ignore cleanup errors
    }
  }
  serverCleanups = [];
});
