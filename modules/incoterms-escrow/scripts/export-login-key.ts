/**
 * Prints this agent's login private key PEM (AGENTS.md 5.26) so an operator can paste it
 * into the settlement panel (panel/src/pages/Login.tsx) — the panel has no way to reach this
 * agent's encrypted secrets store itself, and shouldn't; this is a one-time, operator-run,
 * local step, matching the same env-var conventions as start-settlement-agent.ts.
 *
 *   SETTLEMENT_ROLE=seller SETTLEMENT_PASSPHRASE=... \
 *     npx tsx scripts/export-login-key.ts -w @ublp/incoterms-escrow
 *
 * Never pipe this over a network or paste it anywhere but the panel running on this same
 * operator's machine — whoever holds this PEM can act as this agent's operator.
 */

import path from 'path';
import { fileURLToPath } from 'url';
import { loadOrCreateSettlementIdentity } from '../src/server/identity.js';
import type { AgentRole } from '../src/deploy/wallet.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const role = process.env.SETTLEMENT_ROLE as AgentRole | undefined;
if (role !== 'buyer' && role !== 'seller' && role !== 'port-authority') {
  throw new Error('SETTLEMENT_ROLE must be one of: buyer, seller, port-authority.');
}

const passphrase = process.env.SETTLEMENT_PASSPHRASE;
if (!passphrase) {
  throw new Error('SETTLEMENT_PASSPHRASE must be set — the same value used to start this agent.');
}

// Matches server/index.ts's default secretsDir resolution exactly, so this always reads the
// same store the running agent itself uses.
const secretsDir = path.join(__dirname, '..', '.settlement-secrets');

const identity = loadOrCreateSettlementIdentity(secretsDir, role, passphrase);

console.log(`# Login key for role=${role} — paste the PEM below into the settlement panel.`);
console.log(identity.loginKeyPair.privateKey);
