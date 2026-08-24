/**
 * CLI entrypoint for one company's self-hosted settlement-agent instance (AGENTS.md 5.27).
 * Every config value comes from the environment — nothing here is UBLP-hosted or shared
 * across companies.
 *
 *   SETTLEMENT_ROLE=seller SETTLEMENT_DID=did:ublp:seller:acme-export \
 *     SETTLEMENT_PORT=4100 SETTLEMENT_PASSPHRASE=... \
 *     npm run start:settlement-agent -w @ublp/incoterms-escrow
 */

import { isUBLPDid } from '@ublp/shared';
import { startSettlementAgent } from '../src/server/index.js';
import type { AgentRole } from '../src/deploy/wallet.js';

const role = process.env.SETTLEMENT_ROLE as AgentRole | undefined;
if (role !== 'buyer' && role !== 'seller' && role !== 'port-authority') {
  throw new Error('SETTLEMENT_ROLE must be one of: buyer, seller, port-authority.');
}

const did = process.env.SETTLEMENT_DID;
if (!did || !isUBLPDid(did)) {
  throw new Error('SETTLEMENT_DID must be set to a valid did:ublp:... identifier for this company.');
}

const port = Number(process.env.SETTLEMENT_PORT ?? '4100');
const passphrase = process.env.SETTLEMENT_PASSPHRASE;
if (!passphrase) {
  throw new Error('SETTLEMENT_PASSPHRASE must be set — see AGENTS.md 5.21 on how production should source this.');
}

const agent = await startSettlementAgent({ role, did, port, passphrase });
console.log(`[settlement-agent] role=${role} listening on :${port}`);

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, async () => {
    console.log(`[settlement-agent] received ${signal}, shutting down...`);
    await agent.stop();
    process.exit(0);
  });
}
