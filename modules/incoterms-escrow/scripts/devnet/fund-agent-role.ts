/**
 * Funds a running (or about-to-run) settlement-agent's own wallet — the one derived from
 * deploy/wallet.ts's buildAgentWallet (fixed `.devnet-secrets/<role>.json` mnemonic, same
 * wallet regardless of SETTLEMENT_SECRETS_DIR, which only affects identity.ts's off-chain
 * secrets). Reuses lifecycle-helpers.ts's proven shieldFundsFromGenesis +
 * fundUnshieldedAndRegisterDust — the same funding path full-lifecycle.ts already exercises,
 * just targeting one already-generated role's wallet directly instead of a full deal run.
 *
 *   npx tsx scripts/devnet/fund-agent-role.ts <role> [amount-in-stars]
 */
import { buildAgentWallet, closeAgentWallet } from '../../src/deploy/wallet.js';
import { UndeployedNetworkConfig } from '../../src/deploy/networks.js';
import { shieldFundsFromGenesis, fundUnshieldedAndRegisterDust } from './lifecycle-helpers.js';
import type { AgentRole } from '../../src/deploy/wallet.js';

const [role, amountArg] = process.argv.slice(2);
if (role !== 'buyer' && role !== 'seller' && role !== 'port-authority') {
  throw new Error('Usage: npx tsx scripts/devnet/fund-agent-role.ts <buyer|seller|port-authority> [amount-in-stars]');
}
const amount = BigInt(amountArg ?? '10000000000');
const passphrase = process.env.SETTLEMENT_PASSPHRASE ?? 'local-devnet-only-insecure-default';

async function main() {
  const network = new UndeployedNetworkConfig();
  console.log(`Loading ${role}'s own wallet (.devnet-secrets/${role}.json)...`);
  const agent = await buildAgentWallet(role as AgentRole, network, passphrase);

  console.log(`Shielding ${amount} NIGHT into ${role}'s shielded balance...`);
  await shieldFundsFromGenesis(network, agent, amount);

  console.log(`Funding + registering ${amount} unshielded NIGHT for DUST generation on ${role}...`);
  await fundUnshieldedAndRegisterDust(network, agent, amount);

  await closeAgentWallet(agent);
  console.log(`Done. ${role}'s running agent process should pick this up on its own next sync — no restart needed.`);
}

main().catch((err) => {
  console.error('FAILED:', err);
  process.exit(1);
});
