/**
 * Shared helpers for the devnet lifecycle scripts (full-lifecycle.ts, timeout-lifecycle.ts).
 * See AGENTS.md 5.23 for the SDK gotchas these helpers work around.
 */

import crypto from 'crypto';
import * as Rx from 'rxjs';
import {
  shieldedToken,
  ZswapSecretKeys,
  DustSecretKey,
  LedgerParameters,
} from '@midnight-ntwrk/midnight-js-protocol/ledger';
import { ShieldedAddress, ShieldedCoinPublicKey, ShieldedEncryptionPublicKey } from '@midnight-ntwrk/wallet-sdk-address-format';
import { FluentWalletBuilder } from '@midnight-ntwrk/testkit-js';
import { ZswapChainState } from '@midnight-ntwrk/ledger-v8';
import type { UndeployedNetworkConfig } from '../../src/deploy/networks.js';
import { waitForSync, type AgentWallet } from '../../src/deploy/wallet.js';

export function randomBytes32(): Uint8Array {
  return new Uint8Array(crypto.randomBytes(32));
}

export function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

// Same seed midnight-local-dev's genesis wallet uses — pre-funded with real shielded NIGHT
// (proven in AGENTS.md 5.22's independent shield-test: 250 trillion Stars available).
const GENESIS_SEED = '0000000000000000000000000000000000000000000000000000000000000001';

/** Funds `agent`'s own shielded address from the genesis wallet via a plain shielded-to-
 * shielded transfer. Deliberately sidesteps buyer's own unshielded->shielded conversion:
 * that path goes through WalletFacade.initSwap, which builds a cross-pool atomic swap whose
 * NIGHT-value balancing this SDK generation does not handle transparently for app code (the
 * node rejected it with an InvariantViolation(NightBalance(...)) — see AGENTS.md 5.23, still
 * unresolved). A same-pool shielded transfer from an already-shielded source avoids that
 * entirely, and is strictly simpler than the receiveShielded call already proven to work in
 * the standalone shield-test. */
export async function shieldFundsFromGenesis(network: UndeployedNetworkConfig, agent: AgentWallet, amount: bigint): Promise<void> {
  const { wallet: genesisWallet, seeds } = await FluentWalletBuilder.forEnvironment(network.envConfig())
    .withDustOptions({ ledgerParams: LedgerParameters.initialParameters(), additionalFeeOverhead: 1_000n, feeBlocksMargin: 5 })
    .withSeed(GENESIS_SEED)
    .buildWithoutStarting();
  const genesisShieldedSecretKeys = ZswapSecretKeys.fromSeed(seeds.shielded);
  const genesisDustSecretKey = DustSecretKey.fromSeed(seeds.dust);
  await genesisWallet.start(genesisShieldedSecretKeys, genesisDustSecretKey);
  await waitForSync(genesisWallet);

  const cpk = ShieldedCoinPublicKey.fromHexString(agent.shieldedSecretKeys.coinPublicKey);
  const epk = ShieldedEncryptionPublicKey.fromHexString(agent.shieldedSecretKeys.encryptionPublicKey);
  const recipientShieldedAddress = new ShieldedAddress(cpk, epk);

  const recipe = await genesisWallet.transferTransaction(
    [{ type: 'shielded', outputs: [{ type: shieldedToken().raw, receiverAddress: recipientShieldedAddress, amount }] }],
    { shieldedSecretKeys: genesisShieldedSecretKeys, dustSecretKey: genesisDustSecretKey },
    { ttl: new Date(Date.now() + 5 * 60_000), payFees: true }
  );
  const finalized = await genesisWallet.finalizeRecipe(recipe);
  const txId = await genesisWallet.submitTransaction(finalized);
  console.log(`  [genesis -> ${agent.role}] shield tx submitted: ${txId}`);

  await Rx.firstValueFrom(
    agent.wallet.state().pipe(
      Rx.filter((s: any) => (s.shielded?.balances?.[shieldedToken().raw] ?? 0n) >= amount),
      Rx.timeout({ each: 120_000, with: () => Rx.throwError(() => new Error('Timed out waiting for shielded balance to land')) })
    )
  );
  console.log(`  [${agent.role}] shielded balance confirmed >= ${amount}`);
  await genesisWallet.stop();
}

/** The contract-scoped zswapState's `first_free` field stays 0 even long after a real coin
 * has landed (confirmed by direct inspection — see AGENTS.md 5.23: this looks like stale
 * metadata specific to the filtered/serialized snapshot, not a real "empty tree" signal).
 * midnight-js-contracts' own claimPayout/releaseOnTimeout call path hits the exact same field
 * via queryZSwapAndContractState, so mt_index=firstFree-1 fails there too ("invalid index into
 * sparse merkle tree"). The coin's REAL index is visible directly in the sparse tree's
 * toString(true) dump — e.g. `46: (<commitment>, Some(ContractAddress(<our address>)))` — so
 * this greps that dump for the entry whose ContractAddress matches ours. */
export async function findContractCoinMtIndex(indexerUrl: string, contractAddress: string): Promise<bigint | null> {
  const res = await fetch(indexerUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      query: `query($address: HexEncoded!) { contractAction(address: $address) { zswapState } }`,
      variables: { address: contractAddress },
    }),
  });
  const payload = (await res.json()) as any;
  const zswapStateHex: string | undefined = payload?.data?.contractAction?.zswapState;
  if (!zswapStateHex) return null;
  const state = ZswapChainState.deserialize(hexToBytes(zswapStateHex));
  const dump = state.toString(true);
  const pattern = new RegExp(`(\\d+): \\([0-9a-f]+, Some\\(ContractAddress\\(${contractAddress}\\)\\)\\)`);
  const match = dump.match(pattern);
  return match ? BigInt(match[1]) : null;
}

/** Polls findContractCoinMtIndex until the indexer has caught up with a just-landed deposit. */
export async function waitForContractCoinMtIndex(indexerUrl: string, contractAddress: string, maxAttempts = 30): Promise<bigint> {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const mtIndex = await findContractCoinMtIndex(indexerUrl, contractAddress);
    if (mtIndex !== null) return mtIndex;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  throw new Error('Could not find the deposited coin in the indexed zswap state.');
}
