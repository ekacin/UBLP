/**
 * Funds an arbitrary external wallet address (e.g. the operator's own 1AM/Lace wallet, not one
 * of this repo's own AgentWallet instances) from the local devnet's genesis wallet — same
 * genesis seed and same shielded/unshielded split lifecycle-helpers.ts's
 * shieldFundsFromGenesis/fundUnshieldedAndRegisterDust use, just parsing a raw bech32m address
 * string (MidnightBech32m) instead of deriving the recipient from an AgentWallet object.
 *
 * Sends BOTH shielded NIGHT (to the mn_shield-addr_... address) and unshielded NIGHT (to the
 * mn_addr_... address). Deliberately does NOT attempt DUST registration for the recipient —
 * that requires signing with the recipient's own unshielded keystore, which only the wallet's
 * real owner has (this mirrors the public-testnet faucet's own two-step model: get tNIGHT here,
 * then use your own wallet's "Generate tDUST" feature).
 *
 *   npx tsx scripts/devnet/fund-external-wallet.ts <mn_addr_...> <mn_shield-addr_...> [amount]
 */
import * as Rx from 'rxjs';
import {
  shieldedToken,
  nativeToken,
  ZswapSecretKeys,
  DustSecretKey,
  LedgerParameters,
} from '@midnight-ntwrk/midnight-js-protocol/ledger';
import { FluentWalletBuilder } from '@midnight-ntwrk/testkit-js';
import { MidnightBech32m, ShieldedAddress, UnshieldedAddress } from '@midnight-ntwrk/wallet-sdk-address-format';
import { UndeployedNetworkConfig } from '../../src/deploy/networks.js';
import { waitForSync } from '../../src/deploy/wallet.js';

const GENESIS_SEED = '0000000000000000000000000000000000000000000000000000000000000001';

const [unshieldedAddrStr, shieldedAddrStr, amountArg] = process.argv.slice(2);
if (!unshieldedAddrStr || !shieldedAddrStr) {
  throw new Error(
    'Usage: npx tsx scripts/devnet/fund-external-wallet.ts <mn_addr_...> <mn_shield-addr_...> [amount]'
  );
}
const amount = BigInt(amountArg ?? '10000000000');

async function main() {
  const network = new UndeployedNetworkConfig();
  const networkId = network.networkId;

  const unshieldedAddress = MidnightBech32m.parse(unshieldedAddrStr).decode(UnshieldedAddress, networkId);
  const shieldedAddress = MidnightBech32m.parse(shieldedAddrStr).decode(ShieldedAddress, networkId);

  const { wallet: genesisWallet, seeds, keystore: genesisUnshieldedKeystore } = await FluentWalletBuilder.forEnvironment(
    network.envConfig()
  )
    .withDustOptions({ ledgerParams: LedgerParameters.initialParameters(), additionalFeeOverhead: 1_000n, feeBlocksMargin: 5 })
    .withSeed(GENESIS_SEED)
    .buildWithoutStarting();
  const genesisShieldedSecretKeys = ZswapSecretKeys.fromSeed(seeds.shielded);
  const genesisDustSecretKey = DustSecretKey.fromSeed(seeds.dust);
  await genesisWallet.start(genesisShieldedSecretKeys, genesisDustSecretKey);
  // The exact same wait deploy/wallet.ts's own waitForSync uses (shielded/unshielded/dust
  // progress, each isStrictlyComplete) — my first pass at this script filtered on a
  // `syncProgress.synced` field that doesn't exist on this state shape at all, so it just
  // hung forever with no error (no timeout either). Reusing the proven helper instead of
  // reinventing it.
  await waitForSync(genesisWallet as any);

  console.log(`Sending ${amount} shielded NIGHT -> ${shieldedAddrStr}`);
  const shieldedRecipe = await genesisWallet.transferTransaction(
    [{ type: 'shielded', outputs: [{ type: shieldedToken().raw, receiverAddress: shieldedAddress, amount }] }],
    { shieldedSecretKeys: genesisShieldedSecretKeys, dustSecretKey: genesisDustSecretKey },
    { ttl: new Date(Date.now() + 5 * 60_000), payFees: true }
  );
  const shieldedFinalized = await genesisWallet.finalizeRecipe(shieldedRecipe);
  const shieldedTxId = await genesisWallet.submitTransaction(shieldedFinalized);
  console.log(`  shielded tx submitted: ${shieldedTxId}`);

  console.log(`Sending ${amount} unshielded NIGHT -> ${unshieldedAddrStr}`);
  const unshieldedRecipe = await genesisWallet.transferTransaction(
    [{ type: 'unshielded', outputs: [{ type: nativeToken().raw, receiverAddress: unshieldedAddress, amount }] }],
    { shieldedSecretKeys: genesisShieldedSecretKeys, dustSecretKey: genesisDustSecretKey },
    { ttl: new Date(Date.now() + 5 * 60_000) }
  );
  const signed = await genesisWallet.signRecipe(unshieldedRecipe, (payload) => genesisUnshieldedKeystore.signData(payload));
  const unshieldedFinalized = await genesisWallet.finalizeRecipe(signed);
  const unshieldedTxId = await genesisWallet.submitTransaction(unshieldedFinalized);
  console.log(`  unshielded tx submitted: ${unshieldedTxId}`);

  await genesisWallet.stop();
  console.log('Done. Both transactions submitted — check your wallet in a moment.');
  console.log('To pay fees, use your wallet\'s own "Generate tDUST" / register-for-DUST feature on the unshielded NIGHT you just received — that step needs your own signing key, this script can\'t do it for you.');
}

main().catch((err) => {
  console.error('FAILED:', err);
  process.exit(1);
});
