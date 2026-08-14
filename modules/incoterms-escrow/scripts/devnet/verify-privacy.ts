/**
 * Rigorous privacy check (AGENTS.md 5.22 follow-up): deploys, calls propose() with fully
 * KNOWN plaintext secrets, then dumps the contract's ENTIRE raw on-chain state (not just the
 * friendly `ledger()` getters, which only exist for `export`ed fields) and searches that raw
 * dump for the literal plaintext secrets. If privacy holds, none of them should appear
 * anywhere — only their persistentCommit hashes / memo ciphertext should.
 *
 * Why this and not just reading `ledger()`: `export` only controls whether a convenience
 * getter exists in the generated TS bindings — it does NOT control what's physically stored
 * in the state tree (see AGENTS.md 5.14.1). Dumping the raw StateValue and grepping for known
 * secrets is a much harder test to fool than trusting the typed accessors.
 */

import crypto from 'crypto';
import { deployContract } from '@midnight-ntwrk/midnight-js-contracts';
import { generateX25519KeyPair } from '@ublp/shared';
import { TimeoutDirection } from '../../contracts/managed/escrow/contract/index.js';
import {
  compiledEscrowContract,
  EscrowPrivateStateId,
  emptyEscrowPrivateState,
  zswapRecipient,
  type EscrowPrivateState,
} from '../../src/contract/index.js';
import { UndeployedNetworkConfig } from '../../src/deploy/networks.js';
import { buildAgentWallet, closeAgentWallet } from '../../src/deploy/wallet.js';
import { buildEscrowProviders } from '../../src/deploy/providers.js';

const PASSPHRASE = process.env.DEVNET_WALLET_PASSPHRASE ?? 'local-devnet-only-insecure-default';

function randomBytes32(): Uint8Array {
  return new Uint8Array(crypto.randomBytes(32));
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

async function main(): Promise<void> {
  const network = new UndeployedNetworkConfig();

  console.log('Building seller wallet...');
  const seller = await buildAgentWallet('seller', network, PASSPHRASE);
  const providers = buildEscrowProviders(seller.midnightWalletProvider, network, seller.role);

  console.log('Deploying Escrow.compact...');
  const deployed = await deployContract(providers, {
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: emptyEscrowPrivateState,
  });
  const contractAddress = deployed.deployTxData.public.contractAddress;
  console.log(`Deployed at: ${contractAddress}`);

  // --- KNOWN plaintext secrets — the exact values we expect to NEVER appear on-chain ---
  const buyerMemoKeys = generateX25519KeyPair();
  const sellerMemoKeys = generateX25519KeyPair();
  const sellerCoinPublicKeyHex = seller.midnightWalletProvider.getCoinPublicKey();
  const sellerAddressSalt = randomBytes32();
  const agreedAmount = 1_000_000n;
  const agreedAmountSalt = randomBytes32();

  const sellerPrivateState: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    sellerSecretKey: randomBytes32(),
    sellerAddress: zswapRecipient(hexToBytes(sellerCoinPublicKeyHex)),
    sellerAddressSalt,
    ownMemoPrivateKey: hexToBytes(sellerMemoKeys.privateKey),
    counterpartyMemoPublicKey: hexToBytes(buyerMemoKeys.publicKey),
    agreedAmount,
    agreedAmountSalt,
  };

  console.log('Calling propose()...');
  await providers.privateStateProvider.set(EscrowPrivateStateId, sellerPrivateState);
  await deployed.callTx.propose(
    randomBytes32(),
    BigInt(Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60),
    TimeoutDirection.Buyer
  );

  // --- Dump the ENTIRE raw on-chain state and search for the plaintext secrets above ---
  const contractState = await providers.publicDataProvider.queryContractState(contractAddress);
  if (contractState === null) throw new Error('Contract state not found.');
  const rawDump = (contractState.data as unknown as { state: { toString: (compact?: boolean) => string } })
    .state.toString(false);

  console.log(`\nRaw on-chain state dump length: ${rawDump.length} chars`);
  console.log('--- first 1500 chars ---');
  console.log(rawDump.slice(0, 1500));

  const secretsToCheck: Array<[string, string]> = [
    ['seller coin public key (hex)', sellerCoinPublicKeyHex.toLowerCase()],
    ['seller address salt (hex)', Buffer.from(sellerAddressSalt).toString('hex')],
    ['agreed amount, decimal (1000000)', agreedAmount.toString()],
    ['agreed amount, hex (0xf4240)', agreedAmount.toString(16)],
    ['agreed amount salt (hex)', Buffer.from(agreedAmountSalt).toString('hex')],
    ['seller memo private key (hex)', sellerMemoKeys.privateKey.toLowerCase()],
    ['buyer memo private key (hex)', buyerMemoKeys.privateKey.toLowerCase()],
  ];

  console.log('\n--- Leak check: none of these should appear in the raw on-chain state ---');
  let anyLeak = false;
  for (const [label, needle] of secretsToCheck) {
    const found = rawDump.toLowerCase().includes(needle);
    console.log(`${found ? 'LEAKED  ' : 'clean   '} ${label}`);
    if (found) anyLeak = true;
  }

  if (anyLeak) {
    console.error('\nPRIVACY CHECK FAILED — a plaintext secret appeared in the raw on-chain state.');
    process.exitCode = 1;
  } else {
    console.log('\nPRIVACY CHECK PASSED — no plaintext secret found anywhere in the raw on-chain state.');
  }

  await closeAgentWallet(seller);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
