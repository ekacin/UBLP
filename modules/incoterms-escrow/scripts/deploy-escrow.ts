/**
 * First real contact with the local devnet (AGENTS.md 5.21, task 14): deploys Escrow.compact
 * and reads back its initial ledger state, to prove the wallet/provider layer built in
 * src/deploy actually works end to end — not just that it type-checks.
 *
 * Deploying doesn't require any particular role (no constructor logic sets role-specific
 * state — that only happens in propose()), so any funded wallet can do it. Uses "seller"
 * since that's the role that calls propose() next in the real flow.
 */

import crypto from 'crypto';
import { deployContract } from '@midnight-ntwrk/midnight-js-contracts';
import { generateX25519KeyPair } from '@ublp/shared';
import { ledger, TimeoutDirection } from '../contracts/managed/escrow/contract/index.js';
import {
  compiledEscrowContract,
  EscrowPrivateStateId,
  emptyEscrowPrivateState,
  zswapRecipient,
  type EscrowPrivateState,
} from '../src/contract/index.js';
import { UndeployedNetworkConfig } from '../src/deploy/networks.js';
import { buildAgentWallet, closeAgentWallet } from '../src/deploy/wallet.js';
import { buildEscrowProviders } from '../src/deploy/providers.js';

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

  console.log('Assembling providers...');
  const providers = buildEscrowProviders(seller.midnightWalletProvider, network, seller.role);

  console.log('Deploying Escrow.compact...');
  const deployed = await deployContract(providers, {
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: emptyEscrowPrivateState,
  });

  const contractAddress = deployed.deployTxData.public.contractAddress;
  console.log(`Deployed at: ${contractAddress}`);

  const contractState = await providers.publicDataProvider.queryContractState(contractAddress);
  if (contractState === null) {
    throw new Error('Deployed contract not found via publicDataProvider — something is wrong.');
  }

  const initialState = ledger(contractState.data);
  console.log('Initial ledger state:', {
    state: initialState.state,
    loadingConfirmed: initialState.loadingConfirmed,
  });

  // --- propose() sanity call ---
  // Throwaway values: this script only proves the deploy+call machinery works, not a real
  // negotiated deal (a real EscrowTerms exchange would supply the buyer's actual memo public
  // key, portAuthKeyHash, deadline, etc. — see escrow.ts / AGENTS.md 5.18-5.20).
  const buyerMemoKeys = generateX25519KeyPair();
  const sellerMemoKeys = generateX25519KeyPair();
  const sellerCoinPublicKey = seller.midnightWalletProvider.getCoinPublicKey();

  const sellerPrivateState: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    sellerSecretKey: randomBytes32(),
    sellerAddress: zswapRecipient(hexToBytes(sellerCoinPublicKey)),
    sellerAddressSalt: randomBytes32(),
    ownMemoPrivateKey: hexToBytes(sellerMemoKeys.privateKey),
    counterpartyMemoPublicKey: hexToBytes(buyerMemoKeys.publicKey),
    agreedAmount: 1_000_000n,
    agreedAmountSalt: randomBytes32(),
  };

  console.log('Calling propose()...');
  await providers.privateStateProvider.set(EscrowPrivateStateId, sellerPrivateState);

  const proposeResult = await deployed.callTx.propose(
    randomBytes32(),
    BigInt(Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60),
    TimeoutDirection.Buyer
  );
  console.log(`propose() tx: ${proposeResult.public.txId}`);

  const stateAfterPropose = ledger(
    (await providers.publicDataProvider.queryContractState(contractAddress))!.data
  );
  console.log('Ledger state after propose():', {
    state: stateAfterPropose.state,
    loadingConfirmed: stateAfterPropose.loadingConfirmed,
  });

  await closeAgentWallet(seller);
  console.log('Done.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
