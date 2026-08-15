/**
 * Task 17 (AGENTS.md 5.23): drives Escrow.compact through its full happy-path
 * state machine — propose -> lockEscrow -> attestLoadingConfirmed -> claimPayout — against
 * the real local devnet, with three separate real wallets (buyer/seller/port-authority),
 * real ZK proofs, and a real shielded coin actually moving on-chain.
 *
 * Unlike deploy-escrow.ts (which only sanity-checked propose()), this exercises every
 * circuit and every witness path, including the dual-recipient memo recovery (Section 5.18):
 * the "seller" role never independently knows the deposited coin's nonce/salt — it recovers
 * them by decrypting `buyerMemo` off the chain, exactly as a real seller agent would.
 */

import crypto from 'crypto';
import * as Rx from 'rxjs';
import { deployContract, findDeployedContract } from '@midnight-ntwrk/midnight-js-contracts';
import {
  persistentHash,
  CompactTypeBytes,
  CompactTypeVector,
} from '@midnight-ntwrk/compact-runtime';
import {
  createShieldedCoinInfo,
  shieldedToken,
  encodeShieldedCoinInfo,
} from '@midnight-ntwrk/midnight-js-protocol/ledger';
import { generateX25519KeyPair } from '@ublp/shared';
import { ledger, TimeoutDirection } from '../../contracts/managed/escrow/contract/index.js';
import {
  compiledEscrowContract,
  EscrowPrivateStateId,
  emptyEscrowPrivateState,
  zswapRecipient,
  type EscrowPrivateState,
} from '../../src/contract/index.js';
import { recoverBuyerMemo } from '../../src/contract/memo.js';
import { UndeployedNetworkConfig } from '../../src/deploy/networks.js';
import { buildAgentWallet, closeAgentWallet } from '../../src/deploy/wallet.js';
import { buildEscrowProviders } from '../../src/deploy/providers.js';
import { shieldFundsFromGenesis, waitForContractCoinMtIndex } from './lifecycle-helpers.js';

const PASSPHRASE = process.env.DEVNET_WALLET_PASSPHRASE ?? 'local-devnet-only-insecure-default';
const AGREED_AMOUNT = 1_000_000n; // Stars

function randomBytes32(): Uint8Array {
  return new Uint8Array(crypto.randomBytes(32));
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

/** TS mirror of Escrow.compact's `roleKeyHash` pure circuit — see contract for the source of
 * truth. Verified against the real on-chain result in step 0 below before being trusted for
 * portAuthorityKeyHash (which, unlike sellerKeyHash, is never re-derived on-chain — the caller
 * must supply the already-hashed value). */
function roleKeyHash(sk: Uint8Array, domain: string): Uint8Array {
  const domainBytes = Buffer.alloc(32);
  Buffer.from(domain, 'utf8').copy(domainBytes);
  const rtType = new CompactTypeVector(2, new CompactTypeBytes(32));
  return persistentHash(rtType, [domainBytes, Buffer.from(sk)]);
}

async function main(): Promise<void> {
  const network = new UndeployedNetworkConfig();

  console.log('Building wallets for buyer, seller, port-authority...');
  const seller = await buildAgentWallet('seller', network, PASSPHRASE);
  const buyer = await buildAgentWallet('buyer', network, PASSPHRASE);
  const portAuthority = await buildAgentWallet('port-authority', network, PASSPHRASE);

  // --- Step 0: validate the off-chain roleKeyHash replica against the real on-chain circuit ---
  console.log('\n[0] Validating off-chain roleKeyHash() against the real Compact circuit...');
  const sellerProviders = buildEscrowProviders(seller.midnightWalletProvider, network, seller.role);
  const deployed = await deployContract(sellerProviders, {
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: emptyEscrowPrivateState,
  });
  const contractAddress = deployed.deployTxData.public.contractAddress;
  console.log(`  Deployed at: ${contractAddress}`);

  const sellerSecretKey = randomBytes32();
  const sellerMemoKeyPair = generateX25519KeyPair();
  const buyerMemoKeyPair = generateX25519KeyPair();
  const portAuthoritySecretKey = randomBytes32();
  const portAuthKeyHash = roleKeyHash(portAuthoritySecretKey, 'incoterms-escrow:port-auth:v1');

  const amountSalt = randomBytes32();
  const sellerAddressSalt = randomBytes32();
  const deadlineAt = BigInt(Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60);

  const sellerPrivateState: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    sellerSecretKey,
    sellerAddress: zswapRecipient(hexToBytes(seller.midnightWalletProvider.getCoinPublicKey())),
    sellerAddressSalt,
    ownMemoPrivateKey: hexToBytes(sellerMemoKeyPair.privateKey),
    counterpartyMemoPublicKey: hexToBytes(buyerMemoKeyPair.publicKey),
    agreedAmount: AGREED_AMOUNT,
    agreedAmountSalt: amountSalt,
  };
  await sellerProviders.privateStateProvider.set(EscrowPrivateStateId, sellerPrivateState);

  console.log('  Calling propose()...');
  await deployed.callTx.propose(portAuthKeyHash, deadlineAt, TimeoutDirection.Buyer);

  const stateAfterPropose = ledger((await sellerProviders.publicDataProvider.queryContractState(contractAddress))!.data);
  const expectedSellerKeyHash = roleKeyHash(sellerSecretKey, 'incoterms-escrow:seller:v1');
  const onChainMatches = Buffer.from(stateAfterPropose.sellerKeyHash).equals(Buffer.from(expectedSellerKeyHash));
  console.log(`  state after propose(): ${stateAfterPropose.state} (expect 1=Proposed)`);
  console.log(`  off-chain roleKeyHash() replica matches on-chain sellerKeyHash: ${onChainMatches}`);
  if (!onChainMatches) {
    throw new Error('roleKeyHash() TS replica does not match the real circuit — portAuthorityKeyHash would be wrong.');
  }

  // --- Step 1: buyer shields funds, then locks them into the escrow ---
  console.log('\n[1] Buyer shielding funds and calling lockEscrow()...');
  await shieldFundsFromGenesis(network, buyer, AGREED_AMOUNT + 10_000n); // headroom for change

  const depositSalt = randomBytes32();
  const depositedCoinSdk = createShieldedCoinInfo(shieldedToken().raw, AGREED_AMOUNT);
  const depositedCoinEncoded = encodeShieldedCoinInfo(depositedCoinSdk) as any;

  const buyerAddressSalt = randomBytes32();
  const buyerPrivateState: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    depositedCoin: {
      nonce: hexToBytes(depositedCoinEncoded.nonce ?? depositedCoinSdk.nonce),
      color: hexToBytes(depositedCoinEncoded.color),
      value: AGREED_AMOUNT,
    },
    depositSalt,
    buyerAddress: zswapRecipient(hexToBytes(buyer.midnightWalletProvider.getCoinPublicKey())),
    buyerAddressSalt,
    ownMemoPrivateKey: hexToBytes(buyerMemoKeyPair.privateKey),
    counterpartyMemoPublicKey: hexToBytes(sellerMemoKeyPair.publicKey),
    agreedAmount: AGREED_AMOUNT,
    agreedAmountSalt: amountSalt,
  };

  const buyerProviders = buildEscrowProviders(buyer.midnightWalletProvider, network, buyer.role);
  const buyerContract = await findDeployedContract(buyerProviders, {
    contractAddress,
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: buyerPrivateState,
  });

  await buyerContract.callTx.lockEscrow();
  const stateAfterLock = ledger((await buyerProviders.publicDataProvider.queryContractState(contractAddress))!.data);
  console.log(`  state after lockEscrow(): ${stateAfterLock.state} (expect 2=Locked)`);

  const depositedCoinMtIndex = await waitForContractCoinMtIndex(network.indexer, contractAddress);
  console.log(`  deposited coin's real Merkle-tree mt_index: ${depositedCoinMtIndex}`);

  // --- Step 2: port authority attests loading confirmed ---
  console.log('\n[2] Port authority calling attestLoadingConfirmed()...');
  const portAuthorityProviders = buildEscrowProviders(portAuthority.midnightWalletProvider, network, portAuthority.role);
  const portAuthorityPrivateState: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    portAuthoritySecretKey,
  };
  const portAuthorityContract = await findDeployedContract(portAuthorityProviders, {
    contractAddress,
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: portAuthorityPrivateState,
  });
  await portAuthorityContract.callTx.attestLoadingConfirmed();
  const stateAfterAttest = ledger((await portAuthorityProviders.publicDataProvider.queryContractState(contractAddress))!.data);
  console.log(`  loadingConfirmed after attest: ${stateAfterAttest.loadingConfirmed} (expect true)`);

  // --- Step 3: seller recovers the deposited coin from buyerMemo (NOT copied out-of-band —
  // this is the real dual-recipient-memo recovery path, Section 5.18) and claims payout ---
  console.log('\n[3] Seller recovering buyerMemo and calling claimPayout()...');
  const recovered = recoverBuyerMemo(stateAfterAttest.buyerMemo, hexToBytes(sellerMemoKeyPair.privateKey), hexToBytes(buyerMemoKeyPair.publicKey));
  console.log(`  Recovered deposit salt matches buyer's original: ${Buffer.from(recovered.depositSalt).equals(Buffer.from(depositSalt))}`);
  console.log(`  Recovered coin value: ${recovered.coin.value} (expect ${AGREED_AMOUNT})`);

  // The coin's real Merkle-tree index was already resolved above via findContractCoinMtIndex
  // (mt_index=0 was tried first and failed with "invalid index into sparse merkle tree: 0" —
  // see AGENTS.md 5.23).
  const sellerClaimPrivateState: EscrowPrivateState = {
    ...emptyEscrowPrivateState,
    qualifiedCoin: { ...recovered.coin, mt_index: depositedCoinMtIndex },
    depositSalt: recovered.depositSalt,
    sellerAddress: sellerPrivateState.sellerAddress,
    sellerAddressSalt,
  };
  await sellerProviders.privateStateProvider.set(EscrowPrivateStateId, sellerClaimPrivateState);
  const sellerClaimContract = await findDeployedContract(sellerProviders, {
    contractAddress,
    compiledContract: compiledEscrowContract,
    privateStateId: EscrowPrivateStateId,
    initialPrivateState: sellerClaimPrivateState,
  });
  await sellerClaimContract.callTx.claimPayout();
  const stateAfterClaim = ledger((await sellerProviders.publicDataProvider.queryContractState(contractAddress))!.data);
  console.log(`  state after claimPayout(): ${stateAfterClaim.state} (expect 3=Released)`);

  const sellerStateAfter: any = await Rx.firstValueFrom(seller.wallet.state());
  console.log(`  seller's shielded balance after claim: ${sellerStateAfter.shielded?.balances?.[shieldedToken().raw] ?? 0n}`);

  await closeAgentWallet(seller);
  await closeAgentWallet(buyer);
  await closeAgentWallet(portAuthority);
  console.log('\nDone — full happy-path lifecycle completed successfully.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
