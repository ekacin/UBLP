/**
 * First real end-to-end exercise of the settlement-agent HTTP layer itself — not just the
 * underlying contract calls, which full-lifecycle.ts/timeout-lifecycle.ts/negative-scenarios.ts
 * already proved. Those scripts call proposeDeal/lockDeal etc. as plain TS functions; nothing
 * so far has ever driven auth.ts, routes.ts, or watcher.ts through a real HTTP request. This
 * script starts three real settlement-agent processes (in-process, one per role, against local
 * devnet), logs in to each via the real wallet-signature challenge-response flow, and drives
 * one deal through propose -> approve -> lock -> approve -> attest -> (watcher auto-claims,
 * unattended) purely through the same HTTP API a real panel/ERP would use.
 *
 * Explicitly tests the "two separate companies on two separate networks" assumption, not just
 * the happy path: step [4a] takes the seller's exact signed offer, tampers with it (as a
 * compromised/malicious relay channel would), and confirms the buyer's agent rejects it via
 * acceptEscrow() before ever touching the chain — proving the signed-EscrowTerms model
 * actually defends against a channel that isn't trusted, not just one that happens to be
 * this script calling both sides' APIs directly for convenience.
 */

import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { startSettlementAgent } from '../../src/server/index.js';
import { loadOrCreateSettlementIdentity } from '../../src/server/identity.js';
import { UndeployedNetworkConfig } from '../../src/deploy/networks.js';
import { buildAgentWallet, closeAgentWallet } from '../../src/deploy/wallet.js';
import { shieldFundsFromGenesis, fundUnshieldedAndRegisterDust } from './lifecycle-helpers.js';

const PASSPHRASE = process.env.DEVNET_WALLET_PASSPHRASE ?? 'local-devnet-only-insecure-default';
const AGREED_AMOUNT = '1000000';
const WATCHER_INTERVAL_MS = 5_000;

type Role = 'seller' | 'buyer' | 'port-authority';

function signHashHex(hashHex: string, privateKeyPem: string): string {
  return crypto.sign(null, Buffer.from(hashHex, 'hex'), { key: privateKeyPem, dsaEncoding: 'ieee-p1363' }).toString('base64');
}

interface AgentHandle {
  role: Role;
  baseUrl: string;
  sessionToken: string;
}

async function login(baseUrl: string, secretsDir: string, role: Role): Promise<string> {
  const identity = loadOrCreateSettlementIdentity(secretsDir, role, PASSPHRASE);
  const challengeRes = await fetch(`${baseUrl}/auth/challenge`, { method: 'POST' });
  const { challengeId, nonceHex } = (await challengeRes.json()) as { challengeId: string; nonceHex: string };
  const signature = signHashHex(nonceHex, identity.loginKeyPair.privateKey);
  const verifyRes = await fetch(`${baseUrl}/auth/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ challengeId, signature }),
  });
  if (!verifyRes.ok) throw new Error(`login failed for ${role}: ${verifyRes.status} ${await verifyRes.text()}`);
  const { sessionToken } = (await verifyRes.json()) as { sessionToken: string };
  return sessionToken;
}

async function api(agent: AgentHandle, method: string, urlPath: string, body?: unknown): Promise<any> {
  const res = await fetch(`${agent.baseUrl}${urlPath}`, {
    method,
    headers: {
      authorization: `Bearer ${agent.sessionToken}`,
      ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  const json = text ? JSON.parse(text) : undefined;
  if (!res.ok) throw new Error(`${method} ${urlPath} -> ${res.status}: ${text}`);
  return json;
}

async function main(): Promise<void> {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ublp-e2e-settlement-'));
  const network = new UndeployedNetworkConfig();

  // Fund all three roles' wallets — not just buyer's deposit — before starting the agent
  // processes. Two genuinely separate things are needed here, and conflating them is exactly
  // what earlier attempts got wrong:
  //
  //   1. Shielded NIGHT (shieldFundsFromGenesis) — what the escrow contract itself moves/holds.
  //      Buyer needs an exact-amount coin for the deposit (lockEscrow checks the deposited
  //      coin's value == agreedAmount exactly).
  //   2. DUST (fundUnshieldedAndRegisterDust) — what pays transaction fees. DUST is generated
  //      only from **unshielded** NIGHT UTXOs that have been explicitly registered on-chain via
  //      registerNightUtxosForDustGeneration (confirmed by reading midnight-local-dev's own
  //      src/wallet.ts — the same tool its --fund-config flow uses). Shielded NIGHT can never be
  //      registered for DUST generation, no matter the amount or how long you wait: every
  //      earlier attempt that funded agents via shieldFundsFromGenesis alone and then just
  //      waited failed with "Insufficient Funds: could not balance dust", because there was
  //      never any unshielded UTXO to register in the first place.
  //
  // fundUnshieldedAndRegisterDust itself blocks until a spendable DUST coin actually appears
  // (DUST accrues over real chain time once registered — it isn't instant), so no separate
  // blind sleep is needed here afterward.
  const DUST_BOOTSTRAP_AMOUNT = 50_000_000_000n; // 50,000 NIGHT, in Stars (1 NIGHT = 10^6 Stars)
  console.log('[setup] Funding buyer/seller/port-authority test wallets (NIGHT + DUST registration)...');
  for (const role of ['buyer', 'seller', 'port-authority'] as const) {
    const fundingWallet = await buildAgentWallet(role, network, PASSPHRASE);
    await fundUnshieldedAndRegisterDust(network, fundingWallet, DUST_BOOTSTRAP_AMOUNT);
    if (role === 'buyer') {
      await shieldFundsFromGenesis(network, fundingWallet, BigInt(AGREED_AMOUNT) + 10_000n);
    }
    await closeAgentWallet(fundingWallet);
  }

  console.log('\n[setup] Starting three settlement-agent processes (seller:4100, buyer:4101, port-authority:4102)...');
  const sellerAgentProc = await startSettlementAgent({
    role: 'seller',
    did: 'did:ublp:seller:e2e-acme-export',
    port: 4100,
    passphrase: PASSPHRASE,
    secretsDir: path.join(tmpRoot, 'seller-secrets'),
    dataDir: path.join(tmpRoot, 'seller-data'),
    watcherIntervalMs: WATCHER_INTERVAL_MS,
  });
  const buyerAgentProc = await startSettlementAgent({
    role: 'buyer',
    did: 'did:ublp:buyer:e2e-acme-import',
    port: 4101,
    passphrase: PASSPHRASE,
    secretsDir: path.join(tmpRoot, 'buyer-secrets'),
    dataDir: path.join(tmpRoot, 'buyer-data'),
    watcherIntervalMs: WATCHER_INTERVAL_MS,
  });
  const portAuthorityAgentProc = await startSettlementAgent({
    role: 'port-authority',
    did: 'did:ublp:port-authority:e2e-pendik-roro',
    port: 4102,
    passphrase: PASSPHRASE,
    secretsDir: path.join(tmpRoot, 'port-authority-secrets'),
    dataDir: path.join(tmpRoot, 'port-authority-data'),
  });
  console.log('  All three agents started and wallets synced.');

  try {
    console.log('\n[0] Logging in to each agent via wallet-signature challenge-response (real HTTP)...');
    const seller: AgentHandle = {
      role: 'seller',
      baseUrl: 'http://127.0.0.1:4100',
      sessionToken: await login('http://127.0.0.1:4100', path.join(tmpRoot, 'seller-secrets'), 'seller'),
    };
    const buyer: AgentHandle = {
      role: 'buyer',
      baseUrl: 'http://127.0.0.1:4101',
      sessionToken: await login('http://127.0.0.1:4101', path.join(tmpRoot, 'buyer-secrets'), 'buyer'),
    };
    const portAuthority: AgentHandle = {
      role: 'port-authority',
      baseUrl: 'http://127.0.0.1:4102',
      sessionToken: await login('http://127.0.0.1:4102', path.join(tmpRoot, 'port-authority-secrets'), 'port-authority'),
    };
    console.log('  All three logged in, session tokens issued.');

    // Only PUBLIC values are exchanged this way (memo public keys, C's role-key hash) —
    // tampering with any of these in transit is self-defeating (breaks a hash check or breaks
    // the tamperer's own memo decryption later), so a plain fetch (or a manual out-of-band
    // relay, in a real cross-company deployment) is fine. The AMOUNT/SALT/DEADLINE never
    // travel this way — see [2]-[4] below.
    console.log('\n[1] Off-chain negotiation — public values only (memo key, C key hash)...');
    const { portAuthorityKeyHashHex } = await api(portAuthority, 'GET', '/identity/port-authority-key-hash');
    const { memoPublicKeyHex: buyerMemoPublicKeyHex } = await api(buyer, 'GET', '/identity/memo-public-key');
    console.log(`  portAuthorityKeyHashHex: ${portAuthorityKeyHashHex.slice(0, 16)}...`);

    console.log('\n[2] Seller: POST /deals/propose — builds + SIGNS EscrowTerms, queued for approval...');
    const proposePending = await api(seller, 'POST', '/deals/propose', {
      shipmentId: `e2e-${Date.now()}`,
      buyerDid: 'did:ublp:buyer:e2e-acme-import',
      portAuthorityDid: 'did:ublp:port-authority:e2e-pendik-roro',
      portAuthorityKeyHashHex,
      incoterm: 'FOB',
      // Real ZK proof generation for propose/lock/attest each took 30-45s in earlier runs —
      // needs to comfortably outlast all three plus negotiation overhead, or the watcher's
      // legitimate deadline check can race attest() landing on-chain.
      durationSeconds: 180,
      agreedAmount: AGREED_AMOUNT,
      buyerMemoPublicKeyHex,
    });
    console.log(`  pending action #${proposePending.id}, status: ${proposePending.status}`);

    console.log('\n[3] Seller: POST /deals/pending/:id/approve — real propose() on chain + signs the offer...');
    const proposeApproved = await api(seller, 'POST', `/deals/pending/${proposePending.id}/approve`);
    console.log(`  status: ${proposeApproved.status}, contractAddress: ${proposeApproved.contractAddress}, txId: ${proposeApproved.txId}`);
    const contractAddress: string = proposeApproved.contractAddress;
    // This is the whole point of the fix: `proposal` is a self-contained, signed blob — in a
    // real deployment this is what the seller's operator exports and relays to the buyer's
    // operator over whatever channel the two companies already use (email, EDI, ...). Neither
    // agent needs to be able to reach the other's API for this step to work.
    const proposal = proposeApproved.proposal;
    console.log(`  signed proposal ready to relay out-of-band (sellerSignature: ${proposal.sellerSignature.slice(0, 24)}...)`);

    console.log('\n[4a] Adversarial-channel check: a TAMPERED copy of the relayed offer must be rejected...');
    const tamperedProposal = { ...proposal, terms: { ...proposal.terms, amount: '1' } };
    const tamperedAttempt = await fetch(`${buyer.baseUrl}/deals/lock`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${buyer.sessionToken}` },
      body: JSON.stringify({ contractAddress, proposal: tamperedProposal }),
    });
    console.log(`  lock attempt with tampered proposal -> HTTP ${tamperedAttempt.status} (expect 202 — queued, rejection happens at /approve)`);
    const tamperedPending = await tamperedAttempt.json();
    const tamperedApproveRes = await fetch(`${buyer.baseUrl}/deals/pending/${tamperedPending.id}/approve`, {
      method: 'POST',
      headers: { authorization: `Bearer ${buyer.sessionToken}` },
    });
    console.log(`  approving the tampered pending action -> HTTP ${tamperedApproveRes.status} (expect 502 — acceptEscrow rejects it)`);
    if (tamperedApproveRes.status !== 502) {
      throw new Error('A tampered EscrowProposal was NOT rejected — the signature check is not doing its job.');
    }
    const tamperedBody = await tamperedApproveRes.json();
    console.log(`  rejected as expected: ${tamperedBody.message}`);

    console.log('\n[4b] Buyer: POST /deals/lock with the REAL (untampered) relayed proposal...');
    const lockPending = await api(buyer, 'POST', '/deals/lock', { contractAddress, proposal });
    console.log(`  pending action #${lockPending.id}, status: ${lockPending.status}`);

    console.log("\n[4c] Sanity check: re-submitting the SAME lock while it's in flight must be refused...");
    const dup = await fetch(`${buyer.baseUrl}/deals/lock`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${buyer.sessionToken}` },
      body: JSON.stringify({ contractAddress, proposal }),
    });
    console.log(`  duplicate lock attempt -> HTTP ${dup.status} (expect 409)`);
    if (dup.status !== 409) throw new Error('Expected the in-flight duplicate-lock guard to return 409.');

    console.log('\n[5] Buyer: POST /deals/pending/:id/approve — real lockEscrow() on chain...');
    const lockApproved = await api(buyer, 'POST', `/deals/pending/${lockPending.id}/approve`);
    console.log(`  status: ${lockApproved.status}, txId: ${lockApproved.txId}`);

    console.log('\n[6] Port authority: POST /deals/:address/attest (immediate, no approval gate)...');
    const attestResult = await api(portAuthority, 'POST', `/deals/${contractAddress}/attest`);
    console.log(`  txId: ${attestResult.txId}`);

    console.log("\n[7] Waiting for the seller agent's watcher to auto-claim (NO manual /claim call made)...");
    let released = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      const status = await api(seller, 'GET', `/deals/${contractAddress}/status`);
      console.log(`  poll ${attempt}: state=${status.state} (expect 3=Released), milestoneConfirmed=${status.milestoneConfirmed}`);
      if (status.state === 3) {
        released = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 3000));
    }
    if (!released) throw new Error('Watcher did not auto-claim within the timeout — something is wrong, see watcher.ts.');

    console.log('\nDone — deal auto-claimed by the watcher with zero manual /claim call.');
    console.log('Settlement-agent HTTP layer (auth, pending-approval queue, watcher) verified end-to-end.');
  } finally {
    await sellerAgentProc.stop();
    await buyerAgentProc.stop();
    await portAuthorityAgentProc.stop();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
