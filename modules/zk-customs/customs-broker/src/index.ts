/**
 * Customs Broker — one-shot smoke-test script (`npm run smoke`).
 *
 * NOT the module's entrypoint anymore — `server.ts` (`npm start`/`npm run dev`) is the real,
 * persistent backend with human review gates at both Ministry and Broker (see the
 * backend-foundation plan). This script exercises Ministry's new review-then-sign flow and the
 * unchanged Agent -> Committee -> L2 leg directly, without going through Broker's own server/
 * poller — useful to isolate whether Ministry/Agent/Committee/L2 are wired correctly on their
 * own. It plays both parts of Ministry's human gate itself (submits, then immediately logs in
 * and approves as the officer) so it can still run start-to-finish as a single script.
 *
 * Flow:
 *   1. Prepare the customs document (including holderDid)
 *   2. Ministry → submit for review (API key), then approve as the officer (session login)
 *   3. UBLP Agent → send the resulting VC, get a Verifiable Presentation (VP) + L2 result
 */

import crypto from 'crypto';
import {
  UBLPVerifiableCredential,
  UBLPVerifiablePresentation,
  L2SettleResponse,
} from '@ublp/zk-customs-types';

const MINISTRY_URL = process.env.MINISTRY_URL ?? 'http://localhost:3001';
const MINISTRY_API_KEY = process.env.MINISTRY_BROKER_API_KEY ?? '';
const MINISTRY_OPERATOR_PASSPHRASE = process.env.MINISTRY_OPERATOR_PASSPHRASE ?? '';
const UBLP_AGENT_URL = process.env.UBLP_AGENT_URL ?? 'http://localhost:3002';
const AGENT_DID = process.env.AGENT_DID ?? 'did:ublp:agent:default';

async function run(): Promise<void> {
  // ─── 1. Customs Document ────────────────────────────────────────────────────
  const customsDocument = {
    documentId: `DOC-${crypto.randomUUID()}`,
    holderDid: AGENT_DID,
    exporterName: 'ACME Lojistik A.Ş.',
    exporterTaxId: '1234567890',
    importerName: 'Global Trade GmbH',
    importerVatId: 'DE987654321',
    goodsDescription: 'Elektronik Ekipman (Laptop, Sunucu Bileşenleri)',
    hsCode: '8471.30',
    totalWeight: '1250 kg',
    totalValue: '45000 USD',
    currency: 'USD',
    originCountry: 'TR',
    destinationCountry: 'DE',
    transportMode: 'AIR',
    createdAt: new Date().toISOString(),
  };

  console.log('\n[Customs Broker] ═══════════════════════════════════════════');
  console.log('[Customs Broker] Customs document prepared. ID:', customsDocument.documentId);
  console.log('[Customs Broker] Holder DID:', customsDocument.holderDid);
  console.log('[Customs Broker] Submitting to Ministry for review →', MINISTRY_URL);

  // ─── 2a. Ministry → submit for review ───────────────────────────────────────
  const submitRes = await fetch(`${MINISTRY_URL}/api/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': MINISTRY_API_KEY },
    body: JSON.stringify(customsDocument),
  });
  if (!submitRes.ok) {
    throw new Error(`[Ministry] HTTP ${submitRes.status}: ${await submitRes.text()}`);
  }
  const { submissionId } = (await submitRes.json()) as { submissionId: number };
  console.log('[Customs Broker] ✓ Queued for review. submissionId:', submissionId);

  // ─── 2b. Ministry → log in and approve as the officer (smoke test only —
  //         a real deployment has an actual human doing this in a panel) ────────
  const loginRes = await fetch(`${MINISTRY_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ passphrase: MINISTRY_OPERATOR_PASSPHRASE }),
  });
  if (!loginRes.ok) {
    throw new Error(`[Ministry] Officer login failed: HTTP ${loginRes.status}: ${await loginRes.text()}`);
  }
  const { sessionToken } = (await loginRes.json()) as { sessionToken: string };

  const approveRes = await fetch(`${MINISTRY_URL}/api/pending/${submissionId}/approve`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${sessionToken}` },
  });
  if (!approveRes.ok) {
    throw new Error(`[Ministry] Approve failed: HTTP ${approveRes.status}: ${await approveRes.text()}`);
  }
  const { verifiableCredential: vc } = (await approveRes.json()) as { verifiableCredential: UBLPVerifiableCredential };
  console.log('[Customs Broker] ✓ Verifiable Credential received. VC ID:', vc.id);
  console.log('[Customs Broker] Issuer:', vc.issuer);

  // ─── 3. UBLP Agent → Verifiable Presentation ───────────────────────────────
  console.log('[Customs Broker] Forwarding to UBLP Agent →', UBLP_AGENT_URL);

  const agentRes = await fetch(`${UBLP_AGENT_URL}/api/process`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ verifiableCredential: vc }),
  });

  if (!agentRes.ok) {
    throw new Error(`[UBLP Agent] HTTP ${agentRes.status}: ${await agentRes.text()}`);
  }

  const result = await agentRes.json() as {
    presentation: UBLPVerifiablePresentation;
    l2Result: L2SettleResponse;
  };

  // ─── 4. Result ─────────────────────────────────────────────────────────────
  console.log('\n[Customs Broker] ═══════════════════════════════════════════');
  console.log('[Customs Broker] ✓ W3C VC/VP flow completed!');
  console.log('[Customs Broker] L2 Status:', result.l2Result?.status);
  console.log('[Customs Broker] Holder:', result.presentation?.holder);
  console.log('[Customs Broker] Proof System:', result.presentation?.proof?.proofSystem);
  console.log('[Customs Broker] Settled At:', result.l2Result?.record?.settledAt);
  console.log('[Customs Broker] Full Result:\n', JSON.stringify(result, null, 2));
}

run().catch((err) => {
  console.error('\n[Customs Broker] ✗ Error:', (err as Error).message);
  process.exit(1);
});
