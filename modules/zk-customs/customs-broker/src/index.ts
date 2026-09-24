/**
 * Customs Broker — the party that kicks off the W3C VC/VP flow
 *
 * Flow:
 *   1. Prepare the customs document (including holderDid)
 *   2. Ministry → obtain Verifiable Credential (VC)
 *   3. UBLP Agent → send VC, get Verifiable Presentation (VP) + L2 result
 */

import crypto from 'crypto';
import {
  UBLPVerifiableCredential,
  UBLPVerifiablePresentation,
  L2SettleResponse,
} from '@ublp/zk-customs-types';

const MINISTRY_URL = process.env.MINISTRY_URL ?? 'http://localhost:3001';
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
  console.log('[Customs Broker] Sending for Ministry approval →', MINISTRY_URL);

  // ─── 2. Ministry → Verifiable Credential ────────────────────────────────────
  const ministryRes = await fetch(`${MINISTRY_URL}/api/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(customsDocument),
  });

  if (!ministryRes.ok) {
    throw new Error(`[Ministry] HTTP ${ministryRes.status}: ${await ministryRes.text()}`);
  }

  const vc = await ministryRes.json() as UBLPVerifiableCredential;
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
