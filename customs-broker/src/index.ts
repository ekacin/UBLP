/**
 * Gümrük Müşaviri — W3C VC/VP akışını başlatan taraf
 *
 * Akış:
 *   1. Gümrük belgesi hazırla (holderDid dahil)
 *   2. Bakanlık → Verifiable Credential (VC) al
 *   3. UBLP Agent → VC gönder, Verifiable Presentation (VP) + L2 sonucu al
 */

import crypto from 'crypto';
import {
  UBLPVerifiableCredential,
  UBLPVerifiablePresentation,
  L2SettleResponse,
} from '@ublp/shared';

const MINISTRY_URL = process.env.MINISTRY_URL ?? 'http://localhost:3001';
const UBLP_AGENT_URL = process.env.UBLP_AGENT_URL ?? 'http://localhost:3002';
const AGENT_DID = process.env.AGENT_DID ?? 'did:ublp:agent:default';

async function run(): Promise<void> {
  // ─── 1. Gümrük Belgesi ─────────────────────────────────────────────────────
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
  console.log('[Customs Broker] Gümrük belgesi hazırlandı. ID:', customsDocument.documentId);
  console.log('[Customs Broker] Holder DID:', customsDocument.holderDid);
  console.log('[Customs Broker] Bakanlık onayına gönderiliyor →', MINISTRY_URL);

  // ─── 2. Bakanlık → Verifiable Credential ───────────────────────────────────
  const ministryRes = await fetch(`${MINISTRY_URL}/api/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(customsDocument),
  });

  if (!ministryRes.ok) {
    throw new Error(`[Ministry] HTTP ${ministryRes.status}: ${await ministryRes.text()}`);
  }

  const vc = await ministryRes.json() as UBLPVerifiableCredential;
  console.log('[Customs Broker] ✓ Verifiable Credential alındı. VC ID:', vc.id);
  console.log('[Customs Broker] Issuer:', vc.issuer);

  // ─── 3. UBLP Agent → Verifiable Presentation ───────────────────────────────
  console.log('[Customs Broker] UBLP Agent\'a iletiliyor →', UBLP_AGENT_URL);

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

  // ─── 4. Sonuç ──────────────────────────────────────────────────────────────
  console.log('\n[Customs Broker] ═══════════════════════════════════════════');
  console.log('[Customs Broker] ✓ W3C VC/VP akışı tamamlandı!');
  console.log('[Customs Broker] L2 Durumu:', result.l2Result?.status);
  console.log('[Customs Broker] Holder:', result.presentation?.holder);
  console.log('[Customs Broker] Proof System:', result.presentation?.proof?.proofSystem);
  console.log('[Customs Broker] Settled At:', result.l2Result?.record?.settledAt);
  console.log('[Customs Broker] Tam Sonuç:\n', JSON.stringify(result, null, 2));
}

run().catch((err) => {
  console.error('\n[Customs Broker] ✗ Hata:', (err as Error).message);
  process.exit(1);
});
