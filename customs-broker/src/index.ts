/**
 * Gümrük Müşaviri İstemcisi
 * Akışı başlatan taraf — belge üretir, Bakanlık + UBLP Agent üzerinden ilerler.
 */

const MINISTRY_URL = process.env.MINISTRY_URL ?? 'http://localhost:3001';
const UBLP_AGENT_URL = process.env.UBLP_AGENT_URL ?? 'http://localhost:3002';

async function run(): Promise<void> {
  // ─── 1. Gümrük Belgesi Hazırla ─────────────────────────────────────────────
  const customsDocument: Record<string, unknown> = {
    documentId: `DOC-${Date.now()}`,
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
  console.log('[Customs Broker] Gümrük belgesi hazırlandı. ID:', customsDocument['documentId']);
  console.log('[Customs Broker] Bakanlık onayına gönderiliyor →', MINISTRY_URL);

  // ─── 2. Bakanlık Onayı ─────────────────────────────────────────────────────
  const ministryRes = await fetch(`${MINISTRY_URL}/api/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(customsDocument),
  });

  if (!ministryRes.ok) {
    const body = await ministryRes.text();
    throw new Error(`[Ministry] HTTP ${ministryRes.status}: ${body}`);
  }

  const ministryPayload = await ministryRes.json() as { approvedAt: string };
  console.log('[Customs Broker] ✓ Bakanlık onayı alındı. approvedAt:', ministryPayload.approvedAt);

  // ─── 3. UBLP Agent'a İlet ──────────────────────────────────────────────────
  console.log('[Customs Broker] UBLP Agent\'a iletiliyor →', UBLP_AGENT_URL);

  const agentRes = await fetch(`${UBLP_AGENT_URL}/api/process`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(ministryPayload),
  });

  if (!agentRes.ok) {
    const body = await agentRes.text();
    throw new Error(`[UBLP Agent] HTTP ${agentRes.status}: ${body}`);
  }

  const result = await agentRes.json();

  // ─── 4. Sonuç ──────────────────────────────────────────────────────────────
  console.log('\n[Customs Broker] ═══════════════════════════════════════════');
  console.log('[Customs Broker] ✓ Tüm akış tamamlandı!');
  console.log('[Customs Broker] Belge Durumu:', (result as { l2Result: { status: string } }).l2Result?.status);
  console.log('[Customs Broker] Tam Sonuç:\n', JSON.stringify(result, null, 2));
}

run().catch((err) => {
  console.error('\n[Customs Broker] ✗ Hata:', err.message);
  process.exit(1);
});
