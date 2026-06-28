export const SAMPLE_CUSTOMS_DOCUMENT = {
  documentId: 'DOC-550e8400-e29b-41d4-a716-446655440000',
  holderDid: 'did:ublp:agent:test-carrier',
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
  createdAt: '2025-01-15T10:00:00.000Z',
};

export const SAMPLE_DOCUMENT_ID = 'DOC-550e8400-e29b-41d4-a716-446655440000';
export const SAMPLE_HOLDER_DID = 'did:ublp:agent:test-carrier';

export const ALT_CUSTOMS_DOCUMENT = {
  documentId: 'DOC-660e8400-e29b-41d4-a716-446655440001',
  holderDid: 'did:ublp:agent:alt-carrier',
  exporterName: 'Beta Export A.Ş.',
  exporterTaxId: '9876543210',
  importerName: 'Import Corp.',
  importerVatId: 'FR123456789',
  goodsDescription: 'Tekstil Ürünleri',
  hsCode: '6204.62',
  totalWeight: '500 kg',
  totalValue: '15000 USD',
  currency: 'USD',
  originCountry: 'TR',
  destinationCountry: 'FR',
  transportMode: 'SEA',
  createdAt: '2025-01-15T11:00:00.000Z',
};
