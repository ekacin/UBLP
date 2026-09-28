import React, { useState } from 'react';
import { createSubmission } from '../../api/broker';
import { CURRENCIES, INCOTERMS, WEIGHT_UNITS, TRANSPORT_MODES, COUNTRIES } from '../../data/referenceLists';
import type { CustomsDocument } from '../../types';

interface NewSubmissionProps {
  onCreated: () => void;
}

function generateDocumentId(): string {
  return `DOC-${crypto.randomUUID()}`;
}

// Numeric fields kept as string state (React controlled-input convention — the DOM value of a
// number input is always a string) but rendered with type="number", so the browser itself
// blocks non-numeric characters; converted to real numbers only once, at submit time, into the
// CustomsDocument shape types.ts declares. This is what actually closes the gap a manual test
// found — free-text totalValue/currency previously accepted something like "USDa".
interface FormState {
  invoiceNumber: string;
  holderDid: string;
  exporterName: string;
  exporterTaxId: string;
  importerName: string;
  importerVatId: string;
  goodsDescription: string;
  hsCode: string;
  quantity: string;
  weightValue: string;
  weightUnit: string;
  totalValue: string;
  currency: string;
  incoterm: string;
  originCountry: string;
  destinationCountry: string;
  transportMode: string;
}

const INITIAL_FORM: FormState = {
  invoiceNumber: '',
  holderDid: 'did:ublp:agent:default',
  exporterName: '',
  exporterTaxId: '',
  importerName: '',
  importerVatId: '',
  goodsDescription: '',
  hsCode: '',
  quantity: '',
  weightValue: '',
  weightUnit: 'kg',
  totalValue: '',
  currency: 'USD',
  incoterm: 'FOB',
  originCountry: '',
  destinationCountry: '',
  transportMode: 'AIR',
};

const NewSubmission: React.FC<NewSubmissionProps> = ({ onCreated }) => {
  const [documentId] = useState(generateDocumentId);
  const [form, setForm] = useState<FormState>(INITIAL_FORM);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const set = <K extends keyof FormState>(key: K, value: string) => setForm((f) => ({ ...f, [key]: value }));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const document: CustomsDocument = {
        documentId,
        holderDid: form.holderDid,
        invoiceNumber: form.invoiceNumber,
        exporterName: form.exporterName,
        exporterTaxId: form.exporterTaxId,
        importerName: form.importerName,
        importerVatId: form.importerVatId,
        goodsDescription: form.goodsDescription,
        hsCode: form.hsCode,
        quantity: Number(form.quantity),
        weightValue: Number(form.weightValue),
        weightUnit: form.weightUnit,
        totalValue: Number(form.totalValue),
        currency: form.currency,
        incoterm: form.incoterm,
        originCountry: form.originCountry,
        destinationCountry: form.destinationCountry,
        transportMode: form.transportMode,
        createdAt: new Date().toISOString(),
      };
      await createSubmission(document);
      onCreated();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="new-deal-form" onSubmit={handleSubmit}>
      <div className="form-section">
        <p className="form-section-label">Document</p>
        <label>
          Document ID (auto-generated)
          <input value={documentId} readOnly />
        </label>
        <label>
          Invoice number
          <input value={form.invoiceNumber} onChange={(e) => set('invoiceNumber', e.target.value)} placeholder="e.g. INV-2026-0042" required />
        </label>
        <label>
          Holder DID
          <input value={form.holderDid} onChange={(e) => set('holderDid', e.target.value)} required />
        </label>
      </div>

      <div className="form-section">
        <p className="form-section-label">Parties</p>
        <label>
          Exporter name
          <input value={form.exporterName} onChange={(e) => set('exporterName', e.target.value)} required />
        </label>
        <label>
          Exporter tax ID
          <input value={form.exporterTaxId} onChange={(e) => set('exporterTaxId', e.target.value)} />
        </label>
        <label>
          Importer name
          <input value={form.importerName} onChange={(e) => set('importerName', e.target.value)} required />
        </label>
        <label>
          Importer VAT ID
          <input value={form.importerVatId} onChange={(e) => set('importerVatId', e.target.value)} />
        </label>
      </div>

      <div className="form-section">
        <p className="form-section-label">Goods</p>
        <label>
          Goods description
          <textarea rows={2} value={form.goodsDescription} onChange={(e) => set('goodsDescription', e.target.value)} required />
        </label>
        <label>
          HS code
          <input
            value={form.hsCode}
            onChange={(e) => set('hsCode', e.target.value)}
            placeholder="e.g. 8471.30"
            pattern="[0-9]+(\.[0-9]+)*"
            title="Digits only, optionally grouped with dots (e.g. 8471.30)"
            required
          />
        </label>
        <label>
          Number of packages
          <input type="number" min="1" step="1" value={form.quantity} onChange={(e) => set('quantity', e.target.value)} required />
        </label>
        <label>
          Weight
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              type="number"
              min="0"
              step="0.01"
              value={form.weightValue}
              onChange={(e) => set('weightValue', e.target.value)}
              style={{ flex: 1 }}
              required
            />
            <select value={form.weightUnit} onChange={(e) => set('weightUnit', e.target.value)} style={{ flex: '0 0 90px' }}>
              {WEIGHT_UNITS.map((u) => (
                <option key={u} value={u}>
                  {u}
                </option>
              ))}
            </select>
          </div>
        </label>
        <label>
          Customs value
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              type="number"
              min="0"
              step="0.01"
              value={form.totalValue}
              onChange={(e) => set('totalValue', e.target.value)}
              style={{ flex: 1 }}
              required
            />
            <select value={form.currency} onChange={(e) => set('currency', e.target.value)} style={{ flex: '0 0 90px' }}>
              {CURRENCIES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>
        </label>
      </div>

      <div className="form-section">
        <p className="form-section-label">Terms &amp; route</p>
        <label>
          Incoterm (delivery terms)
          <select value={form.incoterm} onChange={(e) => set('incoterm', e.target.value)}>
            {INCOTERMS.map((i) => (
              <option key={i.code} value={i.code}>
                {i.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Origin country
          <select value={form.originCountry} onChange={(e) => set('originCountry', e.target.value)} required>
            <option value="" disabled>
              Select…
            </option>
            {COUNTRIES.map((c) => (
              <option key={c.code} value={c.code}>
                {c.name} ({c.code})
              </option>
            ))}
          </select>
        </label>
        <label>
          Destination country
          <select value={form.destinationCountry} onChange={(e) => set('destinationCountry', e.target.value)} required>
            <option value="" disabled>
              Select…
            </option>
            {COUNTRIES.map((c) => (
              <option key={c.code} value={c.code}>
                {c.name} ({c.code})
              </option>
            ))}
          </select>
        </label>
        <label>
          Transport mode
          <select value={form.transportMode} onChange={(e) => set('transportMode', e.target.value)}>
            {TRANSPORT_MODES.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </label>
      </div>

      <button type="submit" className="btn btn-primary" disabled={busy}>
        {busy ? 'Creating…' : 'Create submission'}
      </button>

      {error && (
        <div className="alert alert-error" role="alert">
          {error}
        </div>
      )}
    </form>
  );
};

export default NewSubmission;
