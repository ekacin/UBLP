// Hand-copied from the Ministry/Broker backends' own shapes — same convention as
// incoterms-escrow/panel/src/types.ts: this is a browser bundle, the backends are Node-only,
// so these aren't imported, just kept in sync by hand.

export type ServiceRole = 'ministry' | 'broker';

// ---- Ministry: shared/src/agent-core/reviewQueue.ts's ReviewItem, kind 'document-approval' ----

export type ReviewStatus = 'awaiting_approval' | 'approved' | 'rejected';

// Field set cross-checked against real customs paperwork standards (US customs commercial
// invoice's 14 required fields; the EU Single Administrative Document's core boxes) — see the
// backend-foundation follow-up that added invoiceNumber/incoterm/quantity/weightValue+Unit and
// turned totalValue/currency/countries from free text into validated number/select fields.
// Numeric fields are real `number`s here (not strings) — the form enforces this at input time.
export interface CustomsDocument {
  documentId: string;
  holderDid: string;
  invoiceNumber?: string;
  exporterName?: string;
  exporterTaxId?: string;
  importerName?: string;
  importerVatId?: string;
  goodsDescription?: string;
  hsCode?: string;
  quantity?: number;
  weightValue?: number;
  weightUnit?: string;
  totalValue?: number;
  currency?: string;
  incoterm?: string;
  originCountry?: string;
  destinationCountry?: string;
  transportMode?: string;
  createdAt?: string;
}

export interface ReviewItem {
  id: number;
  kind: string;
  refId: string;
  status: ReviewStatus;
  payload: CustomsDocument;
  requestedBy: string;
  decidedBy: string | null;
  decisionNote: string | null;
  createdAt: number;
  updatedAt: number;
}

export interface VerifiableCredential {
  id: string;
  issuer: string;
  issuanceDate: string;
  credentialSubject: { id: string; documentId: string };
}

// ---- Broker: customs-broker/src/db.ts's Submission ----

export type SubmissionStatus =
  | 'draft'
  | 'awaiting_approval'
  | 'sent_to_ministry'
  | 'awaiting_ministry_approval'
  | 'vc_received'
  | 'proof_requested'
  | 'settled'
  | 'rejected'
  | 'failed';

export interface L2SettleRecord {
  documentHash: string;
  documentIdHash: string;
  ministryPublicKeyHash: string;
  holderDid: string;
  status: 'APPROVED' | 'REJECTED' | 'SUSPICIOUS';
  settledAt: string;
  proofSystem: string;
}

export interface VPProof {
  proofSystem: string;
  proofBytes: string;
  publicValues: {
    documentHash: string;
    pubKeyHash: string;
    documentIdHash: string;
    holderPubKeyHash: string;
  };
}

export interface VerifiablePresentation {
  holder: string;
  proof: VPProof;
}

export interface Submission {
  id: number;
  reviewItemId: number;
  document: CustomsDocument;
  status: SubmissionStatus;
  ministryRefId: number | null;
  verifiableCredential: VerifiableCredential | null;
  presentation: VerifiablePresentation | null;
  l2Result: { status: 'APPROVED' | 'REJECTED'; record: L2SettleRecord } | null;
  error: string | null;
  createdAt: number;
  updatedAt: number;
}
