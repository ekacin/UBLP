// Most of these are hand-copied from the Ministry/Broker backends' own shapes — same
// convention as incoterms-escrow/panel/src/types.ts: this is a browser bundle, and `ReviewItem`/
// `Submission` are typed inside Node-only packages (@ublp/shared, customs-broker), so those two
// stay hand-copied. The VC/VP/proof/settlement shapes, though, already live in the dependency-
// free @ublp/zk-customs-types package (also used by every backend service) — imported directly
// below rather than re-duplicated a second time.
export type {
  UBLPVerifiableCredential as VerifiableCredential,
  UBLPVerifiablePresentation as VerifiablePresentation,
  VPProof,
  L2SettleRecord,
} from '@ublp/zk-customs-types';
import type { UBLPVerifiableCredential, UBLPVerifiablePresentation, L2SettleRecord } from '@ublp/zk-customs-types';

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

export interface Submission {
  id: number;
  reviewItemId: number;
  document: CustomsDocument;
  status: SubmissionStatus;
  ministryRefId: number | null;
  verifiableCredential: UBLPVerifiableCredential | null;
  presentation: UBLPVerifiablePresentation | null;
  l2Result: { status: 'APPROVED' | 'REJECTED'; record: L2SettleRecord } | null;
  error: string | null;
  createdAt: number;
  updatedAt: number;
}
