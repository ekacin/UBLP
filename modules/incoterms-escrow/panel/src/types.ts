/**
 * Wire types mirroring the settlement-agent's actual TypeScript interfaces (escrow.ts,
 * server/actions.ts, server/db.ts). Hand-copied rather than imported — the agent is a
 * Node-only package (server crypto, sqlite, wallet SDK) and this is a browser bundle; pulling
 * its source in would drag Node-specific dependencies into Vite for no benefit. Keep these in
 * sync with the backend by hand if those interfaces change.
 */

export type AgentRole = 'buyer' | 'seller' | 'port-authority';

/** A single deployed agent is always ONE company's fixed identity — never a role the operator
 * picks in the UI (unlike a generic multi-role demo). The panel fetches this once after login
 * to render a role-appropriate dashboard (AGENTS.md 5.12/5.26). */
export interface WhoAmI {
  role: AgentRole;
  did: string;
  network: string;
}

export type IncotermRule = 'FOB' | string;

export interface EscrowTerms {
  shipmentId: string;
  sellerDid: string;
  buyerDid: string;
  portAuthorityDid: string;
  portAuthorityKeyHashHex: string;
  insuranceResponsibleParty?: string;
  incoterm: IncotermRule;
  amount: string;
  amountSalt: string;
  durationSeconds: number;
  timeoutDirection: 'buyer' | 'seller';
  sellerMemoPublicKey: string;
  buyerMemoPublicKey: string;
}

export interface EscrowProposal {
  terms: EscrowTerms;
  sellerSignature: string;
  sellerPublicKey: string;
}

export interface ProposeDealParams {
  shipmentId: string;
  buyerDid: string;
  portAuthorityDid: string;
  portAuthorityKeyHashHex: string;
  buyerMemoPublicKeyHex: string;
  incoterm: IncotermRule;
  agreedAmount: string;
  durationSeconds?: number;
  timeoutDirection?: 'buyer' | 'seller';
}

export interface LockDealParams {
  contractAddress: string;
  proposal: EscrowProposal;
}

export type PendingActionStatus =
  | 'awaiting_approval'
  | 'approved'
  | 'submitted_pending'
  | 'confirmed'
  | 'rejected'
  | 'failed';

export type PendingActionKind = 'propose' | 'lockEscrow';

export const ESCROW_STATE_LABELS = ['Empty', 'Proposed', 'Locked', 'Released'] as const;

export interface DealStatus {
  contractAddress: string;
  state: number; // index into ESCROW_STATE_LABELS
  loadingConfirmed: boolean;
  deadlineTimestamp: number;
  timeoutDirection: 'buyer' | 'seller';
  /** This company's own bookkeeping for this deal — never the chain, which never stores the
   * amount in plaintext. See server/actions.ts's DealStatus.ownRecord doc comment. */
  ownRecord: Array<{ action: string; amount: string | null; currency: string | null; timestamp: number }>;
}

export interface PendingAction {
  id: number;
  dealRef: string;
  action: PendingActionKind;
  status: PendingActionStatus;
  requestedBy: string;
  payload: ProposeDealParams | LockDealParams;
  txId: string | null;
  createdAt: number;
  updatedAt: number;
}
