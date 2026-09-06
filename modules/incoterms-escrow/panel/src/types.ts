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

export type IncotermRule = 'EXW' | 'FCA' | 'CPT' | 'CIP' | 'DAP' | 'DPU' | 'DDP' | 'FAS' | 'FOB' | 'CFR' | 'CIF';

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
  /** Captured from the same Fetch step as buyerMemoPublicKeyHex — lets approve() attempt
   * automatic encrypted delivery to the buyer instead of relying purely on manual copy/paste
   * (see api.ts's approvePending doc comment). */
  buyerAgentUrl?: string;
}

export interface LockDealParams {
  contractAddress: string;
  proposal: EscrowProposal;
  /** Set when this Lock originated from an "incoming offer" (agent-to-agent delivery) rather
   * than a manually-pasted blob — lets the backend mark that offer 'used' once queued. */
  incomingOfferId?: number;
}

/** A proposal a counterparty's agent delivered directly (encrypted, agent-to-agent) — see
 * server/actions.ts's receiveOffer. Distinct from PendingAction: nothing has been queued for
 * approval yet, this is just "received, awaiting the operator's accept/dismiss decision". */
export interface IncomingOffer {
  id: number;
  contractAddress: string;
  proposal: EscrowProposal;
  senderMemoPublicKeyHex: string;
  status: 'pending' | 'dismissed' | 'used';
  receivedAt: number;
  updatedAt: number;
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
  milestoneConfirmed: boolean;
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
