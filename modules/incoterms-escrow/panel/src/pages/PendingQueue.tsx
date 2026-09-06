import React, { useCallback, useEffect, useState } from 'react';
import { listPending, approvePending, rejectPending } from '../api';
import type { EscrowProposal, PendingAction, PendingActionStatus, ProposeDealParams, LockDealParams } from '../types';

const POLL_INTERVAL_MS = 5_000;

const ACTION_LABELS: Record<string, string> = {
  propose: 'New offer',
  lockEscrow: 'Lock funds',
};

const STATUS_LABELS: Record<PendingActionStatus, string> = {
  awaiting_approval: 'Awaiting approval',
  approved: 'Approved',
  submitted_pending: 'Submitting…',
  confirmed: 'Confirmed',
  rejected: 'Rejected',
  failed: 'Failed',
};

function truncate(value: string, edge = 8): string {
  return value.length > edge * 2 + 3 ? `${value.slice(0, edge)}…${value.slice(-edge)}` : value;
}

function isProposePayload(action: PendingAction): action is PendingAction & { payload: ProposeDealParams } {
  return action.action === 'propose';
}

function isLockPayload(action: PendingAction): action is PendingAction & { payload: LockDealParams } {
  return action.action === 'lockEscrow';
}

/** Full-detail view of what approving this pending action actually commits to on-chain —
 * shown before approval per the "always show full EscrowTerms" decision, since propose/
 * lockEscrow create real financial exposure (AGENTS.md 5.21). */
const PendingDetail: React.FC<{ action: PendingAction }> = ({ action }) => {
  if (isProposePayload(action)) {
    const p = action.payload;
    return (
      <dl className="terms-table">
        <dt>Shipment ID</dt>
        <dd>{p.shipmentId}</dd>
        <dt>Buyer DID</dt>
        <dd>{p.buyerDid}</dd>
        <dt>Port authority (C) DID</dt>
        <dd>{p.portAuthorityDid}</dd>
        <dt>Incoterm</dt>
        <dd>{p.incoterm}</dd>
        <dt>Agreed amount</dt>
        <dd>{p.agreedAmount}</dd>
        <dt>Duration</dt>
        <dd>{p.durationSeconds ?? '(default 7 days)'} seconds</dd>
        <dt>Timeout direction</dt>
        <dd>{p.timeoutDirection ?? '(default buyer)'}</dd>
      </dl>
    );
  }

  if (isLockPayload(action)) {
    const { terms, sellerSignature, sellerPublicKey } = action.payload.proposal;
    return (
      <dl className="terms-table">
        <dt>Contract</dt>
        <dd title={action.payload.contractAddress}>{truncate(action.payload.contractAddress)}</dd>
        <dt>Shipment ID</dt>
        <dd>{terms.shipmentId}</dd>
        <dt>Seller DID</dt>
        <dd>{terms.sellerDid}</dd>
        <dt>Buyer DID</dt>
        <dd>{terms.buyerDid}</dd>
        <dt>Port authority (C) DID</dt>
        <dd>{terms.portAuthorityDid}</dd>
        <dt>Incoterm</dt>
        <dd>{terms.incoterm}</dd>
        <dt>Amount</dt>
        <dd>{terms.amount}</dd>
        <dt>Duration</dt>
        <dd>{terms.durationSeconds} seconds</dd>
        <dt>Timeout direction</dt>
        <dd>{terms.timeoutDirection}</dd>
        <dt>Insurance-responsible party</dt>
        <dd>{terms.insuranceResponsibleParty ?? '(none)'}</dd>
        <dt>Seller signature</dt>
        <dd title={sellerPublicKey}>{truncate(sellerSignature, 12)} — verified server-side before this reaches the chain</dd>
      </dl>
    );
  }

  return <p>Unrecognized pending action shape.</p>;
};

interface PendingQueueProps {
  onViewDeal: (contractAddress: string) => void;
}

const PendingQueue: React.FC<PendingQueueProps> = ({ onViewDeal }) => {
  const [items, setItems] = useState<PendingAction[]>([]);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [lastError, setLastError] = useState<string | null>(null);
  // Only ever comes from a live approve response — never persisted server-side, so this is
  // the one chance to capture it (see api.ts's approvePending doc comment).
  const [justApproved, setJustApproved] = useState<EscrowProposal | null>(null);
  const [justDelivered, setJustDelivered] = useState(false);
  const [copied, setCopied] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setItems(await listPending());
    } catch (err) {
      setLastError((err as Error).message);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [refresh]);

  const handleApprove = async (id: number) => {
    setBusyId(id); // blocking overlay: the whole queue is disabled while busyId is set
    setLastError(null);
    try {
      const result = await approvePending(id);
      if (result.proposal) {
        setJustApproved(result.proposal);
        setJustDelivered(!!result.delivered);
      }
      await refresh();
    } catch (err) {
      setLastError((err as Error).message);
    } finally {
      setBusyId(null);
    }
  };

  const copyOffer = () => {
    if (!justApproved) return;
    navigator.clipboard?.writeText(JSON.stringify(justApproved)).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const handleReject = async (id: number) => {
    setBusyId(id);
    setLastError(null);
    try {
      await rejectPending(id);
      await refresh();
    } catch (err) {
      setLastError((err as Error).message);
    } finally {
      setBusyId(null);
    }
  };

  const awaiting = items.filter((i) => i.status === 'awaiting_approval');
  const others = items.filter((i) => i.status !== 'awaiting_approval');

  return (
    <div>
      {lastError && (
        <div className="alert alert-error" role="alert">
          {lastError}
        </div>
      )}

      {busyId !== null && (
        <div className="blocking-overlay" role="alert" aria-busy="true">
          <div className="blocking-card">
            <div className="spinner" />
            <div className="blocking-title">Submitting to the network</div>
            <div className="blocking-sub">
              This generates a real ZK proof and can take 30–60 seconds. Don't close this page.
              Funds are drawn from this agent's own wallet — not the personal wallet you signed in
              with, which is used only to authenticate this session.
            </div>
          </div>
        </div>
      )}

      {justApproved && (
        <div className="card">
          <div className="queue-item-head">
            <div className="queue-item-title">
              {justDelivered ? 'Signed offer — delivered to your buyer' : 'Signed offer — send this to your buyer'}
            </div>
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setJustApproved(null)}>
              Dismiss
            </button>
          </div>
          {justDelivered ? (
            <p className="action-note" style={{ marginTop: 8 }}>
              Sent automatically, encrypted, straight to their agent — it's already waiting in their "Incoming
              offers" list. The copy below is just a backup in case they'd rather have it out-of-band too.
            </p>
          ) : (
            <p className="action-note" style={{ marginTop: 8 }}>
              This is not published anywhere the buyer can already see it — copy it and send it via
              whatever channel you already use (email, chat, EDI). The buyer pastes it into their own
              panel's "Lock a received offer" form.
            </p>
          )}
          <textarea
            readOnly
            rows={6}
            value={JSON.stringify(justApproved, null, 2)}
            onClick={(e) => (e.target as HTMLTextAreaElement).select()}
            style={{
              width: '100%',
              fontFamily: 'var(--mono)',
              fontSize: 12,
              padding: 10,
              border: '1px solid var(--line)',
              borderRadius: 8,
              background: 'var(--soft)',
              color: 'var(--fg)',
              resize: 'vertical',
            }}
          />
          <div className="queue-item-actions">
            <button type="button" className="btn btn-primary btn-sm" onClick={copyOffer}>
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>
      )}

      <h2 className="section-title">Awaiting your approval ({awaiting.length})</h2>
      {awaiting.length === 0 && <p className="empty-state">Nothing waiting right now.</p>}
      {awaiting.map((item) => (
        <div className="card" key={item.id}>
          <div className="queue-item-head">
            <div>
              <div className="queue-item-title">{ACTION_LABELS[item.action] ?? item.action}</div>
              <div className="queue-item-sub">
                #{item.id} · {item.dealRef.startsWith('pending-propose:') ? 'new deal' : truncate(item.dealRef)}
              </div>
            </div>
            <button type="button" className="btn btn-sm" onClick={() => setExpandedId(expandedId === item.id ? null : item.id)}>
              {expandedId === item.id ? 'Hide details' : 'Show full terms'}
            </button>
          </div>
          {expandedId === item.id && <PendingDetail action={item} />}
          <div className="queue-item-actions">
            <button type="button" className="btn btn-primary" disabled={busyId !== null} onClick={() => handleApprove(item.id)}>
              Approve
            </button>
            <button type="button" className="btn btn-danger" disabled={busyId !== null} onClick={() => handleReject(item.id)}>
              Reject
            </button>
          </div>
        </div>
      ))}

      <h2 className="section-title">History</h2>
      {others.length === 0 && <p className="empty-state">No past activity yet.</p>}
      {others.map((item) => {
        // dealRef starts as a 'pending-propose:<timestamp>' placeholder until propose()
        // actually deploys and confirms (server/db.ts) — only a real address is worth a
        // status link.
        const hasRealDealRef = item.status === 'confirmed' && !item.dealRef.startsWith('pending-propose:');
        return (
          <div className="card" key={item.id}>
            <div className="queue-item-head">
              <div>
                <div className="queue-item-title">{ACTION_LABELS[item.action] ?? item.action}</div>
                <div className="queue-item-sub">
                  #{item.id} · {truncate(item.dealRef)}
                  {item.txId && <> · tx {truncate(item.txId)}</>}
                </div>
              </div>
              <span className={`badge badge-${item.status}`}>{STATUS_LABELS[item.status]}</span>
            </div>
            {hasRealDealRef && (
              <div className="queue-item-actions">
                <button type="button" className="btn btn-sm" onClick={() => onViewDeal(item.dealRef)}>
                  View status
                </button>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

export default PendingQueue;
