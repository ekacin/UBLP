import React, { useCallback, useEffect, useState } from 'react';
import { listPending, approvePending, rejectPending } from '../../api/ministry';
import type { ReviewItem } from '../../types';

const POLL_INTERVAL_MS = 5_000;

const STATUS_LABELS: Record<string, string> = {
  awaiting_approval: 'Awaiting review',
  approved: 'Approved',
  rejected: 'Rejected',
};

function truncate(value: string, edge = 8): string {
  return value.length > edge * 2 + 3 ? `${value.slice(0, edge)}…${value.slice(-edge)}` : value;
}

const PendingReview: React.FC = () => {
  const [items, setItems] = useState<ReviewItem[]>([]);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [lastError, setLastError] = useState<string | null>(null);

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
    setBusyId(id);
    setLastError(null);
    try {
      await approvePending(id);
      await refresh();
    } catch (err) {
      setLastError((err as Error).message);
    } finally {
      setBusyId(null);
    }
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
  const decided = items.filter((i) => i.status !== 'awaiting_approval');

  return (
    <div>
      {lastError && (
        <div className="alert alert-error" role="alert">
          {lastError}
        </div>
      )}

      <h2 className="section-title">Awaiting review ({awaiting.length})</h2>
      {awaiting.length === 0 && <p className="empty-state">Nothing waiting right now.</p>}
      {awaiting.map((item) => (
        <div className="card" key={item.id}>
          <div className="queue-item-head">
            <div>
              <div className="queue-item-title">{item.payload.exporterName ?? item.refId}</div>
              <div className="queue-item-sub">
                #{item.id} · {truncate(item.refId)}
              </div>
            </div>
            <button type="button" className="btn btn-sm" onClick={() => setExpandedId(expandedId === item.id ? null : item.id)}>
              {expandedId === item.id ? 'Hide details' : 'Show document'}
            </button>
          </div>
          {expandedId === item.id && (
            <dl className="terms-table">
              <dt>Document ID</dt>
              <dd>{item.payload.documentId}</dd>
              <dt>Holder DID</dt>
              <dd>{item.payload.holderDid}</dd>
              <dt>Exporter</dt>
              <dd>
                {item.payload.exporterName} ({item.payload.exporterTaxId})
              </dd>
              <dt>Importer</dt>
              <dd>
                {item.payload.importerName} ({item.payload.importerVatId})
              </dd>
              <dt>Goods</dt>
              <dd>{item.payload.goodsDescription}</dd>
              <dt>HS code</dt>
              <dd>{item.payload.hsCode}</dd>
              <dt>Value</dt>
              <dd>
                {item.payload.totalValue} {item.payload.currency}
              </dd>
              <dt>Route</dt>
              <dd>
                {item.payload.originCountry} → {item.payload.destinationCountry} ({item.payload.transportMode})
              </dd>
            </dl>
          )}
          <div className="queue-item-actions">
            <button type="button" className="btn btn-primary" disabled={busyId !== null} onClick={() => handleApprove(item.id)}>
              {busyId === item.id ? 'Signing…' : 'Approve & sign'}
            </button>
            <button type="button" className="btn btn-danger" disabled={busyId !== null} onClick={() => handleReject(item.id)}>
              Reject
            </button>
          </div>
        </div>
      ))}

      <h2 className="section-title">Recently decided</h2>
      {decided.length === 0 && <p className="empty-state">No past activity yet.</p>}
      {decided.map((item) => (
        <div className="card" key={item.id}>
          <div className="queue-item-head">
            <div>
              <div className="queue-item-title">{item.payload.exporterName ?? item.refId}</div>
              <div className="queue-item-sub">
                #{item.id} · {truncate(item.refId)}
                {item.decisionNote && <> · {item.decisionNote}</>}
              </div>
            </div>
            <span className={`badge badge-${item.status}`}>{STATUS_LABELS[item.status]}</span>
          </div>
        </div>
      ))}
    </div>
  );
};

export default PendingReview;
