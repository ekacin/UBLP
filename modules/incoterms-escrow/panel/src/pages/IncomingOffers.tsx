import React, { useCallback, useEffect, useState } from 'react';
import { dismissIncomingOffer, lockDeal, listIncomingOffers } from '../api';
import type { IncomingOffer } from '../types';

const POLL_INTERVAL_MS = 5_000;

interface IncomingOffersProps {
  onQueued: () => void;
}

/** Offers a counterparty's agent delivered directly (encrypted, agent-to-agent — see
 * server/actions.ts's receiveOffer). Nothing here has touched the chain: "Accept & Lock" only
 * queues a lockEscrow pending-action, same as the manual paste flow always did — the actual
 * on-chain commitment still needs a separate Approve in the Pending queue (AGENTS.md 5.21). */
const IncomingOffers: React.FC<IncomingOffersProps> = ({ onQueued }) => {
  const [offers, setOffers] = useState<IncomingOffer[]>([]);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setOffers(await listIncomingOffers());
    } catch (err) {
      setError((err as Error).message);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [refresh]);

  const accept = async (offer: IncomingOffer) => {
    setBusyId(offer.id);
    setError(null);
    try {
      await lockDeal({ contractAddress: offer.contractAddress, proposal: offer.proposal, incomingOfferId: offer.id });
      await refresh();
      onQueued();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusyId(null);
    }
  };

  const dismiss = async (id: number) => {
    setBusyId(id);
    setError(null);
    try {
      await dismissIncomingOffer(id);
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusyId(null);
    }
  };

  const pending = offers.filter((o) => o.status === 'pending');

  return (
    <div>
      <h2 className="section-title">Incoming offers ({pending.length})</h2>
      {error && (
        <div className="alert alert-error" role="alert">
          {error}
        </div>
      )}
      {pending.length === 0 && (
        <p className="empty-state">
          Nothing here yet. A seller's agent delivers a proposal here automatically once they approve it — or ask
          them to send it out-of-band and paste it under "New deal" instead.
        </p>
      )}
      {pending.map((offer) => {
        const { terms } = offer.proposal;
        return (
          <div className="card" key={offer.id}>
            <div className="queue-item-head">
              <div>
                <div className="queue-item-title">Offer from {terms.sellerDid}</div>
                <div className="queue-item-sub">{new Date(offer.receivedAt).toLocaleString()}</div>
              </div>
            </div>
            <dl className="terms-table">
              <dt>Shipment ID</dt>
              <dd>{terms.shipmentId}</dd>
              <dt>Contract</dt>
              <dd title={offer.contractAddress}>{offer.contractAddress}</dd>
              <dt>Incoterm</dt>
              <dd>{terms.incoterm}</dd>
              <dt>Amount</dt>
              <dd>{terms.amount}</dd>
              <dt>Duration</dt>
              <dd>{terms.durationSeconds} seconds</dd>
              <dt>Timeout direction</dt>
              <dd>{terms.timeoutDirection}</dd>
              <dt>Port authority (C)</dt>
              <dd>{terms.portAuthorityDid}</dd>
            </dl>
            <div className="queue-item-actions">
              <button type="button" className="btn btn-primary" disabled={busyId !== null} onClick={() => accept(offer)}>
                {busyId === offer.id ? 'Queuing…' : 'Accept & Lock'}
              </button>
              <button type="button" className="btn btn-danger" disabled={busyId !== null} onClick={() => dismiss(offer.id)}>
                Dismiss
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default IncomingOffers;
