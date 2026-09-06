import React, { useState } from 'react';
import { useAuth } from './auth/useAuth';
import { useWhoAmI } from './auth/useWhoAmI';
import Login from './pages/Login';
import PendingQueue from './pages/PendingQueue';
import DealStatus from './pages/DealStatus';
import NewDeal from './pages/NewDeal';
import OpenDeal from './pages/OpenDeal';
import IncomingOffers from './pages/IncomingOffers';
import InstanceSwitcher from './components/InstanceSwitcher';

type View = 'queue' | 'newDeal' | 'openDeal' | 'incoming';

const ROLE_LABEL: Record<string, string> = {
  buyer: 'Buyer',
  seller: 'Seller',
  'port-authority': 'Port authority',
};

const App: React.FC = () => {
  const { status, error, wallets, login, logout, activeBaseUrl, switchInstance } = useAuth();
  const { identity } = useWhoAmI(status === 'authenticated', activeBaseUrl);
  const [viewingDeal, setViewingDeal] = useState<string | null>(null);
  // Sellers/buyers land on their approval queue; a port-authority agent never has anything to
  // approve (it only ever calls attestMilestone, an immediate action — see routes.ts's
  // header), so its natural home is opening a deal directly by contract address instead.
  const [view, setView] = useState<View | null>(null);
  const effectiveView: View = view ?? (identity?.role === 'port-authority' ? 'openDeal' : 'queue');

  // A deal viewed on one instance (e.g. the seller agent) is meaningless on another (e.g. the
  // same operator's buyer agent) — drop any in-progress view when switching instances rather
  // than showing stale state from the previous one.
  const handleSwitchInstance = (baseUrl: string) => {
    setViewingDeal(null);
    setView(null);
    switchInstance(baseUrl);
  };

  if (status === 'checking') return null;

  if (status === 'unauthenticated' || status === 'connecting') {
    return (
      <Login
        wallets={wallets}
        connecting={status === 'connecting'}
        error={error}
        onConnect={login}
        activeBaseUrl={activeBaseUrl}
        onSwitchInstance={handleSwitchInstance}
      />
    );
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand-block">
          <span className="brand-mark" />
          <span className="brand">UBLP</span>
          <h1>Escrow Settlement</h1>
        </div>
        <div className="header-meta">
          {identity && <span className="role-badge">{ROLE_LABEL[identity.role] ?? identity.role}</span>}
          {identity && (
            <span className="network-badge">
              <span className="dot" />
              {identity.network}
            </span>
          )}
          <InstanceSwitcher activeBaseUrl={activeBaseUrl} onSwitch={handleSwitchInstance} />
          <button type="button" className="btn btn-ghost btn-sm" onClick={logout}>
            Sign out
          </button>
        </div>
      </header>
      <main className="app-main">
        {viewingDeal ? (
          <DealStatus contractAddress={viewingDeal} role={identity?.role ?? null} onClose={() => setViewingDeal(null)} />
        ) : (
          <>
            {identity?.role !== 'port-authority' && (
              <nav className="app-nav">
                <button
                  type="button"
                  className={`btn btn-sm ${effectiveView === 'queue' ? 'btn-primary' : ''}`}
                  onClick={() => setView('queue')}
                >
                  Pending queue
                </button>
                <button
                  type="button"
                  className={`btn btn-sm ${effectiveView === 'newDeal' ? 'btn-primary' : ''}`}
                  onClick={() => setView('newDeal')}
                >
                  New deal
                </button>
                {identity?.role === 'buyer' && (
                  <button
                    type="button"
                    className={`btn btn-sm ${effectiveView === 'incoming' ? 'btn-primary' : ''}`}
                    onClick={() => setView('incoming')}
                  >
                    Incoming offers
                  </button>
                )}
                <button
                  type="button"
                  className={`btn btn-sm ${effectiveView === 'openDeal' ? 'btn-primary' : ''}`}
                  onClick={() => setView('openDeal')}
                >
                  Open deal
                </button>
              </nav>
            )}
            {effectiveView === 'queue' && <PendingQueue onViewDeal={setViewingDeal} />}
            {effectiveView === 'newDeal' && (
              <NewDeal role={identity?.role ?? null} onCreated={() => setView('queue')} />
            )}
            {effectiveView === 'incoming' && <IncomingOffers onQueued={() => setView('queue')} />}
            {effectiveView === 'openDeal' && <OpenDeal onOpen={setViewingDeal} />}
          </>
        )}
      </main>
    </div>
  );
};

export default App;
