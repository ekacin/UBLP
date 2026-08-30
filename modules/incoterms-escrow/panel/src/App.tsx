import React, { useState } from 'react';
import { useAuth } from './auth/useAuth';
import Login from './pages/Login';
import PendingQueue from './pages/PendingQueue';
import DealStatus from './pages/DealStatus';

const App: React.FC = () => {
  const { status, error, wallets, login, logout } = useAuth();
  const [viewingDeal, setViewingDeal] = useState<string | null>(null);

  if (status === 'checking') return null;

  if (status === 'unauthenticated' || status === 'connecting') {
    return <Login wallets={wallets} connecting={status === 'connecting'} error={error} onConnect={login} />;
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand-block">
          <span className="brand">UBLP</span>
          <h1>Settlement Panel</h1>
        </div>
        <button type="button" className="btn btn-ghost btn-sm" onClick={logout}>
          Sign out
        </button>
      </header>
      <main className="app-main">
        {viewingDeal ? (
          <DealStatus contractAddress={viewingDeal} onClose={() => setViewingDeal(null)} />
        ) : (
          <PendingQueue onViewDeal={setViewingDeal} />
        )}
      </main>
    </div>
  );
};

export default App;
