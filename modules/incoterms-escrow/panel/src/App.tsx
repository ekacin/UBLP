import React, { useState } from 'react';
import { useAuth } from './auth/useAuth';
import Login from './pages/Login';
import PendingQueue from './pages/PendingQueue';
import DealStatus from './pages/DealStatus';

const App: React.FC = () => {
  const { status, error, submitLoginKey, logout } = useAuth();
  const [viewingDeal, setViewingDeal] = useState<string | null>(null);

  if (status === 'checking') return <p>Checking session…</p>;

  if (status === 'unauthenticated') {
    return <Login error={error} onSubmit={submitLoginKey} />;
  }

  return (
    <div>
      <header>
        <h1>UBLP Settlement Panel</h1>
        <button type="button" onClick={() => logout(false)}>
          Sign out
        </button>
      </header>
      <main>
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
