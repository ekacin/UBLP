import React from 'react';
import { useAuth } from './auth/useAuth';
import Login from './pages/Login';
import BrokerApp from './roles/BrokerApp';
import MinistryApp from './roles/MinistryApp';

const ROLE = import.meta.env.VITE_SERVICE_ROLE;

const TITLE: Record<typeof ROLE, string> = {
  ministry: 'Ministry Review',
  broker: 'Customs Broker',
};

const App: React.FC = () => {
  const { status, error, login, logout } = useAuth();

  if (status === 'checking') return null;

  if (status === 'unauthenticated' || status === 'connecting') {
    return <Login role={ROLE} connecting={status === 'connecting'} error={error} onLogin={login} />;
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand-block">
          <span className="brand-mark" />
          <span className="brand">UBLP</span>
          <h1>{TITLE[ROLE]}</h1>
        </div>
        <div className="header-meta">
          <span className="role-badge">{ROLE}</span>
          <button type="button" className="btn btn-ghost btn-sm" onClick={logout}>
            Sign out
          </button>
        </div>
      </header>
      <main className="app-main">{ROLE === 'broker' ? <BrokerApp /> : <MinistryApp />}</main>
    </div>
  );
};

export default App;
