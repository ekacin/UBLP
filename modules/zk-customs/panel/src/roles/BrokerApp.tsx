import React, { useState } from 'react';
import NewSubmission from '../pages/broker/NewSubmission';
import SubmissionQueue from '../pages/broker/SubmissionQueue';
import SubmissionStatus from '../pages/broker/SubmissionStatus';

type View = 'queue' | 'newSubmission';

const BrokerApp: React.FC = () => {
  const [view, setView] = useState<View>('queue');
  const [viewingId, setViewingId] = useState<number | null>(null);

  if (viewingId !== null) {
    return <SubmissionStatus id={viewingId} onClose={() => setViewingId(null)} />;
  }

  return (
    <>
      <nav className="app-nav">
        <button type="button" className={`btn btn-sm ${view === 'queue' ? 'btn-primary' : ''}`} onClick={() => setView('queue')}>
          Queue
        </button>
        <button
          type="button"
          className={`btn btn-sm ${view === 'newSubmission' ? 'btn-primary' : ''}`}
          onClick={() => setView('newSubmission')}
        >
          New submission
        </button>
      </nav>
      {view === 'queue' && <SubmissionQueue onView={setViewingId} />}
      {view === 'newSubmission' && <NewSubmission onCreated={() => setView('queue')} />}
    </>
  );
};

export default BrokerApp;
