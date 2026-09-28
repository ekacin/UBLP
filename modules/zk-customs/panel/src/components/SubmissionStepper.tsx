import React from 'react';
import type { SubmissionStatus } from '../types';

interface SubmissionStepperProps {
  status: SubmissionStatus;
}

const STEPS = ['Submitted', 'At Ministry', 'VC received', 'Proof & L2', 'Settled'];

// Maps Broker's actual 9-value status enum (customs-broker/src/db.ts) onto 5 visual stages —
// same idea as incoterms-escrow/panel's Stepper.tsx (a richer state machine collapsed onto a
// small number of milestones), just a different source enum since this pipeline isn't
// chain-state-driven.
const STAGE: Record<SubmissionStatus, number> = {
  draft: 0,
  awaiting_approval: 0,
  sent_to_ministry: 1,
  awaiting_ministry_approval: 1,
  vc_received: 2,
  proof_requested: 3,
  settled: 4,
  rejected: -1,
  failed: -1,
};

/** Reuses the exact .stepper/.stepper-item/.stepper-dot classes and done/current/stuck
 * modifiers from incoterms-escrow/panel's index.css — same visual language, different driving
 * enum. */
const SubmissionStepper: React.FC<SubmissionStepperProps> = ({ status }) => {
  const stuck = status === 'rejected' || status === 'failed';
  const stage = STAGE[status];
  const done = STEPS.map((_, i) => (stuck ? false : i < 4 ? stage > i : status === 'settled'));
  const current = stuck ? Math.max(STAGE.draft, 0) : done.findIndex((d) => !d);

  return (
    <div className="stepper">
      <ol className="stepper-list">
        {STEPS.map((label, i) => (
          <React.Fragment key={label}>
            {i > 0 && <span className={`stepper-connector${done[i - 1] ? ' filled' : ''}`} />}
            <li
              className={`stepper-item${done[i] ? ' done' : ''}${i === current ? ' current' : ''}${
                stuck && i === current ? ' stuck' : ''
              }`}
            >
              <span className="stepper-dot">{done[i] ? '✓' : i + 1}</span>
              <span className="stepper-label">{label}</span>
            </li>
          </React.Fragment>
        ))}
      </ol>
      {stuck && (
        <p className="stepper-note stepper-note-warn">
          {status === 'rejected' ? 'Rejected by Ministry — this submission will not settle.' : 'Failed while contacting Agent/L2 — check the error below.'}
        </p>
      )}
    </div>
  );
};

export default SubmissionStepper;
