import React from 'react';

interface StepperProps {
  /** ESCROW_STATE_LABELS index: 0 Empty, 1 Proposed, 2 Locked, 3 Released. */
  state: number;
  milestoneConfirmed: boolean;
  expired: boolean;
}

const STEPS = ['Proposed', 'Funds locked', 'Milestone confirmed', 'Released'];

/** Maps the contract's actual state machine (types.ts's ESCROW_STATE_LABELS + the separate
 * milestoneConfirmed flag) onto 4 visual milestones. The label stays generic ("Milestone
 * confirmed") regardless of which Incoterm rule the deal actually uses — Escrow.compact's
 * attest circuit is one generic "C attests, then payout" mechanism with no rule-specific
 * branching (see AGENTS.md 5.2/5.14.1); which real-world event that milestone represents for
 * this deal is shown separately via `terms.incoterm` (see README's "Choosing an Incoterm
 * rule" table). */
const Stepper: React.FC<StepperProps> = ({ state, milestoneConfirmed, expired }) => {
  const done = [state >= 1, state >= 2, state >= 2 && milestoneConfirmed, state === 3];
  const stuck = state === 2 && !milestoneConfirmed && expired;
  const current = state === 3 ? -1 : stuck ? 2 : done.findIndex((d) => !d);

  return (
    <div className="stepper">
      <ol className="stepper-list">
        {STEPS.map((label, i) => (
          <React.Fragment key={label}>
            {i > 0 && <span className={`stepper-connector${done[i - 1] ? ' filled' : ''}`} />}
            <li
              className={`stepper-item${done[i] ? ' done' : ''}${i === current ? ' current' : ''}${
                stuck && i === 2 ? ' stuck' : ''
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
          Deadline passed without confirmation — funds are unlocked for the timeout payout, not this normal path.
        </p>
      )}
    </div>
  );
};

export default Stepper;
