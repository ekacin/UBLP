import React from 'react';
import PendingReview from '../pages/ministry/PendingReview';

// Ministry's officer has exactly one job here — review the queue — so unlike Broker there's no
// nav bar at all, same reasoning as escrow's own App.tsx hiding its nav entirely for the
// single-purpose port-authority role.
const MinistryApp: React.FC = () => <PendingReview />;

export default MinistryApp;
