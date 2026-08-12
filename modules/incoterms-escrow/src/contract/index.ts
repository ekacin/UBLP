/**
 * Escrow.compact bundled together with its witnesses. See AGENTS.md Section 5.14.1. The
 * deploy/circuit-call side (providers, indexer, real chain transactions) is out of scope
 * here — that's a separate task, set up naturally once Module 4's real deploy flow is written.
 */

import * as CompiledContractModule from '@midnight-ntwrk/compact-js/effect/CompiledContract';
import {
  Contract,
  type ProvableCircuits,
} from '../../contracts/managed/escrow/contract/index.js';
import { escrowWitnesses, emptyEscrowPrivateState, type EscrowPrivateState } from './witnesses.js';

export * from './witnesses.js';

export const compiledEscrowContract = CompiledContractModule.make('incoterms-escrow', Contract).pipe(
  CompiledContractModule.withWitnesses(escrowWitnesses),
  CompiledContractModule.withCompiledFileAssets('/zk/incoterms-escrow')
);

export const EscrowPrivateStateId = 'incotermsEscrowPrivateState' as const;
export type EscrowPrivateStateId = typeof EscrowPrivateStateId;

// Derived from the generated contract rather than hand-typed, so it can't drift out of
// sync — needed for midnight-js-contracts' circuit-id union.
export type EscrowCircuitId = keyof ProvableCircuits<EscrowPrivateState>;
export type EscrowContractType = InstanceType<typeof Contract<EscrowPrivateState>>;

export { emptyEscrowPrivateState };
export type { EscrowPrivateState };
