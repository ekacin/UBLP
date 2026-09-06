import { describe, it, expect } from 'vitest';
import { evaluatePolicy } from '@ublp/shared';
import type { Attestation, AttestationPolicy, UBLPDid, ShipmentId } from '@ublp/shared';
import { fasPolicy, ALONGSIDE_SHIP_CONFIRMED_CLAIM } from '../src/policies/fas.js';
import { cfrPolicy } from '../src/policies/cfr.js';
import { cifPolicy } from '../src/policies/cif.js';
import { fcaPolicy, HANDED_TO_CARRIER_CONFIRMED_CLAIM } from '../src/policies/fca.js';
import { cptPolicy } from '../src/policies/cpt.js';
import { cipPolicy } from '../src/policies/cip.js';
import { dapPolicy, ARRIVED_READY_FOR_UNLOADING_CLAIM } from '../src/policies/dap.js';
import { dpuPolicy, UNLOADED_AT_DESTINATION_CLAIM } from '../src/policies/dpu.js';
import { ddpPolicy, DELIVERED_DUTY_PAID_CLAIM } from '../src/policies/ddp.js';
import { exwPolicy, GOODS_MADE_AVAILABLE_CLAIM } from '../src/policies/exw.js';
import { LOADING_CONFIRMED_CLAIM } from '../src/policies/fob.js';

const SHIPMENT_ID: ShipmentId = 'shp:test-incoterms-1';
const ATTESTOR: UBLPDid = 'did:ublp:port-authority:pendik-roro';
const OTHER_ISSUER: UBLPDid = 'did:ublp:port-authority:someone-else';

function attestationFor(claimType: string, issuerSet: UBLPDid[]): Attestation {
  return {
    subjectId: SHIPMENT_ID,
    claimType,
    proofRef: 'mock-proof',
    issuerSet,
    threshold: issuerSet.length,
    timestamp: Date.now(),
  };
}

// Every one of the remaining 10 Incoterms 2020 rules, and the claim its policy requires.
// CFR/CIF share FOB's claim and CPT/CIP share FCA's claim (see each policy file's doc comment
// for why) — that's the point being verified here, not a gap in the table.
const RULES: Array<{ name: string; policy: (did: UBLPDid) => AttestationPolicy; claim: string }> = [
  { name: 'FAS', policy: fasPolicy, claim: ALONGSIDE_SHIP_CONFIRMED_CLAIM },
  { name: 'CFR', policy: cfrPolicy, claim: LOADING_CONFIRMED_CLAIM },
  { name: 'CIF', policy: cifPolicy, claim: LOADING_CONFIRMED_CLAIM },
  { name: 'FCA', policy: fcaPolicy, claim: HANDED_TO_CARRIER_CONFIRMED_CLAIM },
  { name: 'CPT', policy: cptPolicy, claim: HANDED_TO_CARRIER_CONFIRMED_CLAIM },
  { name: 'CIP', policy: cipPolicy, claim: HANDED_TO_CARRIER_CONFIRMED_CLAIM },
  { name: 'DAP', policy: dapPolicy, claim: ARRIVED_READY_FOR_UNLOADING_CLAIM },
  { name: 'DPU', policy: dpuPolicy, claim: UNLOADED_AT_DESTINATION_CLAIM },
  { name: 'DDP', policy: ddpPolicy, claim: DELIVERED_DUTY_PAID_CLAIM },
  { name: 'EXW', policy: exwPolicy, claim: GOODS_MADE_AVAILABLE_CLAIM },
];

describe.each(RULES)('$name AttestationPolicy', ({ policy, claim }) => {
  it('is satisfied when the designated attesting party (C) attests and the attestation verifies', async () => {
    const result = await evaluatePolicy(policy(ATTESTOR), [attestationFor(claim, [ATTESTOR])], async () => true);
    expect(result.satisfied).toBe(true);
  });

  it('is NOT satisfied when a different party (not the escrow-scoped C) attests', async () => {
    const result = await evaluatePolicy(policy(ATTESTOR), [attestationFor(claim, [OTHER_ISSUER])], async () => true);
    expect(result.satisfied).toBe(false);
    expect(result.reasons.length).toBeGreaterThan(0);
  });

  it('is NOT satisfied when the bundle has no matching claim', async () => {
    const result = await evaluatePolicy(policy(ATTESTOR), [], async () => true);
    expect(result.satisfied).toBe(false);
  });

  it('is NOT satisfied when the cryptographic verification fails even for the right issuer', async () => {
    const result = await evaluatePolicy(policy(ATTESTOR), [attestationFor(claim, [ATTESTOR])], async () => false);
    expect(result.satisfied).toBe(false);
  });
});
